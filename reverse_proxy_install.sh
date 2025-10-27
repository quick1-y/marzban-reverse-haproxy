#!/usr/bin/env bash
set -euo pipefail

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
CYAN="\033[36m"
RESET="\033[0m"

trap 'log ERROR "Скрипт завершился с ошибкой на строке ${LINENO}."; exit 1' ERR

APP_DIR="/opt/marzban-reverse-proxy"
CONFIG_DIR="$APP_DIR/config"
SCRIPTS_DIR="$APP_DIR/scripts"
WWW_DIR="/var/www/marzban"
SYSTEMD_DIR="/etc/systemd/system"
SUBSCRIPTION_SERVICE="marzban-subscription.service"
SUBSCRIPTION_TIMER="marzban-subscription.timer"
NGINX_SITE="/etc/nginx/sites-available/marzban-reverse-proxy.conf"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/marzban-reverse-proxy.conf"
DEFAULT_TEMPLATE_NAMES=("classic" "material" "terminal" "landing")

log() {
  local level="$1"; shift
  local color="$CYAN"

  case "$level" in
    INFO)
      color="$CYAN"
      ;;
    WARN)
      color="$YELLOW"
      ;;
    ERROR)
      color="$RED"
      ;;
    SUCCESS)
      color="$GREEN"
      ;;
  esac

  printf '%b[%(%Y-%m-%d %H:%M:%S)T] [%s] %s%b\n' "$color" -1 "$level" "$*" "$RESET"
}

escape_sed() {
  printf '%s' "$1" | sed -e 's/[\\/&]/\\&/g'
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    log ERROR "Скрипт должен выполняться от имени root."
    exit 1
  fi
}

prompt_with_default() {
  local prompt_text="$1"; shift
  local default_value="$1"; shift || true
  local value
  read -rp "${prompt_text} [${default_value}]: " value
  if [[ -z "$value" ]]; then
    value="$default_value"
  fi
  printf '%s' "$value"
}

install_packages() {
  log INFO "Установка системных зависимостей..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y \
    ca-certificates \
    curl \
    jq \
    git \
    ufw \
    nginx \
    unzip \
    lsb-release \
    software-properties-common \
    unattended-upgrades \
    systemd-timesyncd \
    resolvconf \
    gnupg \
    socat \
    cron \
    net-tools \
    python3 \
    uuid-runtime \
    openssl \
    iptables
}

configure_unattended_upgrades() {
  log INFO "Настройка автоматических обновлений (unattended-upgrades)..."
  dpkg-reconfigure -f noninteractive unattended-upgrades
}

ensure_directories() {
  log INFO "Создание служебных каталогов..."
  mkdir -p "$CONFIG_DIR" "$SCRIPTS_DIR" "$WWW_DIR"
}

configure_bbr() {
  log INFO "Включение TCP BBR..."
  cat > /etc/sysctl.d/99-bbr.conf <<'CONF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
CONF
  sysctl --system >/dev/null
}

disable_ipv6() {
  log INFO "Отключение IPv6..."
  cat > /etc/sysctl.d/99-disable-ipv6.conf <<'CONF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
CONF
  sysctl --system >/dev/null
}

configure_firewall() {
  local ssh_port="$1"
  log INFO "Настройка UFW..."
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${ssh_port}/tcp"
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw --force enable
}

install_warp() {
  log INFO "Установка Cloudflare WARP..."
  if ! command -v warp-cli >/dev/null 2>&1; then
    curl https://pkg.cloudflareclient.com/pubkey.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -sc) main" \
      > /etc/apt/sources.list.d/cloudflare-client.list
    apt-get update -y
    apt-get install -y cloudflare-warp
  else
    log INFO "WARP уже установлен."
  fi
  systemctl enable --now warp-svc
  warp-cli --accept-tos registration new >/dev/null || true
  warp-cli --accept-tos set-mode warp >/dev/null || true
  warp-cli --accept-tos connect >/dev/null || true
}

configure_dns_over_tls() {
  log INFO "Настройка шифрования DNS (systemd-resolved DoT)..."
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/dns-over-tls.conf <<'CONF'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
FallbackDNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
CONF
  systemctl restart systemd-resolved
}

configure_nginx() {
  local domain="$1"
  local marzban_host="$2"
  local marzban_port="$3"
  local ssl_certificate="$4"
  local ssl_key="$5"

  log INFO "Настройка обратного прокси NGINX..."
  cat > "$NGINX_SITE" <<'NGINX'
server {
    listen 443 ssl http2;
    server_name __DOMAIN__;

    ssl_certificate __SSL_CERT__;
    ssl_certificate_key __SSL_KEY__;
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass https://__MARZBAN_HOST__:__MARZBAN_PORT__;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90;
        proxy_set_header Connection "";
    }
}

server {
    listen 80;
    server_name __DOMAIN__;
    return 301 https://$host$request_uri;
}
NGINX
  local escaped_domain escaped_cert escaped_key escaped_host escaped_port
  escaped_domain=$(escape_sed "$domain")
  escaped_cert=$(escape_sed "$ssl_certificate")
  escaped_key=$(escape_sed "$ssl_key")
  escaped_host=$(escape_sed "$marzban_host")
  escaped_port=$(escape_sed "$marzban_port")

  sed -i "s/__DOMAIN__/${escaped_domain}/g" "$NGINX_SITE"
  sed -i "s/__SSL_CERT__/${escaped_cert}/g" "$NGINX_SITE"
  sed -i "s/__SSL_KEY__/${escaped_key}/g" "$NGINX_SITE"
  sed -i "s/__MARZBAN_HOST__/${escaped_host}/g" "$NGINX_SITE"
  sed -i "s/__MARZBAN_PORT__/${escaped_port}/g" "$NGINX_SITE"
  ln -sf "$NGINX_SITE" "$NGINX_SITE_LINK"
  nginx -t
  systemctl reload nginx
}

create_subscription_scripts() {
  local subscription_url="$1"
  local json_url="$2"
  local convert_format="$3"

  log INFO "Создание скриптов для обновления подписки..."
  cat > "$APP_DIR/.env" <<ENV
SUBSCRIPTION_URL="${subscription_url}"
JSON_SUBSCRIPTION_URL="${json_url}"
CONVERT_TARGET="${convert_format}"
CONFIG_DIR="${CONFIG_DIR}"
ENV

  cat > "$SCRIPTS_DIR/update-subscription.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/marzban-reverse-proxy"
source "$APP_DIR/.env"
mkdir -p "$CONFIG_DIR"

fetch_and_write() {
  local url="$1"
  local destination="$2"
  local description="$3"

  if [[ -z "$url" ]]; then
    echo "Пропускаем ${description}: URL не указан"
    return
  fi

  tmp_file="$(mktemp)"
  if curl -fsSL "$url" -o "$tmp_file"; then
    mv "$tmp_file" "$destination"
    echo "Обновлено ${description}"
  else
    echo "Не удалось скачать ${description}"
    rm -f "$tmp_file"
  fi
}

fetch_and_write "$SUBSCRIPTION_URL" "$CONFIG_DIR/subscription.txt" "base64 подписку"
fetch_and_write "$JSON_SUBSCRIPTION_URL" "$CONFIG_DIR/subscription.json" "JSON подписку"

if [[ -f "$CONFIG_DIR/subscription.json" && -n "${CONVERT_TARGET:-}" ]]; then
  case "$CONVERT_TARGET" in
    clash)
      jq -r '.profiles[]? | select(.type=="vless" or .type=="vmess") | .uri' "$CONFIG_DIR/subscription.json" \
        > "$CONFIG_DIR/subscription_clash.txt" || true
      ;;
    sing-box)
      jq '{inbounds: [.inbounds[]?], outbounds: [.outbounds[]?]}' "$CONFIG_DIR/subscription.json" \
        > "$CONFIG_DIR/subscription_sing-box.json" || true
      ;;
    v2ray)
      jq '{log: {loglevel: "warning"}, inbounds: [.inbounds[]?], outbounds: [.outbounds[]?]}' "$CONFIG_DIR/subscription.json" \
        > "$CONFIG_DIR/subscription_v2ray.json" || true
      ;;
    *)
      echo "Неизвестный формат конвертации: $CONVERT_TARGET"
      ;;
  esac
fi
SCRIPT
  chmod +x "$SCRIPTS_DIR/update-subscription.sh"

  cat > "$SYSTEMD_DIR/$SUBSCRIPTION_SERVICE" <<SERVICE
[Unit]
Description=Обновление подписки Marzban
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPTS_DIR/update-subscription.sh
User=root
Group=root

[Install]
WantedBy=multi-user.target
SERVICE

  cat > "$SYSTEMD_DIR/$SUBSCRIPTION_TIMER" <<TIMER
[Unit]
Description=Периодическое обновление подписки Marzban

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
TIMER

  systemctl daemon-reload
  systemctl enable --now "$SUBSCRIPTION_TIMER"
}

generate_user_config() {
  local user_email="$1"
  local user_uuid="$2"
  local flow="$3"
  local reality_port="$4"
  local tls_port="$5"
  cat > "$CONFIG_DIR/users.json" <<JSON
{
  "users": [
    {
      "email": "${user_email}",
      "uuid": "${user_uuid}",
      "flow": "${flow}",
      "inbounds": {
        "reality": ${reality_port},
        "tls": ${tls_port}
      }
    }
  ]
}
JSON
}

create_random_template() {
  log INFO "Развёртывание маскировочного сайта..."
  local index="${DEFAULT_TEMPLATE_NAMES[RANDOM % ${#DEFAULT_TEMPLATE_NAMES[@]}]}"
  case "$index" in
    classic)
      cat > "$WWW_DIR/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Marzban Proxy</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
</head>
<body class="bg-light">
  <main class="container py-5">
    <h1 class="display-5 fw-bold">Добро пожаловать!</h1>
    <p class="lead">Сервер успешно настроен и готов к работе.</p>
    <p>Используйте безопасное подключение и следите за обновлениями.</p>
  </main>
</body>
</html>
HTML
      ;;
    material)
      cat > "$WWW_DIR/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Proxy Gateway</title>
  <style>
    body { margin: 0; font-family: 'Roboto', sans-serif; background: linear-gradient(135deg, #141e30, #243b55); color: #fff; }
    .wrapper { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; text-align: center; }
    h1 { font-size: 3rem; margin-bottom: 1rem; }
    p { max-width: 480px; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="wrapper">
    <h1>Secure Gateway</h1>
    <p>Инфраструктура защищена Cloudflare и использует шифрование DNS. Доступ для неавторизованных пользователей ограничен.</p>
  </div>
</body>
</html>
HTML
      ;;
    terminal)
      cat > "$WWW_DIR/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Status Console</title>
  <style>
    body { background: #000; color: #0f0; font-family: 'Courier New', monospace; padding: 2rem; }
    .cursor { animation: blink 1s step-end infinite; }
    @keyframes blink { 50% { opacity: 0; } }
  </style>
</head>
<body>
  <h1>> Proxy status: <span class="cursor">_</span></h1>
  <p>nginx reverse proxy: ok</p>
  <p>warp secure tunnel: ok</p>
  <p>dns over tls: ok</p>
  <p>system updates: automated</p>
</body>
</html>
HTML
      ;;
    landing|*)
      cat > "$WWW_DIR/index.html" <<HTML
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Digital Services</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; font-family: 'Open Sans', sans-serif; background: #f2f4f8; color: #2c3e50; }
    header { padding: 60px 30px; text-align: center; background: #1e90ff; color: #fff; }
    section { padding: 40px 20px; max-width: 900px; margin: auto; }
    footer { padding: 20px; text-align: center; font-size: 0.85rem; color: #95a5a6; }
  </style>
</head>
<body>
  <header>
    <h1>Digital Services</h1>
    <p>Скорость. Надёжность. Безопасность.</p>
  </header>
  <section>
    <h2>Инфраструктура нового поколения</h2>
    <p>Высоконадежный кластер для обработки зашифрованного трафика и защиты данных пользователей.</p>
  </section>
  <footer>
    © $(date +%Y) Digital Services. Все права защищены.
  </footer>
</body>
</html>
HTML
      ;;
  esac
}

configure_nginx_static_site() {
  log INFO "Настройка NGINX для статического сайта..."
  cat > /etc/nginx/sites-available/marzban-static.conf <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/marzban;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
NGINX
  ln -sf /etc/nginx/sites-available/marzban-static.conf /etc/nginx/sites-enabled/marzban-static.conf
  nginx -t
  systemctl reload nginx
}

setup_subscription_limits() {
  local allowed_ips=("127.0.0.1" "::1")
  log INFO "Настройка ограничения доступа по IP..."
  cat > "$CONFIG_DIR/allowed_ips.txt" <<EOF
${allowed_ips[*]}
EOF
}

deploy_additional_modules() {
  log INFO "Добавление дополнительных модулей (torrent block, node, подписка)..."

  cat > "$SCRIPTS_DIR/torrent-block.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

iptables -N TORRENT_BLOCK 2>/dev/null || true
iptables -F TORRENT_BLOCK

BLOCK_KEYWORDS=("BitTorrent" "BitComet" "utorrent" "peer_id" "announce.php?passkey" "tracker")

for keyword in "${BLOCK_KEYWORDS[@]}"; do
  iptables -A TORRENT_BLOCK -m string --algo bm --string "$keyword" -j DROP 2>/dev/null || true
done

iptables -D FORWARD -j TORRENT_BLOCK 2>/dev/null || true
iptables -I FORWARD -j TORRENT_BLOCK 2>/dev/null || true
SCRIPT
  chmod +x "$SCRIPTS_DIR/torrent-block.sh"

  cat > "$CONFIG_DIR/node-blagodaren.json" <<'JSON'
{
  "name": "reverse-proxy-node",
  "provider": "blagodaren",
  "description": "Пример ноды для подключения реверс-прокси.",
  "entrypoint": "https://127.0.0.1:8443",
  "healthcheck": {
    "interval": "60s",
    "timeout": "5s"
  }
}
JSON

  cat > "$CONFIG_DIR/subscription-legiz.md" <<'MARKDOWN'
# Пользовательская подписка (legiz)

- Отредактируйте файл `/opt/marzban-reverse-proxy/.env`, установите `SUBSCRIPTION_URL` и `JSON_SUBSCRIPTION_URL`.
- Сервис `marzban-subscription.timer` будет обновлять подписи каждый час.
- Для ручного обновления выполните `sudo systemctl start marzban-subscription.service`.
MARKDOWN
}

setup_systemd_services() {
  log INFO "Создание основной службы systemd для вспомогательных задач..."
  cat > "$SYSTEMD_DIR/marzban-maintenance.service" <<SERVICE
[Unit]
Description=Обслуживание Marzban Reverse Proxy
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/true

[Install]
WantedBy=multi-user.target
SERVICE
  systemctl enable marzban-maintenance.service >/dev/null 2>&1 || true
}

configure_reality_stub() {
  local hostname="$1"
  local reality_port="$2"
  local destination="$CONFIG_DIR/reality.json"
  cat > "$destination" <<JSON
{
  "inbound": {
    "type": "tcp",
    "port": ${reality_port},
    "protocol": "vless",
    "tag": "reality-steal",
    "settings": {
      "clients": [
        {
          "id": "$(uuidgen)",
          "flow": "xtls-rprx-vision",
          "email": "admin@${hostname}"
        }
      ],
      "decryption": "none",
      "fallbacks": []
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "${hostname}:443",
        "serverNames": ["${hostname}"],
        "shortIds": ["0123456789abcdef"],
        "privateKey": "$(openssl rand -hex 32)",
        "publicKey": ""
      }
    }
  }
}
JSON
}

print_summary() {
  local domain="$1"
  cat <<SUMMARY

============================================================
Установка завершена
============================================================
• Домен обратного прокси: ${domain}
• Конфигурация: ${CONFIG_DIR}
• Подписка: systemctl status ${SUBSCRIPTION_TIMER}
• Реверс-прокси: ${NGINX_SITE}
• Статический сайт: ${WWW_DIR}/index.html
============================================================
SUMMARY
}

main() {
  require_root

  local domain
  local marzban_host
  local marzban_port
  local ssh_port
  local subscription_url
  local json_subscription_url
  local convert_format
  local ssl_certificate
  local ssl_key
  local user_email
  local user_uuid
  local flow="xtls-rprx-vision"
  local reality_port
  local tls_port

  domain=$(prompt_with_default "Введите домен для обратного прокси" "example.com")
  marzban_host=$(prompt_with_default "Введите адрес панели Marzban" "127.0.0.1")
  marzban_port=$(prompt_with_default "Введите порт панели Marzban" "8443")
  ssh_port=$(prompt_with_default "Введите порт SSH" "22")
  subscription_url=$(prompt_with_default "URL подписки (base64)" "")
  json_subscription_url=$(prompt_with_default "URL JSON подписки" "")
  convert_format=$(prompt_with_default "Формат конвертации (clash/sing-box/v2ray/пусто)" "clash")
  ssl_certificate=$(prompt_with_default "Путь к SSL сертификату Cloudflare" "/etc/ssl/certs/marzban.crt")
  ssl_key=$(prompt_with_default "Путь к приватному ключу" "/etc/ssl/private/marzban.key")
  user_email=$(prompt_with_default "Email пользователя" "user@${domain}")
  read -rp "UUID пользователя (пусто для автоматического) []: " user_uuid
  reality_port=$(prompt_with_default "Порт TCP-REALITY" "2053")
  tls_port=$(prompt_with_default "Порт TCP-TLS" "443")

  if [[ -z "$user_uuid" ]]; then
    user_uuid=$(uuidgen)
  fi

  install_packages
  configure_unattended_upgrades
  ensure_directories
  configure_bbr
  disable_ipv6
  configure_firewall "$ssh_port"
  install_warp
  configure_dns_over_tls
  create_random_template
  configure_nginx_static_site
  configure_nginx "$domain" "$marzban_host" "$marzban_port" "$ssl_certificate" "$ssl_key"
  create_subscription_scripts "$subscription_url" "$json_subscription_url" "$convert_format"
  generate_user_config "$user_email" "$user_uuid" "$flow" "$reality_port" "$tls_port"
  setup_subscription_limits
  deploy_additional_modules
  setup_systemd_services
  configure_reality_stub "$domain" "$reality_port"

  print_summary "$domain"
}

main "$@"
