# Marzban Reverse Proxy Installer

Скрипт `reverse_proxy_install.sh` предназначен для автоматической подготовки сервера с обратным прокси по аналогии с проектом [marz-reverse-proxy](https://github.com/Adam-Sizzler/marz-reverse-proxy). Все инструкции и выводы локализованы на русском языке.

## Возможности

- Развёртывание инфраструктуры реверс-прокси для панели Marzban.
- Настройка подписок (base64 и JSON) с автоматическим обновлением и конвертацией в популярные форматы (Clash, Sing-box, V2Ray).
- Генерация пользовательских конфигураций с включённым `"flow": "xtls-rprx-vision"` и профилем TCP-REALITY (Steal oneself) + TCP-TLS.
- Настройка NGINX с обратным прокси на порт 443 и статического маскировочного сайта со случайным шаблоном.
- Интеграция дополнительных функций: нода обратного прокси, блокировщик торрентов, ограничение по IP (файлы-заготовки).
- Меры безопасности: unattended-upgrades, Cloudflare WARP, DoT через systemd-resolved, настройка UFW, отключение IPv6, включение TCP BBR.
- Подготовка служб systemd для автоматического обновления подписок и дальнейших задач обслуживания.

## Требования

- Чистая установка Ubuntu 20.04/22.04 от имени пользователя `root` (или использование `sudo`).
- Настроенные DNS-записи на ваш домен и наличие Cloudflare Origin/Universal сертификатов (файлы должны быть скопированы на сервер заранее).
- Доступ в интернет для загрузки зависимостей (apt, Cloudflare репозиторий).

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/<ваш_профиль>/<репозиторий>/main/reverse_proxy_install.sh | sudo bash
```

Либо скачайте репозиторий и выполните скрипт:

```bash
git clone https://github.com/<ваш_профиль>/marzban-reverse-haproxy.git
cd marzban-reverse-haproxy
sudo bash reverse_proxy_install.sh
```

## Ход установки

Скрипт задаст вопросы и предложит значения по умолчанию:

- **Домен** — доменное имя, закреплённое за панелью Marzban.
- **Адрес и порт панели** — параметры upstream, которые будут защищены обратным прокси.
- **Пути до SSL сертификата и ключа Cloudflare** — сертификаты копируются в `/etc/ssl/...` заранее.
- **URL подписок** — можно оставить пустыми и настроить позже в `/opt/marzban-reverse-proxy/.env`.
- **Email и UUID пользователя** — при пустом значении UUID генерируется автоматически, flow фиксирован как `xtls-rprx-vision`.
- **Порты TCP-REALITY и TCP-TLS** — рекомендуется оставить значения по умолчанию, отключение REALITY приведёт к потере доступа.

После завершения установки появится сводка с ключевыми путями и командами проверки сервисов.

## Что создаётся

- `/opt/marzban-reverse-proxy` — конфигурации, подписки, вспомогательные скрипты.
- Systemd таймер `marzban-subscription.timer` — ежечасное обновление подписок.
- Конфигурация NGINX `marzban-reverse-proxy.conf` + статический сайт в `/var/www/marzban`.
- Конфигурация безопасности: UFW, отключение IPv6, TCP BBR, Cloudflare WARP, DoT.
- `/opt/marzban-reverse-proxy/scripts/torrent-block.sh` — базовый скрипт iptables для блокировки BitTorrent-трафика.
- `/opt/marzban-reverse-proxy/config/node-blagodaren.json` — пример ноды реверс-прокси.
- `/opt/marzban-reverse-proxy/config/subscription-legiz.md` — памятка по пользовательской подписке.

## Настройка после установки

- Отредактируйте `/opt/marzban-reverse-proxy/.env`, чтобы изменить URL подписок или формат конвертации, затем выполните `sudo systemctl start marzban-subscription.service` для немедленного обновления.
- При необходимости добавьте IP-адреса в `/opt/marzban-reverse-proxy/config/allowed_ips.txt` и реализуйте проверку в своих сервисах.
- Активируйте блокировщик торрентов командой `sudo bash /opt/marzban-reverse-proxy/scripts/torrent-block.sh` после проверки правил.
- Для обновления SSL сертификата подмените файлы и перезагрузите NGINX: `sudo systemctl reload nginx`.

## Удаление

```bash
sudo systemctl disable --now marzban-subscription.timer warp-svc
sudo rm -f /etc/nginx/sites-enabled/marzban-reverse-proxy.conf /etc/nginx/sites-available/marzban-reverse-proxy.conf
sudo rm -f /etc/nginx/sites-enabled/marzban-static.conf /etc/nginx/sites-available/marzban-static.conf
sudo rm -rf /opt/marzban-reverse-proxy /var/www/marzban
sudo systemctl reload nginx
```

При необходимости удалите пакеты (`cloudflare-warp`, `unattended-upgrades` и т.д.) вручную.
