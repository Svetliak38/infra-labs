# Runbook: развёртывание VPS с нуля (Debian)

Черновик для портфолио. Основан на реальном процессе: март — ноябрь 2026, от ручной настройки по чужой инструкции до повторяемого документированного развёртывания.

**Что это даёт на собеседовании:** на вопрос «покажи, как ты поднимаешь сервер» не рассказываешь по памяти, а открываешь документ и говоришь: «вот порядок, вот проверки, вот что делаю при сбое». Это уровень выше джуна.

---

## 1. Предположения

- Провайдер даёт чистый образ **Debian 13 (trixie)**, root-доступ по паролю при первом входе.
- Сервер нужен под сетевой сервис (прокси/туннель), один процесс — один публичный IP.
- RAM 512 МБ – 1 ГБ, трафик лимитирован. Отсюда выбор дистрибутива: **Debian, а не Ubuntu** — меньше потребление памяти в простое и меньше фоновых сервисов.

## 2. Первый вход и инвентаризация

```bash
ssh root@SERVER_IP
uname -a
cat /etc/os-release        # убедиться, что это именно Debian 13, а не старый образ
free -m                    # сколько памяти реально доступно
df -h /
ip -a
```

**Если образ старый — не подменяй `sources.list` на чужой релиз.** Подмена репозиториев Ubuntu focal на Debian-подобной системе даёт «франкенштейна»: зависимости не сходятся, `apt upgrade` ломает пакеты. Правильно — переустановить ОС из актуального образа у провайдера. Это 10 минут против вечера отладки.

## 3. Обновление системы

```bash
apt update && apt upgrade -y
apt install -y curl ca-certificates nano less htop
# если обновилось ядро:
reboot
```

## 4. Пользователь и SSH (не работать под root)

```bash
adduser deploy
usermod -aG sudo deploy
mkdir -p /home/deploy/.ssh && chmod 700 /home/deploy/.ssh
# на локальной машине:
ssh-copy-id deploy@SERVER_IP
```

Затем `nano /etc/ssh/sshd_config`:

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Port 22
```

```bash
systemctl restart ssh
# ПРОВЕРИТЬ во втором терминале, что вход по ключу работает, И ТОЛЬКО ПОТОМ выходить из первого
```

**Правило:** не закрывай текущую сессию, пока не убедился, что новая работает. Иначе останется только консоль провайдера.

## 5. Firewall

```bash
apt install -y nftables
```

`/etc/nftables.conf` — минимальный набор:

```
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport 22 accept
    tcp dport 8080 accept      # порт сервиса
    ip protocol icmp accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
```

```bash
systemctl enable --now nftables
```

## 6. Установка сервиса — без `curl | bash`

Чужая инструкция вида `curl https://... | sudo bash` — это запуск незнакомого кода от root. В учебном процессе сойдёт, в продакшене — нет. Правильно:

```bash
apt install -y 3proxy          # или dante-server
```

Конфиг `/etc/3proxy/3proxy.cfg`:

```
daemon
maxconn 100
nserver 1.1.1.1
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
users deploy:CL:СТОЙКИЙ_ПАРОЛЬ
auth strong
allow deploy
socks -p8080
```

Проверить конфиг до запуска: `3proxy /etc/3proxy/3proxy.cfg` в переднем плане и глазами посмотреть на ошибки.

## 7. systemd: автозапуск и логи

`/etc/systemd/system/proxy.service`:

```ini
[Unit]
Description=SOCKS5 proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now proxy
systemctl status proxy
journalctl -u proxy -n 50 --no-pager
```

## 8. Проверка работоспособности

```bash
ss -tlnp | grep 8080                        # слушает ли порт
curl -x socks5h://deploy:ПАРОЛЬ@127.0.0.1:8080 https://ifconfig.me   # виден ли внешний IP сервера
curl -s -m 5 https://ifconfig.me            # сравнить с прямым IP
```

Четыре проверки, которые надо делать после каждого развёртывания: **порт слушает, сервис жив, выход в интернет есть, IP тот, который ожидался.**

## 9. Эксплуатация

- **Память:** `free -m`, при 512 МБ следить за swap и OOM в `journalctl -k | grep -i oom`.
- **Соединения:** `ss -s`, `conntrack -C` — сколько одновременных сессий держит.
- **Трафик:** `vnstat` или счётчики провайдера; при лимите — ставить `tc` или ограничивать `maxconn`.
- **Логи:** `journalctl -u proxy --since "1 hour ago"`, ротация через `journald.conf` (`SystemMaxUse=100M`).
- **Обновления:** раз в месяц `apt update && apt upgrade`, перезагрузка по необходимости.

## 10. Если сервер перестал отвечать

1. Пинг и порт 22 снаружи: `nc -vz SERVER_IP 22`.
2. Консоль провайдера — жив ли вообще, не ушёл ли в OOM.
3. Если SSH недоступен, а сервер пингуется — смотреть, не заблокировал ли файрвол: правка через консоль провайдера.
4. Если конфиг сломан — `systemctl status`, `journalctl`; откат последнего изменения (перед правкой всегда `cp file file.bak`).
5. Пересоздание сервера — последний шаг, а не первый.

## 11. Чек-лист «новый сервер»

- [ ] Образ актуальный, не старый
- [ ] `apt update && apt upgrade` выполнены
- [ ] Создан пользователь, root по SSH запрещён, пароль отключён
- [ ] Ключ проверен во второй сессии
- [ ] Файрвол: только нужные порты
- [ ] Сервис поставлен из пакета, не `curl | bash`
- [ ] systemd-юнит, автозапуск, `Restart=always`
- [ ] Четыре проверки пройдены (порт, сервис, интернет, IP)
- [ ] Конфиги сохранены копией вне сервера
- [ ] Пароль сгенерирован, не в истории bash

---

## Что я вынес за 8 месяцев (для раздела «опыт»)

- **Debian вместо Ubuntu** для бюджетных VPS: меньше памяти в простое, меньше фоновых сервисов, стабильнее на 512 МБ.
- **Один процесс — один IP**: при трафиковом лимите проще считать и ограничивать, чем дебажить общий пул.
- **Ручная настройка по чужой инструкции масштабируется до первого десятка серверов.** Дальше нужен документ и скрипт, иначе время уходит на повторение одних и тех же шагов.
- **`curl | bash` от root — техдолг с процентами.** Один раз сэкономил 10 минут, потом ищешь, что именно скрипт поменял в системе.
- **Пароль в `export` оседает в истории bash** (`~/.bash_history`, `ps aux`). Хранить в файле с `chmod 600` или использовать ключи.
