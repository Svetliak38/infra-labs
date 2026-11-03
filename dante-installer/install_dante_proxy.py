#!/usr/bin/env python3
"""
FINAL DANTE INSTALLER v1.0 — Единое решение для Debian 12/13.
1. Определяет ОС.
2. Если пакет dante-server есть (Debian 12) — ставит его.
3. Если пакета нет (Debian 13) — компилирует из исходников.
4. Настраивает жесткую безопасность (блокировка внутренних сетей).
5. Сохраняет или генерирует пароль.

v3.0 — к v1.1 добавлено:
  * защита от ложного rc=97: тест блокировки только после положительного контроля (выход наружу);
  * пароль пишется на диск сразу после chpasswd (страховочный файл, чистится по итогам прогона);
  * один apt-get update на сервер (с повтором при блокировке apt);
  * фолбэк apt -> сборка ровно один раз; путь к бинарнику известен из установки.
v3.1:
  * recovery-файл с ФИКСИРОВАННЫМ именем (proxies_recovery.txt), метка прогона в каждой строке;
    записи прежних/прерванных прогонов никогда не удаляются автоматически, при старте — предупреждение;
  * положительный контроль по трём целям (proxy -> ipify -> http://1.1.1.1 без DNS);
  * repair_dpkg: мягкий (dpkg --configure -a; apt -f только если dpkg сломан, с --no-remove);
  * drop-in для sshd: при ошибке sshd -t файл удаляется, причина пишется в лог.
"""
from __future__ import annotations
import os, re, sys, time, socket, logging, secrets, string, threading
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko

# ============================================================
# КОНФИГ
# ============================================================
SSH_USER           = "root"
SSH_PORT           = 22
SSH_TIMEOUT        = 60
SSH_RETRIES        = 3
SSH_RETRY_DELAY    = 5
PROXY_PORT         = 1080
PROXY_USER         = "proxyuser"
PASS_LEN           = 24
SAFE_ALPHABET      = string.ascii_letters + string.digits
PASS_RE            = re.compile(r"[A-Za-z0-9]{8,64}")
REUSE_EXISTING_PASSWORD = True   # Пытаться сохранить старый пароль
MAX_WORKERS        = 2            # Серверы обрабатываются параллельно (на каждый — своя SSH-сессия)
SERVERS_FILE       = "servers.txt"
OUTPUT_FILE        = "proxies_final_dante.txt"
DANTE_VERSION      = "1.4.3"
DANTE_SHA256       = ""           # опционально: sha256 архива для проверки целостности
PID_FILE           = "/run/danted.pid"
# Цели положительного контроля: важно, что трафик идёт, а не что конкретный сайт ответил 200.
# Последняя — по IP: не зависит от DNS на сервере.
TEST_URLS          = ("https://ya.ru", "https://api.ipify.org", "http://1.1.1.1/")
RECOVERY_FILE      = "proxies_recovery.txt"   # пароли, изменённые на серверах (страховка), имя фиксированное
RUN_ID             = f"{datetime.now():%Y%m%d_%H%M%S}"
PATH_PREFIX        = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)

# ============================================================
# ШАБЛОНЫ
# ============================================================
# Конфиг Dante с ЖЕСТКОЙ блокировкой внутренних сетей
DANTED_CONF_TEMPLATE = """\
logoutput: syslog
internal: 0.0.0.0 port = @@PORT@@
external: @@IFACE@@
clientmethod: none
socksmethod: username
user.privileged: root
user.unprivileged: nobody
timeout.negotiate: 30
timeout.connect: 30
timeout.io: 86400
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error
}
# Block internal / special-use networks
socks block {
    from: 0.0.0.0/0 to: 0.0.0.0/8
    log: error
}
socks block {
    from: 0.0.0.0/0 to: 127.0.0.0/8
    log: error
}
socks block {
    from: 0.0.0.0/0 to: 169.254.0.0/16
    log: error
}
socks block {
    from: 0.0.0.0/0 to: 10.0.0.0/8
    log: error
}
socks block {
    from: 0.0.0.0/0 to: 172.16.0.0/12
    log: error
}
socks block {
    from: 0.0.0.0/0 to: 192.168.0.0/16
    log: error
}
socks block {
    from: 0.0.0.0/0 to: 100.64.0.0/10
    log: error
}
socks block {
    from: 0.0.0.0/0 to: 198.18.0.0/15
    log: error
}
@@SELF_BLOCKS@@# Allow only TCP CONNECT to the outside
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: connect
    protocol: tcp
    socksmethod: username
    log: error
}
"""

DANTED_DROPIN = """\
[Unit]
StartLimitIntervalSec=0
[Service]
Restart=always
RestartSec=3
LimitNOFILE=8192
MemoryMax=200M
TasksMax=512
"""

HEALTHCHECK_SCRIPT = r"""#!/bin/bash
SVC=danted
PORT=@@PORT@@
if ! systemctl is-active --quiet "$SVC"; then
    systemctl restart "$SVC" 2>/dev/null
    sleep 3
    systemctl is-active --quiet "$SVC" || exit 1
fi
resp=$(timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/'"$PORT"'; printf "\x05\x01\x02" >&3; head -c2 <&3 | od -An -tx1' 2>/dev/null | tr -d ' \n')
if [ "$resp" != "0502" ]; then
    logger -t proxy-hc "socks handshake failed (resp='$resp'), restarting $SVC"
    systemctl restart "$SVC" 2>/dev/null
fi
exit 0
"""

HC_SERVICE = """\
[Unit]
Description=proxy proxy healthcheck
[Service]
Type=oneshot
ExecStart=/opt/proxy-hc.sh
"""

HC_TIMER = """\
[Unit]
Description=proxy proxy healthcheck timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
[Install]
WantedBy=timers.target
"""

# ============================================================
# УТИЛИТЫ
# ============================================================
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def gen_password(length: int = PASS_LEN) -> str:
    while True:
        p = "".join(secrets.choice(SAFE_ALPHABET) for _ in range(length))
        if any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p):
            return p

def is_safe_password(p: str) -> bool:
    return bool(PASS_RE.fullmatch(p or ""))

@dataclass
class CommandResult:
    command: str; exit_code: int; stdout: str; stderr: str

class RemoteHost:
    def __init__(self, ip, password):
        self.ip, self.password, self.client = ip, password, None

    def connect(self):
        last = None
        for a in range(1, SSH_RETRIES + 1):
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(self.ip, port=SSH_PORT, username=SSH_USER, password=self.password,
                          timeout=SSH_TIMEOUT, banner_timeout=45, auth_timeout=30,
                          allow_agent=False, look_for_keys=False)
                c.get_transport().set_keepalive(15)
                self.client = c; return
            except Exception as e:
                last = e
                logger.warning("[%s] SSH попытка %s/%s: %s", self.ip, a, SSH_RETRIES, str(e)[:80])
                if a < SSH_RETRIES: time.sleep(SSH_RETRY_DELAY)
        raise RuntimeError(f"SSH connect failed: {last}")

    def close(self):
        if self.client:
            try: self.client.close()
            finally: self.client = None

    def __enter__(self): self.connect(); return self
    def __exit__(self, *_): self.close()

    def run(self, cmd, check=True, timeout=120, stdin_data: Optional[str] = None) -> CommandResult:
        """FIX: stdout и stderr читаются одновременно (раньше o.read() потом e.read() мог
        зависнуть при большом stderr, например при make), таймаут теперь общий на команду."""
        if not self.client: raise RuntimeError("Not connected")
        sin, o, _e = self.client.exec_command(PATH_PREFIX + cmd)
        chan = o.channel
        if stdin_data is not None:
            sin.write(stdin_data); sin.flush(); chan.shutdown_write()
        out_b, err_b = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        while True:
            got = False
            while chan.recv_ready():
                out_b += chan.recv(65536); got = True
            while chan.recv_stderr_ready():
                err_b += chan.recv_stderr(65536); got = True
            if (chan.exit_status_ready() or chan.closed) and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            if time.monotonic() > deadline:
                chan.close()
                raise RuntimeError(f"[{self.ip}] timeout ({timeout}s): {cmd.strip()[:80]}")
            if not got:
                time.sleep(0.1)
        ec = chan.recv_exit_status()
        out = out_b.decode(errors="replace").strip()
        err = err_b.decode(errors="replace").strip()
        r = CommandResult(cmd, ec, out, err)
        if check and ec != 0:
            raise RuntimeError(f"[{self.ip}] failed ({ec}): {(err or out)[:200]}")
        return r

    def run_silent(self, cmd, check=True, timeout=120):
        # FIX: группировка { ...; }, иначе редирект относился только к последней команде после ||
        return self.run(f"{{ {cmd}\n}} >/dev/null 2>&1", check=check, timeout=timeout)

    def write_file(self, path, content, mode=0o644):
        s = self.client.open_sftp()
        try:
            with s.open(path, "w") as f:
                f.chmod(mode)
                f.write(content)
        finally: s.close()

    def is_active(self, unit) -> bool:
        r = self.run(f"systemctl is-active {unit}", check=False)
        return r.exit_code == 0 and r.stdout.strip() == "active"

# ============================================================
# УЧЁТ ПАРОЛЕЙ (recovery-файл: страховка от потери)
# ============================================================
# Формат строки: ip:port:user:password:RUN_ID  (первые 4 поля совместимы с OUTPUT_FILE).
# Файл ничего не "забывает": записи прежних (прерванных/упавших) прогонов остаются, пока их не
# заменит новый пароль того же сервера или пока вы не удалите файл вручную.
_creds_lock = threading.Lock()
_pending_ips: set = set()

def _parse_recovery_line(ln: str):
    p = ln.rstrip("\n").split(":")
    if ln.lstrip().startswith("#") or len(p) < 4:
        return None
    return p[0], (p[4] if len(p) > 4 else "")

def _read_recovery_lines() -> List[str]:
    if not os.path.exists(RECOVERY_FILE):
        return []
    with open(RECOVERY_FILE, encoding="utf-8") as f:
        return [ln if ln.endswith("\n") else ln + "\n" for ln in f if ln.strip()]

def _write_recovery_lines(lines: List[str]):
    """Атомарная перезапись (tmp -> os.replace): сбой посреди записи не портит файл."""
    if not lines:
        if os.path.exists(RECOVERY_FILE):
            os.remove(RECOVERY_FILE)
        return
    tmp = RECOVERY_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.writelines(lines)
    os.replace(tmp, RECOVERY_FILE)
    os.chmod(RECOVERY_FILE, 0o600)

def save_recovery_credentials(ip: str, user: str, pw: str):
    """Вызывается СРАЗУ после chpasswd. Новый пароль вытесняет старую запись того же сервера
    (старый пароль после chpasswd уже недействителен — оставлять его только путало бы)."""
    new = f"{ip}:{PROXY_PORT}:{user}:{pw}:{RUN_ID}\n"
    with _creds_lock:
        keep = [ln for ln in _read_recovery_lines()
                if (_parse_recovery_line(ln) or (None, None))[0] != ip]
        _write_recovery_lines(keep + [new])
        _pending_ips.add(ip)

def leftover_ips() -> List[str]:
    """IP, чьи записи остались от прежних прогонов (RUN_ID другой)."""
    with _creds_lock:
        parsed = [_parse_recovery_line(ln) for ln in _read_recovery_lines()]
    return sorted({p[0] for p in parsed if p and p[1] != RUN_ID})

def finalize_recovery(failed: set) -> Tuple[int, int]:
    """По итогам НОРМАЛЬНО завершённого прогона убираем записи этого прогона для успешных серверов
    (их пароль уже в OUTPUT_FILE). Остаются: упавшие этого прогона и ВСЕ записи прежних прогонов.
    Возвращает (упавших_этого_прогона, записей_прежних_прогонов)."""
    with _creds_lock:
        keep, kept_failed, kept_old = [], 0, 0
        for ln in _read_recovery_lines():
            p = _parse_recovery_line(ln)
            if not p:
                keep.append(ln); continue
            ip, rid = p
            if rid == RUN_ID:
                if ip in failed:
                    keep.append(ln); kept_failed += 1
            else:
                keep.append(ln); kept_old += 1
        _write_recovery_lines(keep)
        return kept_failed, kept_old

# ============================================================
# ЛОГИКА УСТАНОВКИ
# ============================================================
DANTED_BIN_APT = "/usr/sbin/danted"
DANTED_BIN_SRC = "/usr/local/sbin/danted"

def pick_password(host, given: str) -> str:
    if given and is_safe_password(given):
        return given
    if given:
        logger.warning("[%s] пароль из servers.txt небезопасен — игнорирую", host.ip)

    if REUSE_EXISTING_PASSWORD:
        # Ищем в microsocks env
        out = host.run("sed -n 's/^PROXY_PASS=//p' /etc/microsocks.env 2>/dev/null | tr -d \"'\\\"\"", check=False).stdout.strip()
        if is_safe_password(out):
            logger.info("[%s] использую прежний пароль из microsocks", host.ip)
            return out
        # Ищем в старом danted passwd
        old_pw = host.run("cat /etc/danted/passwd 2>/dev/null | cut -d: -f2 | head -1", check=False).stdout.strip()
        if is_safe_password(old_pw):
            logger.info("[%s] использую прежний пароль из старого danted", host.ip)
            return old_pw
    return gen_password()

def repair_dpkg(host):
    """Мягкая починка dpkg перед фолбэком на сборку. Best-effort: любая ошибка (в т.ч. таймаут,
    который run() бросает даже при check=False) только логируется и не валит сервер.
    apt -f install запускается лишь если dpkg всё ещё сломан и с --no-remove: он не будет
    удалять пакеты и тянуть рекомендуемые."""
    try:
        host.run_silent("dpkg --configure -a", check=False, timeout=300)
        state = host.run('[ -n "$(dpkg --audit 2>/dev/null)" ] && echo broken || echo ok', check=False).stdout.strip()
        if state == "broken":
            logger.warning("[%s] dpkg всё ещё в неконсистентном состоянии — apt -f install (--no-remove)", host.ip)
            host.run_silent("DEBIAN_FRONTEND=noninteractive apt-get -f install -y "
                            "--no-install-recommends --no-remove", check=False, timeout=300)
    except RuntimeError as e:
        logger.warning("[%s] repair_dpkg: %s — продолжаю без починки", host.ip, str(e)[:120])

def apt_update(host):
    """ЕДИНСТВЕННЫЙ apt-get update на сервер — вызывается из process_server.
    install_dante_via_apt и compile_dante_from_source его не повторяют."""
    host.run_silent('[ -z "$(dpkg --audit 2>/dev/null)" ] || dpkg --configure -a', check=False, timeout=300)
    last = None
    for attempt in range(1, 4):
        try:
            host.run("DEBIAN_FRONTEND=noninteractive apt-get update -qq "
                     "-o DPkg::Lock::Timeout=120 -o Acquire::Retries=3", timeout=240)
            return
        except RuntimeError as e:      # например, блокировка apt у unattended-upgrades на свежем VPS
            last = e
            logger.warning("[%s] apt-get update, попытка %s/3: %s", host.ip, attempt, str(e)[:100])
            if attempt < 3: time.sleep(10)
    raise last

def apt_has_dante(host) -> bool:
    cand = host.run("apt-cache policy dante-server 2>/dev/null | awk '/Candidate:/{print $2}'",
                    check=False).stdout.strip()
    return bool(cand) and cand != "(none)"

def install_dante_via_apt(host):
    """Бросает RuntimeError при сбое. Сборку из исходников здесь НЕ запускаем — это решает install_dante."""
    logger.info("[%s] Installing dante-server via apt...", host.ip)
    # postinst пакета пытается стартовать danted с дефолтным конфигом — запрещаем на время установки
    created = host.run("[ -e /usr/sbin/policy-rc.d ] && echo exists || echo no", check=False).stdout.strip() == "no"
    if created:
        host.write_file("/usr/sbin/policy-rc.d", "#!/bin/sh\nexit 101\n", mode=0o755)
    try:
        host.run("DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=120 "
                 "--no-install-recommends dante-server curl ca-certificates iproute2 procps", timeout=420)
        host.run(f"test -x {DANTED_BIN_APT}")
    finally:
        if created:
            host.run("rm -f /usr/sbin/policy-rc.d", check=False)

def compile_dante_from_source(host):

    if not DANTE_SHA256:
        raise RuntimeError(
            "DANTE_SHA256 не задан — отказываюсь собирать из непроверенного архива. "
            "Впиши sha256 файла dante-{}.tar.gz".format(DANTE_VERSION)
        )
    logger.info("[%s] Compiling Dante %s from source...", host.ip, DANTE_VERSION)
    host.run("DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=120 "
             "--no-install-recommends build-essential curl wget ca-certificates iproute2 procps", timeout=420)

    sha_check = f'echo "{DANTE_SHA256}  dante-{DANTE_VERSION}.tar.gz" | sha256sum -c -' if DANTE_SHA256 else "true"
    # set -e: при сбое wget/cd команды не идут дальше. CFLAGS: на GCC>=14 (Debian 13) старый configure
    # Dante иначе может падать на implicit-declaration. Логи сборки — в /tmp/dante-*.log.
    build_cmd = f"""
set -e
cd /tmp
rm -rf dante-{DANTE_VERSION} dante-{DANTE_VERSION}.tar.gz
wget -nv --https-only --secure-protocol=TLSv1_2 --tries=3 --timeout=30 https://www.inet.no/dante/files/dante-{DANTE_VERSION}.tar.gz
{sha_check}
tar xzf dante-{DANTE_VERSION}.tar.gz
cd dante-{DANTE_VERSION}
export CFLAGS="-O2 -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types -Wno-error=int-conversion"
./configure --prefix=/usr/local --sysconfdir=/etc --localstatedir=/var --disable-client >/tmp/dante-configure.log 2>&1 || {{ tail -n 30 /tmp/dante-configure.log >&2; exit 1; }}
MEM_KB=$(awk '/MemTotal/{{print $2}}' /proc/meminfo); J=1; [ "$MEM_KB" -gt 900000 ] && J=2; make -j"$J" >/tmp/dante-make.log 2>&1 || {{ tail -n 30 /tmp/dante-make.log >&2; exit 1; }}
make install-strip >/tmp/dante-install.log 2>&1 || {{ tail -n 30 /tmp/dante-install.log >&2; exit 1; }}
cd /tmp && rm -rf dante-{DANTE_VERSION} dante-{DANTE_VERSION}.tar.gz
"""
    host.run(build_cmd, check=True, timeout=900)
    host.run(f"ln -sf /usr/local/sbin/sockd {DANTED_BIN_SRC}")
    host.run(f"test -x {DANTED_BIN_SRC}")

def install_dante(host) -> str:
    """Ставит Dante и возвращает путь к бинарнику.
    apt -> при RuntimeError ОДИН фолбэк на сборку. Сборка стоит вне try, поэтому
    запускается максимум один раз, а её ошибка уходит наверх без повторов."""
    if apt_has_dante(host):
        try:
            install_dante_via_apt(host)
            return DANTED_BIN_APT
        except RuntimeError as e:
            logger.warning("[%s] apt-установка не удалась (%s) — фолбэк на сборку из исходников",
                           host.ip, str(e)[:120])
            repair_dpkg(host)     # apt мог оставить пакет в полунастроенном состоянии
    compile_dante_from_source(host)
    return DANTED_BIN_SRC

def detect_self_ips(host, iface: str) -> List[str]:
    """Собственные IPv4 сервера: их надо блокировать, иначе через прокси можно достучаться
    до локальных сервисов (sshd и т.д.) по внешнему адресу."""
    res = host.run(f"ip -4 -o addr show dev {iface} 2>/dev/null | awk '{{print $4}}' | cut -d/ -f1",
                   check=False).stdout.split()
    ips = {i for i in res if IPV4_RE.match(i)}
    if IPV4_RE.match(host.ip):
        ips.add(host.ip)
    return sorted(ips)

SSHD_DROPIN = "/etc/ssh/sshd_config.d/10-proxy-proxyuser.conf"

def deny_ssh_for_proxyuser(host):
    """DenyUsers для proxyuser отдельным drop-in. Если sshd -t не проходит, файл УДАЛЯЕМ (иначе
    битый drop-in остался бы и мог не дать sshd подняться при следующем рестарте/ребуте),
    причину пишем в лог и отдельно выясняем, виноват ли наш файл."""
    host.run("mkdir -p /etc/ssh/sshd_config.d")
    host.write_file(SSHD_DROPIN, f"DenyUsers {PROXY_USER}\n")
    t = host.run("sshd -t", check=False)
    if t.exit_code != 0:
        reason = (t.stderr or t.stdout)[:200]
        host.run(f"rm -f {SSHD_DROPIN}", check=False)
        if host.run("sshd -t", check=False).exit_code == 0:
            logger.warning("[%s] sshd -t не прошёл с %s (%s) — файл удалён, sshd не тронут",
                           host.ip, SSHD_DROPIN, reason)
        else:
            logger.warning("[%s] sshd -t падает и без нашего файла (%s) — проблема не от скрипта; "
                           "drop-in удалён, reload пропущен", host.ip, reason)
        return
    r = host.run("systemctl reload ssh 2>/dev/null || systemctl reload sshd", check=False)
    if r.exit_code != 0:
        logger.warning("[%s] reload sshd не удался: %s", host.ip, (r.stderr or r.stdout)[:150])

def setup_dante_service(host, pw: str, danted_bin: str):
    """Общая настройка конфига, юнита и пользователя."""
    # 1. Пользователь
    host.run(f"id -u {PROXY_USER} >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin {PROXY_USER}")
    host.run("chpasswd", stdin_data=f"{PROXY_USER}:{pw}\n")
    # Пароль на сервере уже изменён — фиксируем его на диске немедленно
    save_recovery_credentials(host.ip, PROXY_USER, pw)
    logger.info("[%s] Пароль установлен и сохранён в %s", host.ip, RECOVERY_FILE)

    # 2. Интерфейс
    iface_res = host.run("ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}' | head -1", check=False).stdout.strip()
    iface = iface_res or "eth0"
    logger.info("[%s] Detected interface: %s", host.ip, iface)

    # 3. Конфиг
    self_blocks = "".join(
        f"socks block {{\n    from: 0.0.0.0/0 to: {ip}/32\n    log: error\n}}\n"
        for ip in detect_self_ips(host, iface))
    conf = (DANTED_CONF_TEMPLATE.replace("@@PORT@@", str(PROXY_PORT))
            .replace("@@IFACE@@", iface).replace("@@SELF_BLOCKS@@", self_blocks))
    host.write_file("/etc/danted.conf", conf)

    # 4. Валидация (бинарник известен из install_dante — без угадывания по наличию файлов)
    r = host.run(f"{danted_bin} -Vf /etc/danted.conf", check=False)
    if r.exit_code != 0:
        raise RuntimeError(f"danted.conf invalid: {(r.stderr or r.stdout)[:200]}")
    logger.info("[%s] Config validated.", host.ip)

    # 5. Systemd Unit. PID-файл задаётся явно через -p, иначе PIDFile= не совпадает с реальным.
    unit_content = f"""\
[Unit]
Description=Dante SOCKS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile={PID_FILE}
ExecStart={danted_bin} -D -f /etc/danted.conf -p {PID_FILE}
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
"""
    host.write_file("/etc/systemd/system/danted.service", unit_content)
    host.run("mkdir -p /etc/systemd/system/danted.service.d")
    host.write_file("/etc/systemd/system/danted.service.d/10-proxy.conf", DANTED_DROPIN)

    # 6. Healthcheck & Finalize
    host.write_file("/opt/proxy-hc.sh", HEALTHCHECK_SCRIPT.replace("@@PORT@@", str(PROXY_PORT)), mode=0o700)
    host.write_file("/etc/systemd/system/proxy-hc.service", HC_SERVICE)
    host.write_file("/etc/systemd/system/proxy-hc.timer", HC_TIMER)

    # Запрет SSH для proxyuser (с проверкой sshd -t и откатом)
    deny_ssh_for_proxyuser(host)

    # 7. Старт
    host.run("systemctl daemon-reload")
    host.run("systemctl enable danted")
    host.run("systemctl restart danted")
    host.run("systemctl enable --now proxy-hc.timer")
    time.sleep(3)

    if not host.is_active("danted"):
        logs = host.run("journalctl -u danted -n 20 --no-pager", check=False).stdout
        raise RuntimeError(f"Dante failed to start.\nLogs: {logs}")

    logger.info("[%s] Dante service started successfully.", host.ip)

def _curl_code(host, creds: str, url: str, max_time: int = 12) -> str:
    return host.run(
        f"curl -s -o /dev/null -w '%{{http_code}}' --max-time {max_time} "
        f"--socks5-hostname {creds}@127.0.0.1:{PROXY_PORT} {url}",
        check=False, timeout=max_time + 8).stdout.strip()

def _curl_rc(host, creds: str, url: str, max_time: int = 6) -> str:
    return host.run(
        f"curl -s -o /dev/null --max-time {max_time} "
        f"--socks5-hostname {creds}@127.0.0.1:{PROXY_PORT} {url}; echo $?",
        check=False, timeout=max_time + 8).stdout.strip()

def verify_proxy(host, pw: str):
    """Проверка работы прокси.
    ВАЖНО про curl rc=97 (CURLE_PROXY): его дают И блокировка правилом Dante, И ошибка
    SOCKS-авторизации. Поэтому тест блокировки осмыслен только после положительного контроля:
    раз запрос наружу с этими же логином/паролем прошёл — авторизация точно в порядке, и
    rc=97 на 127.0.0.1 значит именно блокировку.
    Недоступность внешних сайтов НЕ делает сервер FAILED — только предупреждение."""
    # 1. Рукопожатие (od печатает ' 05 02' с пробелами — их убираем)
    hs = host.run(
        rf"""timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{PROXY_PORT}; printf "\x05\x01\x02" >&3; """
        rf"""head -c2 <&3 | od -An -tx1' 2>/dev/null | tr -d ' \n'""", check=False).stdout.strip()
    if hs != "0502":
        raise RuntimeError(f"SOCKS5 handshake failed: '{hs}' (expected 0502)")

    good = f"{PROXY_USER}:{pw}"

    # 2. Положительный контроль: любой HTTP-код, кроме 000, хотя бы с одной из целей
    egress_url = None
    for url in TEST_URLS:
        code = _curl_code(host, good, url)
        if code not in ("", "000"):
            logger.info("[%s] Proxy VERIFIED (%s -> HTTP %s).", host.ip, url, code)
            egress_url = url
            break
        logger.warning("[%s] Запрос %s через прокси не прошёл (code=%s).", host.ip, url, code or "-")

    if not egress_url:
        logger.warning("[%s] Выход наружу через прокси не подтверждён ни по одной из %s целей "
                       "(DNS/файрвол/авторизация?). Dante запущен, пароль сохранён. Проверки блокировки "
                       "и неверного пароля ПРОПУЩЕНЫ: без положительного контроля rc=97 неоднозначен.",
                       host.ip, len(TEST_URLS))
        return

    # 3. Прокси обязан отвергать неверный пароль (иначе это открытый прокси)
    bad_rc = _curl_rc(host, f"{PROXY_USER}:wrong{secrets.token_hex(4)}", egress_url)
    if bad_rc == "0":
        raise RuntimeError("Прокси принимает НЕВЕРНЫЙ пароль — авторизация не работает (открытый прокси)!")

    # 4. Блокировка внутренних сетей (авторизация уже подтверждена п.2 => 97 = блок по правилу)
    for target in ("127.0.0.1", "localhost"):
        rc = _curl_rc(host, good, f"http://{target}:22/")
        if rc == "97":
            logger.info("[%s] Блокировка %s работает.", host.ip, target)
        else:
            logger.warning("[%s] ВНИМАНИЕ: доступ к %s через прокси НЕ заблокирован (curl rc=%s)!",
                           host.ip, target, rc)

def process_server(ip: str, ssh_pass: str, given_pass: str):
    try:
        with RemoteHost(ip, ssh_pass) as host:
            logger.info("[%s] === START PROCESSING ===", ip)

            # 1. Очистка старого. pkill принимает один паттерн; у собранного демона имя процесса — sockd.
            host.run_silent("systemctl stop microsocks danted || true", check=False)
            host.run_silent("pkill -9 -x microsocks; pkill -9 -x danted; pkill -9 -x sockd; true", check=False)
            host.run_silent("systemctl disable microsocks danted || true", check=False)
            time.sleep(1)

            # 2. Выбор пароля
            pw = pick_password(host, given_pass)

            # 3. Установка: один apt-get update -> apt (или единственный фолбэк на сборку)
            apt_update(host)
            danted_bin = install_dante(host)

            # 4. Настройка (внутри — chpasswd и немедленное сохранение пароля)
            setup_dante_service(host, pw, danted_bin)

            # 5. Проверка
            verify_proxy(host, pw)

            logger.info("[%s] === DONE ===", ip)
            return ip, PROXY_USER, pw

    except Exception as e:
        logger.error("[%s] FAILED: %s", ip, str(e)[:200])
        if ip in _pending_ips:
            logger.error("[%s] Пароль на сервере уже изменён; он сохранён в %s", ip, RECOVERY_FILE)
        return None

def load_servers(path) -> List[Tuple[str, str, str]]:
    if not os.path.exists(path): raise FileNotFoundError(path)
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            p = line.split(":", 2)
            if len(p) >= 2:
                out.append((p[0].strip(), p[1].strip(), p[2].strip() if len(p) > 2 else ""))
    return out

def main():
    print("=" * 60)
    print("  FINAL DANTE INSTALLER v3.1 (Debian 12/13)")
    print("=" * 60)
    servers = load_servers(SERVERS_FILE)
    if not servers:
        print("No servers found in servers.txt"); return

    old = leftover_ips()
    if old:
        print(f"ВНИМАНИЕ: в {RECOVERY_FILE} есть записи прежних (прерванных/неудачных) прогонов: {', '.join(old)}")
        print("  Они НЕ будут удалены. Пароль сервера, который есть в servers.txt, заменится новым.\n")

    results, failed = [], []
    ex = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        futures = {ex.submit(process_server, ip, pwd, pp): ip for ip, pwd, pp in servers}
        for fut in as_completed(futures):
            res = fut.result()
            if res: results.append(res)
            else: failed.append(futures[fut])
    except KeyboardInterrupt:
        print(f"\nПРЕРВАНО. Пароли, уже изменённые на серверах, лежат в {RECOVERY_FILE} (в т.ч. успешных).")
        sys.stdout.flush()
        ex.shutdown(wait=False, cancel_futures=True)
        os._exit(130)
    ex.shutdown(wait=True)

    if results:
        order = {ip: i for i, (ip, _, _) in enumerate(servers)}
        results.sort(key=lambda r: order.get(r[0], 0))
        fd = os.open(OUTPUT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for ip, user, pw in results:
                f.write(f"{ip}:{PROXY_PORT}:{user}:{pw}\n")
        os.chmod(OUTPUT_FILE, 0o600)
        print(f"\nSUCCESS: {len(results)} servers configured.")
        print(f"Creds saved to: {OUTPUT_FILE}")
    else:
        print("\nALL FAILED.")

    if failed:
        print(f"FAILED ({len(failed)}): {', '.join(failed)}")
    kept_failed, kept_old = finalize_recovery(set(failed))
    if kept_failed:
        print(f"ВНИМАНИЕ: на {kept_failed} упавших серверах пароль уже изменён — он в {RECOVERY_FILE}")
    if kept_old:
        print(f"В {RECOVERY_FILE} также сохранены {kept_old} записей прежних прогонов (не тронуты).")

if __name__ == "__main__":
    main()
