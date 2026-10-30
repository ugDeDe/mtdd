#!/usr/bin/env bash
# mtdd installer, updater, and interactive management launcher.
#
# Modes:
#   - fresh system + installer flags  -> install or update the service;
#   - installed system, no arguments  -> interactive management menu;
#   - management subcommand           -> non-interactive management action.
set -Eeuo pipefail
umask 077

readonly MTDD_BIN=/usr/local/bin/mtdd
readonly MTDD_CTL=/usr/local/bin/mtdd-ctl
readonly MTDD_CONF=/etc/mtdd/config.json
readonly MTDD_CREDS=/etc/mtdd/credentials.env
readonly MTDD_STATE=/var/lib/mtdd
readonly MTDD_METRICS_HISTORY="$MTDD_STATE/metrics-history.tsv"
readonly MTDD_UNIT=/etc/systemd/system/mtdd.service
readonly MTDD_SERVICE=mtdd.service
readonly MTDD_NETTUNE=/usr/local/bin/mtdd-nettune
readonly MTDD_NETTUNE_UNIT=/etc/systemd/system/mtdd-nettune.service
readonly MTDD_NETTUNE_SERVICE=mtdd-nettune.service

repo=${MTDD_REPOSITORY:-ugDeDe/mtdd}
channel=main
channel_set=0
domain=
ad_tag=
proxy_port=443
port_set=0
public_host=
public_port=
user_name=admin
user_set=0
output=/usr/local/bin/mtdd
base_url=
binary_only=0

invocation_args=$#
command=
cargs=()
yes_flag=0

# ---------------------------------------------------------------------------
# Оформление: градиент, рамки, спиннер. Всё отключается само без терминала,
# через NO_COLOR (цвета) и MTDD_NO_ANIM=1 (анимации).
# ---------------------------------------------------------------------------
ui_color=0 ui_anim=0
bold= dim= reset=
accent= cyan= violet= green= yellow= red= gray=
if [[ -t 1 && ${TERM:-dumb} != dumb && ! ${NO_COLOR+x} ]]; then
    ui_color=1
    bold=$'\033[1m'; dim=$'\033[2m'; reset=$'\033[0m'
    accent=$'\033[38;5;45m'      # циан
    violet=$'\033[38;5;141m'
    green=$'\033[38;5;114m'
    yellow=$'\033[38;5;221m'
    red=$'\033[38;5;203m'
    gray=$'\033[38;5;245m'
    cyan=$accent
    if [[ -z ${MTDD_NO_ANIM+x} ]] && { [[ -t 0 ]] || { true </dev/tty; } 2>/dev/null; }; then
        ui_anim=1
    fi
fi

has_tty() { [[ -t 0 || -t 1 || -t 2 ]] && { : </dev/tty; } 2>/dev/null; }
die() { err "$*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Не найдена необходимая команда: $1"; }

# Ширина строки в колонках терминала (корректно для кириллицы).
text_width() { printf '%s' "${1-}" | wc -L; }
pad() { # pad ТЕКСТ ШИРИНА — добить пробелами до ширины
    local text=${1-} width=$2 len
    len=$(text_width "$text")
    printf '%s' "$text"
    ((len < width)) && printf '%*s' $((width - len)) ''
    return 0
}

hr() { # градиентная линейка
    if ((ui_color)); then
        local shade
        for shade in 45 51 81 117 153 189; do
            printf '\033[38;5;%sm%s\033[0m' "$shade" '────────────'
        done
        printf '\n'
    else
        printf '%s\n' '────────────────────────────────────────────────────────────────────────'
    fi
}
line() { printf '  '; hr; }
section() {
    printf '\n  %s▌%s %s%s%s\n  ' "$violet" "$reset" "$bold" "$*" "$reset"
    hr
}
step() { printf '  %s›%s %s\n' "$accent" "$reset" "$*"; }
ok() { printf '  %s✔%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '  %s▲%s %s\n' "$yellow" "$reset" "$*"; }
err() { printf '  %s✖%s %s\n' "$red" "$reset" "$*" >&2; }
kv() { # kv ПОДПИСЬ ЗНАЧЕНИЕ — выровненная пара
    printf '  %s' "$gray"
    pad "${1-}" 16
    printf '%s%s\n' "$reset" "${2-}"
}

banner() { # banner [ПОДЗАГОЛОВОК]
    local sub=${1-mtdd · MTProto / FakeTLS}
    local -a art=(
        '███╗   ███╗████████╗██████╗ ██████╗'
        '████╗ ████║╚══██╔══╝██╔══██╗██╔══██╗'
        '██╔████╔██║   ██║   ██║  ██║██║  ██║'
        '██║╚██╔╝██║   ██║   ██║  ██║██║  ██║'
        '██║ ╚═╝ ██║   ██║   ██████╔╝██████╔╝'
        '╚═╝     ╚═╝   ╚═╝   ╚═════╝ ╚═════╝'
    )
    printf '\n'
    if ((ui_color)); then
        local -a shades=(45 51 81 117 153 189)
        local row
        for row in "${!art[@]}"; do
            printf '  \033[38;5;%sm%s\033[0m\n' "${shades[row]}" "${art[row]}"
            ((ui_anim)) && sleep 0.015
        done
        printf '  %s%s%s\n' "$gray" "$sub" "$reset"
    else
        printf '  mtdd — %s\n' "$sub"
    fi
    printf '  '; hr
}

spin() { # spin [--quiet] ЗАГОЛОВОК КОМАНДА [АРГУМЕНТЫ…]
    local quiet=0
    if [[ ${1-} == --quiet ]]; then quiet=1; shift; fi
    local title=${1-}; shift
    local rc=0
    if ((!ui_anim)); then
        if "$@" 2>/dev/null 1>/dev/null; then return 0; else rc=$?; fi
        err "$title · ошибка (код $rc)"
        return $rc
    fi
    local log start=$SECONDS i=0 frame
    log=$(mktemp)
    "$@" >"$log" 2>&1 &
    local pid=$!
    local -a frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
    while kill -0 "$pid" 2>/dev/null; do
        frame=${frames[i]}
        printf '\r\033[2K  %s%s%s %s %s· %02d:%02d%s' \
            "$accent" "$frame" "$reset" "$title" "$dim" \
            $(((SECONDS - start) / 60)) $(((SECONDS - start) % 60)) "$reset" >/dev/tty
        i=$(((i + 1) % ${#frames[@]}))
        sleep 0.08
    done
    if wait "$pid"; then rc=0; else rc=$?; fi
    printf '\r\033[2K' >/dev/tty
    if ((rc == 0)); then
        ((quiet)) || ok "$title · $((SECONDS - start)) с"
    else
        err "$title · ошибка (код $rc)"
        sed 's/^/     /' "$log" >&2 || true
    fi
    rm -f -- "$log"
    return $rc
}

service_badge() { # цветная метка состояния службы
    local state
    state=$(systemctl is-active "$MTDD_SERVICE" 2>/dev/null || true)
    case $state in
        active) printf '%s●%s активна' "$green" "$reset" ;;
        activating|reloading) printf '%s●%s %s' "$yellow" "$reset" "$state" ;;
        failed) printf '%s●%s ошибка' "$red" "$reset" ;;
        *) printf '%s○%s %s' "$gray" "$reset" "${state:-нет}" ;;
    esac
}

usage() {
    cat <<'EOF'
mtdd — установка и управление MTProto-прокси

Использование:
  sudo bash install.sh [ПАРАМЕТРЫ]           Установка или обновление
  sudo mtdd-ctl                              Меню управления (после установки)
  sudo bash install.sh КОМАНДА [АРГУМЕНТЫ]   Управление без меню

Команды управления (требуют root):

  status                          Состояние службы, API и пулов ME
  service start|stop|restart      Действие над systemd-службой
  logs [N|follow]                 Журнал: последние N строк (по умолчанию 50) или поток
  users [list]                    Список пользователей
  users add ИМЯ                   Создать пользователя и показать ссылку
  users enable|disable ИМЯ        Включить или отключить пользователя
  users remove ИМЯ [--yes]        Удалить пользователя (без подтверждения с --yes)
  users rotate ИМЯ                Заменить секрет и показать новую ссылку
  links [ИМЯ]                     Ссылки подключения (все или одного)
  rotate ИМЯ                      То же, что users rotate
  metrics [--watch]               Дашборд: соединения, буферы, ME/DC, RTT, IP, графики
  metrics all|ФИЛЬТР              Сырые метрики Prometheus (по умолчанию mtdd_)
  host АДРЕС [ПОРТ]               Сменить публичный адрес ссылок и перезапустить
  check-config                    Проверить конфигурацию бинарником
  update [--branch main|dev]      Обновить бинарник (то же, что повторная установка)
  uninstall [--yes]               Удалить прокси с сервера
  menu                            Меню управления

Настройка новой установки:

  --domain HOST           Домен маскировки FakeTLS
  --ad-tag HEX            Ненулевой рекламный тег Telegram (32 hex)
  --port PORT             Порт прокси (по умолчанию 443)
  --user NAME             Первый пользователь (по умолчанию admin)
  --public-host HOST      Внешний IP или DNS (по умолчанию автоопределение)
  --public-port PORT      Внешний порт при NAT (по умолчанию --port)

Сборка и режим работы:

  --branch main|dev       Канал бинарника (по умолчанию main)
  --binary-only           Скачать бинарник без установки службы
  --output PATH           Путь для --binary-only
  --repo OWNER/REPO       Репозиторий релизов (по умолчанию ugDeDe/mtdd)
  --base-url URL          HTTPS-зеркало каталога релизов
  -h, --help              Показать справку

API: 127.0.0.1:9090. При обновлении пользователи и токен сохраняются.
Ссылка подключения выводится после установки и содержит секрет пользователя.
EOF
}

# Разбор аргументов: первый позиционный токен — подкоманда управления,
# остальные позиционные — её аргументы; флаги принадлежат установщику.
SUBCOMMANDS=" status service start stop restart logs users links rotate metrics host check-config update uninstall menu help "
positional=()
while (($#)); do
    case $1 in
        --repo|--branch|--domain|--ad-tag|--port|--public-host|--public-port|--user|--output|--base-url)
            (($# >= 2)) || die "Не указано значение для $1"
            case $1 in
                --repo) repo=$2 ;; --branch) channel=$2; channel_set=1 ;; --domain) domain=$2 ;;
                --ad-tag) ad_tag=$2 ;; --port) proxy_port=$2; port_set=1 ;; --user) user_name=$2; user_set=1 ;;
                --public-host) public_host=$2 ;; --public-port) public_port=$2 ;;
                --output) output=$2 ;; --base-url) base_url=$2 ;;
            esac
            shift 2 ;;
        --binary-only) binary_only=1; shift ;;
        --yes) yes_flag=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*)
            # У metrics свои ключи (--watch, --all, фильтр) — не трогаем их.
            if ((${#positional[@]})) && [[ ${positional[0]} == metrics ]]; then
                positional+=("$1")
                shift
            else
                die "Неизвестный параметр: $1 (справка: --help)"
            fi ;;
        *) positional+=("$1"); shift ;;
    esac
done
if ((${#positional[@]})); then
    command=${positional[0]}
    if [[ $SUBCOMMANDS != *" $command "* ]]; then
        die "Неизвестная команда: $command (справка: --help)"
    fi
    cargs=("${positional[@]:1}")
fi
[[ $command == update ]] && command= # обновление — это повторный запуск установщика
if [[ -n $command && $binary_only == 1 ]]; then
    die 'Команды управления несовместимы с --binary-only'
fi
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'Неверный репозиторий; используйте OWNER/REPO'

# ---------------------------------------------------------------------------
# Общие валидаторы (установщик и команда host)
# ---------------------------------------------------------------------------
valid_dns_name() {
    python3 - "$1" <<'PY'
import re
import sys
name = sys.argv[1]
labels = name.split('.')
ok = len(name) <= 253 and all(
    1 <= len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label)
    for label in labels
)
sys.exit(0 if ok else 1)
PY
}

valid_public_host() {
    python3 - "$1" <<'PY'
import ipaddress, re, sys
host = sys.argv[1]
try:
    valid = not ipaddress.ip_address(host).is_unspecified
except ValueError:
    valid = len(host) <= 253 and all(
        1 <= len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label)
        for label in host.split('.'))
sys.exit(0 if valid else 1)
PY
}

valid_port() {
    [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

valid_user_name() {
    [[ $1 =~ ^[A-Za-z0-9_.-]{1,64}$ ]]
}

prompt() {
    local variable=$1 label=$2 fallback=${3-} answer
    has_tty || die "$label: требуется значение (укажите его параметром при запуске без терминала)"
    printf '  → %s%s: ' "$label" "${fallback:+ [$fallback]}" >/dev/tty
    IFS= read -r answer </dev/tty || die "Не удалось прочитать ответ: $label"
    printf -v "$variable" '%s' "${answer:-$fallback}"
}

confirm() { # confirm ВОПРОС -> 0 при подтверждении; без терминала — отказ
    local answer
    has_tty || return 1
    printf '  → %s [y/N]: ' "$1" >/dev/tty
    IFS= read -r answer </dev/tty || return 1
    [[ $answer == y || $answer == Y || $answer == да ]]
}

# ---------------------------------------------------------------------------
# Режим управления: доступ к локальному API и службе
# ---------------------------------------------------------------------------
mg_installed() {
    [[ -x $MTDD_BIN && -f $MTDD_CONF && -f $MTDD_CREDS ]]
}

mg_require_root() {
    ((EUID == 0)) || { err 'Требуются права root: запустите через sudo'; return 1; }
}

mg_require_install() {
    if [[ ! -f $MTDD_CONF || ! -f $MTDD_CREDS ]]; then
        err 'mtdd не установлен или установка неполная; выполните: sudo bash install.sh'
        return 1
    fi
}

mg_require_tools() {
    need curl
    need python3
    need systemctl
}

cfg_get() { # cfg_get КЛЮЧ [ПО_УМОЛЧАНИЮ]
    python3 - "$MTDD_CONF" "$1" "${2-}" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
value = cfg.get(sys.argv[2], sys.argv[3])
print(value if value is not None else "")
PY
}

token_read() {
    local token
    token=$(sed -n 's/^\(export \)\{0,1\}MTDD_API_TOKEN=\([A-Za-z0-9]\{32,512\}\)$/\2/p' "$MTDD_CREDS" | head -1)
    [[ -n $token ]] || { err "В $MTDD_CREDS нет корректного MTDD_API_TOKEN"; return 1; }
    printf '%s' "$token"
}

api() { # api МЕТОД ПУТЬ [JSON-ТЕЛО] — печатает тело ответа или завершается ошибкой
    local method=$1 path=$2 body=${3-} token host port
    token=$(token_read) || return 1
    host=$(cfg_get control_host 127.0.0.1)
    port=$(cfg_get control_port 9090)
    [[ $host == 0.0.0.0 || $host == '::' || $host == '*' ]] && host=127.0.0.1
    [[ $host == *:* ]] && host="[$host]"
    local -a extra=()
    [[ -n $body ]] && extra+=(-H 'Content-Type: application/json' -d "$body")
    curl -fsS --max-time 10 -X "$method" -H "Authorization: Bearer $token" \
        "${extra[@]}" "http://${host}:${port}${path}"
}

api_fields() { # api_fields JSON — краткая сводка ключевых полей data
    python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    print("—")
    raise SystemExit
try:
    data = json.loads(raw).get("data", {})
except Exception:
    print(raw)
    raise SystemExit
keys = ("status", "ready", "revision")
parts = ["{}={}".format(key, data[key]) for key in keys if key in data]
print(" · ".join(parts) if parts else raw)
' <<<"${1-}"
}

api_endpoint() {
    local host port
    host=$(cfg_get control_host 127.0.0.1)
    port=$(cfg_get control_port 9090)
    [[ $host == 0.0.0.0 || $host == '::' || $host == '*' ]] && host=127.0.0.1
    printf 'http://%s:%s' "$host" "$port"
}

cmd_status() {
    local enabled health ready summary status_json
    enabled=$(systemctl is-enabled "$MTDD_SERVICE" 2>/dev/null || true)
    section 'mtdd · состояние'
    kv 'Служба' "$(service_badge) · автозапуск: ${enabled:-unknown}"
    health=$(api GET /v1/health 2>/dev/null) || health=
    ready=$(api GET /v1/ready 2>/dev/null) || ready=
    if [[ -z $health && -z $ready ]]; then
        kv 'API' "$(api_endpoint) · не отвечает"
        warn 'Служба может запускаться или завершилась с ошибкой; журнал: sudo install.sh logs 100'
        return 1
    fi
    kv 'API' "$(api_endpoint)"
    kv 'health' "$(api_fields "$health")"
    kv 'ready' "$(api_fields "$ready")"
    status_json=$(api GET /v1/status 2>/dev/null) || status_json=
    summary=$(printf '%s' "$status_json" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin).get("data", {})
except Exception:
    sys.exit(1)

def human(seconds):
    if not isinstance(seconds, int):
        return "?"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return "{}д {}ч {}м".format(days, hours, minutes)
    if hours:
        return "{}ч {}м".format(hours, minutes)
    if minutes:
        return "{}м {}с".format(minutes, secs)
    return "{}с".format(secs)

print("  Аптайм: {} · пользователей: {} (включено {})".format(
    human(data.get("uptime_seconds")), data.get("users_total", "?"),
    data.get("users_enabled", "?")))
print("  Соединений: {} · принято: {} · отклонено: {} · уникальных IP: {}".format(
    data.get("connections_active", "?"), data.get("connections_accepted_total", "?"),
    data.get("connections_rejected_total", "?"), data.get("unique_ips_active", "?")))
me = data.get("me") or {}
dcs = me.get("dcs") or []
if dcs:
    rtts = [dc.get("ping_rtt_us", 0) / 1000.0 for dc in dcs
            if dc.get("connected") and dc.get("ping_rtt_us")]
    print("  ME/DC: {} из {} в сети · RTT {}".format(
        sum(1 for dc in dcs if dc.get("connected")), len(dcs),
        "{:.0f} ms".format(sum(rtts) / len(rtts)) if rtts else "—"))
') || summary=
    if [[ -n $summary ]]; then
        printf '%s\n' "$summary"
        metrics_record "$status_json"
        kv 'Метрики' 'sudo mtdd-ctl metrics · --watch — живой режим с графиками'
        return 0
    fi
    warn 'Не удалось получить /v1/status'
    return 1
}

cmd_service() {
    local action=${1-}
    case $action in
        start|stop|restart) ;;
        *) err 'Использование: install.sh service start|stop|restart'; return 1 ;;
    esac
    systemctl "$action" "$MTDD_SERVICE" || { err "systemctl $action завершился с ошибкой"; return 1; }
    ok "Служба: systemctl $action выполнен · состояние: $(systemctl is-active "$MTDD_SERVICE" 2>/dev/null || echo unknown)"
}

cmd_logs() {
    need journalctl
    local arg=${1:-50}
    case $arg in
        follow|f|-f)
            step 'Журнал в реальном времени (Ctrl+C — выход)…'
            journalctl -u "$MTDD_SERVICE" -f --no-pager ;;
        ''|*[!0-9]*)
            err 'Использование: install.sh logs [ЧИСЛО|follow]'; return 1 ;;
        *)
            journalctl -u "$MTDD_SERVICE" -n "$arg" --no-pager ;;
    esac
}

cmd_users_list() {
    local out
    out=$(api GET /v1/users 2>/dev/null) || { err 'Не удалось получить список пользователей'; return 1; }
    printf '%s' "$out" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)["data"]
except Exception:
    sys.exit(1)
users = data["users"]
print("  Пользователей: {} · ревизия: {}".format(len(users), data.get("revision", "?")))
if not users:
    sys.exit(0)
print("  {:<20} {:<4} {:>10} {:>12}".format("Имя", "Вкл", "Соединений", "Уникальных IP"))
for u in users:
    stats = u.get("stats", {})
    print("  {:<20} {:<4} {:>10} {:>12}".format(
        str(u.get("name", "?")), "да" if u.get("enabled") else "нет",
        str(stats.get("active_connections", 0)), str(stats.get("unique_ips_active", 0))))
' || { err 'Не удалось разобрать список пользователей'; return 1; }
}

print_user_link() { # print_user_link ИМЯ — печатает ссылку из API
    local name=$1 response
    response=$(api GET "/v1/users/$name/links" 2>/dev/null) \
        || { err "Не удалось получить ссылку для $name"; return 1; }
    printf '%s' "$response" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)["data"]
except Exception:
    sys.exit(1)
links = data.get("links", {})
mark = "" if data.get("enabled") else " (disabled)"
print("  {}{}: {}".format(data.get("name", "?"), mark, links.get("telegram", "")))
print("  tg://: {}".format(links.get("native", "")))
' || { err "Не удалось разобрать ссылку для $name"; return 1; }
}

cmd_users_add() {
    local name=$1 response secret
    valid_user_name "$name" || { err 'Имя: 1–64 символа A–Z, a–z, 0–9, _ . -'; return 1; }
    response=$(api POST /v1/users "{\"name\":\"$name\"}" 2>/dev/null) \
        || { err "Не удалось создать $name (уже существует?)"; return 1; }
    secret=$(printf '%s' "$response" | python3 -c 'import json, sys; print(json.load(sys.stdin)["data"].get("secret", ""))') || secret=
    [[ -n $secret ]] && warn "Секрет $name (показывается один раз): $secret"
    print_user_link "$name"
    warn 'Ссылка содержит секрет. Передавайте её только этому пользователю.'
}

cmd_users_set_enabled() {
    local name=$1 value=$2 verb=$3
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    api PATCH "/v1/users/$name" "{\"enabled\":$value}" >/dev/null 2>&1 \
        || { err "Не удалось изменить $name (нет такого пользователя?)"; return 1; }
    ok "Пользователь $name: $verb · активные сессии отозваны"
    [[ $value == true ]] || warn 'Отключённый пользователь не может подключаться до включения'
}

cmd_users_remove() {
    local name=$1 force=${2-}
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    if [[ $force != --yes && $yes_flag != 1 ]]; then
        confirm "Удалить пользователя $name? Ссылка перестанет работать" \
            || { warn "Удаление $name отменено"; return 1; }
    fi
    api DELETE "/v1/users/$name" >/dev/null 2>&1 \
        || { err "Не удалось удалить $name (нет такого пользователя?)"; return 1; }
    ok "Пользователь $name удалён, сессии отозваны"
}

cmd_users_rotate() {
    local name=$1
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    api POST "/v1/users/$name/rotate-secret" '{}' >/dev/null 2>&1 \
        || { err "Не удалось заменить секрет $name (нет такого пользователя?)"; return 1; }
    ok "Секрет $name заменён; старая ссылка больше не работает"
    print_user_link "$name"
    warn 'Передайте пользователю новую ссылку.'
}

cmd_users() {
    local action=${1-list}
    case $action in
        list)
            cmd_users_list ;;
        add)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users add ИМЯ'; return 1; }
            cmd_users_add "${cargs[1]}" ;;
        enable)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users enable ИМЯ'; return 1; }
            cmd_users_set_enabled "${cargs[1]}" true 'включён' ;;
        disable)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users disable ИМЯ'; return 1; }
            cmd_users_set_enabled "${cargs[1]}" false 'отключён' ;;
        remove|delete)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users remove ИМЯ [--yes]'; return 1; }
            cmd_users_remove "${cargs[1]}" "${cargs[2]-}" ;;
        rotate)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users rotate ИМЯ'; return 1; }
            cmd_users_rotate "${cargs[1]}" ;;
        *)
            err "Неизвестное действие users: $action (list|add|enable|disable|remove|rotate)"
            return 1 ;;
    esac
}

cmd_links() {
    if ((${#cargs[@]} >= 1)); then
        print_user_link "${cargs[0]}"
        return
    fi
    local names rc=0 name
    names=$(api GET /v1/users 2>/dev/null | python3 -c 'import json, sys; d = json.load(sys.stdin)["data"]["users"]; print("\n".join(u["name"] for u in d))') \
        || { err 'Не удалось получить список пользователей'; return 1; }
    [[ -n $names ]] || { warn 'Пользователей нет'; return 0; }
    while IFS= read -r name; do
        print_user_link "$name" || rc=1
    done <<< "$names"
    return "$rc"
}

cmd_rotate() {
    ((${#cargs[@]} >= 1)) || { err 'Использование: install.sh rotate ИМЯ'; return 1; }
    cmd_users_rotate "${cargs[0]}"
}

# ---------------------------------------------------------------------------
# Метрики: дашборд, история измерений и графики
# ---------------------------------------------------------------------------
metrics_python() {
    cat <<'PY'
import json
import os
import sys
import time
import unicodedata


def c(name):
    return os.environ.get("MTDD_C_" + name, "")


RESET = c("RESET")
BOLD = c("BOLD")
DIM = c("DIM")
GRAY = c("GRAY")
ACCENT = c("ACCENT")
VIOLET = c("VIOLET")
GREEN = c("GREEN")
YELLOW = c("YELLOW")
RED = c("RED")
COLOR = os.environ.get("MTDD_COLOR") == "1"
WIDTH = 72
GRAPH_WIDTH = 34
BLOCKS = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"


def width(text):
    total = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return total


def pad(text, size):
    return text + " " * max(0, size - width(text))


def cell(text, size, color=""):
    body = pad(text, size)
    return (color + body + RESET) if color else body


def rule():
    return GRAY + "\u2500" * WIDTH + RESET


def section(title):
    return "\n  " + VIOLET + "\u258c" + RESET + " " + BOLD + title + RESET + "\n  " + rule()


def row2(l1, v1, l2="", v2=""):
    out = "  " + GRAY + pad(l1, 19) + RESET + pad(str(v1), 11)
    if l2:
        out += GRAY + pad(l2, 19) + RESET + pad(str(v2), 11)
    return out.rstrip()


def plural(count, one, few, many):
    count = int(count)
    if count % 10 == 1 and count % 100 != 11:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


def note(text):
    return "  " + DIM + text + RESET


def num(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return "\u2014"
    return "{:,}".format(value).replace(",", "\u2009")


def human(size):
    try:
        size = float(size or 0)
    except (TypeError, ValueError):
        return "\u2014"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            if unit == "B" or size >= 100:
                return "{:.0f} {}".format(size, unit)
            return "{:.1f} {}".format(size, unit)
        size /= 1024.0
    return "{:.0f} B".format(size)


def human_duration(seconds):
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return "\u2014"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return "{} \u0434 {} \u0447".format(days, hours)
    if hours:
        return "{} \u0447 {} \u043c".format(hours, minutes)
    if minutes:
        return "{} \u043c\u0438\u043d".format(minutes)
    return "{} \u0441".format(secs)


def load_prom(path):
    series = {}
    if not path:
        return series
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if " " not in line:
                    continue
                key, rest = line.split(" ", 1)
                labels = {}
                if "{" in key:
                    key, raw = key.split("{", 1)
                    for item in raw.rstrip("}").split(","):
                        if "=" not in item:
                            continue
                        label, value = item.split("=", 1)
                        labels[label.strip()] = value.strip().strip('"')
                try:
                    value = float(rest)
                except ValueError:
                    continue
                series.setdefault(key, []).append((labels, value))
    except OSError:
        return {}
    return series


def prom_scalar(prom, key):
    items = prom.get(key) or []
    if not items:
        return None
    return int(items[0][1])


def pnum(prom, key):
    value = prom_scalar(prom, key)
    return num(value) if value is not None else "\u2014"


def history_path():
    return os.environ.get("MTDD_HISTORY_FILE", "")


def history_load(path):
    rows = []
    if not path:
        return rows
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 8:
                    continue
                try:
                    rows.append([float(part) for part in parts])
                except ValueError:
                    continue
    except OSError:
        return []
    return rows


def history_save(path, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(
                "{:.0f}\t{:.0f}\t{:.0f}\t{:.0f}\t{:.1f}\t{:.0f}\t{:.0f}\t{:.0f}\n".format(*row)
            )
    os.replace(tmp, path)


def sample(data, force=False):
    path = history_path()
    if not path:
        return
    now = time.time()
    rows = history_load(path)
    try:
        interval = float(os.environ.get("MTDD_METRICS_INTERVAL", "25"))
    except ValueError:
        interval = 25.0
    if not force and rows and now - rows[-1][0] < interval:
        return
    me = data.get("me") or {}
    dcs = me.get("dcs") or []
    traffic = 0.0
    rtts = []
    for dc in dcs:
        traffic += float(dc.get("rx_bytes_total", 0)) + float(dc.get("tx_bytes_total", 0))
        if dc.get("connected") and dc.get("ping_rtt_us"):
            rtts.append(float(dc["ping_rtt_us"]) / 1000.0)
    rows.append(
        [
            now,
            float(data.get("connections_active", 0)),
            float(data.get("unique_ips_active", 0)),
            traffic,
            (sum(rtts) / len(rtts)) if rtts else 0.0,
            float(me.get("connected_dcs", 0)),
            float(data.get("connections_rejected_total", 0)),
            float(data.get("connections_accepted_total", 0)),
        ]
    )
    rows = rows[-5000:]
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        history_save(path, rows)
    except OSError:
        pass


def spark(values, size=GRAPH_WIDTH, zero=True):
    vals = values[-size:]
    if not vals:
        return DIM + "\u043d\u0435\u0442 \u0434\u0430\u043d\u043d\u044b\u0445" + RESET
    low = 0.0 if zero else min(vals)
    high = max(vals)
    if high <= low:
        high = low + 1.0
    out = []
    last = max(1, len(vals) - 1)
    for index, value in enumerate(vals):
        ratio = (value - low) / (high - low)
        block = BLOCKS[max(0, min(7, int(ratio * 7.999)))]
        if COLOR:
            shade = 45 + int(index * 96 / last)
            out.append("\033[38;5;{}m{}".format(shade, block))
        else:
            out.append(block)
    return "".join(out) + (RESET if COLOR else "")


def graph(label, values, summary, zero=True):
    return (
        "  "
        + GRAY
        + pad(label, 14)
        + RESET
        + spark(values, GRAPH_WIDTH, zero)
        + "  "
        + DIM
        + summary
        + RESET
    )


def rate_series(points):
    rates = []
    for prev, cur in zip(points, points[1:]):
        delta_t = cur[0] - prev[0]
        if delta_t <= 0:
            continue
        rates.append(max(0.0, (cur[3] - prev[3]) / delta_t))
    return rates


def render(data, prom):
    live = os.environ.get("MTDD_LIVE") == "1"
    me = data.get("me") or {}
    dcs = me.get("dcs") or []
    out = []

    clock = time.strftime("%H:%M:%S")
    if live:
        right_plain = "\u25cf live \u00b7 2 \u0441  " + clock
        right = GREEN + "\u25cf live \u00b7 2 \u0441" + RESET + "  " + GRAY + clock + RESET
    else:
        state_plain = "ready" if data.get("ready") else "\u043d\u0435 \u0433\u043e\u0442\u043e\u0432"
        state_color = GREEN if data.get("ready") else YELLOW
        right_plain = state_plain + " \u00b7 " + clock
        right = state_color + state_plain + RESET + " \u00b7 " + GRAY + clock + RESET
    left_plain = "  \u258c \u041c\u0435\u0442\u0440\u0438\u043a\u0438"
    gap = max(1, WIDTH - width(left_plain) - width(right_plain))
    out.append(
        "\n  "
        + VIOLET
        + "\u258c"
        + RESET
        + " "
        + BOLD
        + "\u041c\u0435\u0442\u0440\u0438\u043a\u0438"
        + RESET
        + " " * gap
        + right
    )
    build = data.get("build") or {}
    out.append(
        note(
            "\u0430\u043f\u0442\u0430\u0439\u043c {} \u00b7 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439 {} (\u0432\u043a\u043b. {}) \u00b7 \u0432\u0435\u0440\u0441\u0438\u044f {} \u00b7 \u0440\u0435\u0432\u0438\u0437\u0438\u044f {}".format(
                human_duration(data.get("uptime_seconds")),
                num(data.get("users_total")),
                num(data.get("users_enabled")),
                build.get("version", "?"),
                num(data.get("revision")),
            )
        )
    )
    out.append("  " + rule())

    out.append(section("\u0421\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f"))
    out.append(
        row2(
            "\u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0435",
            num(data.get("connections_active")),
            "\u043f\u0440\u0438\u043d\u044f\u0442\u043e \u0432\u0441\u0435\u0433\u043e",
            num(data.get("connections_accepted_total")),
        )
    )
    out.append(
        row2(
            "\u043e\u0442\u043a\u043b\u043e\u043d\u0435\u043d\u043e",
            num(data.get("connections_rejected_total")),
            "\u0440\u0443\u043a\u043e\u043f\u043e\u0436\u0430\u0442\u0438\u0439",
            num(data.get("handshakes_total")),
        )
    )

    handshakes = {}
    for labels, value in prom.get("mtdd_handshakes_total", []):
        handshakes[labels.get("result", "")] = int(value)
    if handshakes:
        parts = []
        for key, label in (
            ("success", "\u0443\u0441\u043f\u0435\u0448\u043d\u043e"),
            ("failure", "\u043e\u0448\u0438\u0431\u043a\u0430"),
            ("timeout", "\u0442\u0430\u0439\u043c\u0430\u0443\u0442"),
            ("replay", "replay"),
        ):
            if key in handshakes:
                parts.append(ACCENT + num(handshakes[key]) + RESET + " " + label)
        out.append("  " + DIM + "\u0440\u0443\u043a\u043e\u043f\u043e\u0436\u0430\u0442\u0438\u044f: " + RESET + " \u00b7 ".join(parts))

    reasons = {}
    for labels, value in prom.get("mtdd_connections_rejected_total", []):
        if int(value):
            reasons[labels.get("reason", "other")] = int(value)
    if reasons:
        out.append(
            "  "
            + DIM
            + "\u043f\u0440\u0438\u0447\u0438\u043d\u044b \u043e\u0442\u043a\u0430\u0437\u0430: "
            + RESET
            + " \u00b7 ".join("{} {}".format(name, num(value)) for name, value in sorted(reasons.items()))
        )

    out.append(
        row2(
            "\u0432 \u0440\u0430\u0431\u043e\u0442\u0435",
            pnum(prom, "mtdd_handshakes_pending"),
            "replay-\u043a\u044d\u0448",
            num(data.get("replay_cache_entries")),
        )
    )
    backpressure = data.get("backpressure_events_total") or {}
    out.append(
        row2(
            "backpressure c2s",
            num(backpressure.get("c2s")),
            "s2c",
            num(backpressure.get("s2c")),
        )
    )

    out.append(section("\u0411\u0443\u0444\u0435\u0440\u044b \u0438 \u043e\u0447\u0435\u0440\u0435\u0434\u0438"))
    buffers = data.get("buffer_bytes") or {}
    out.append(
        row2(
            "relay",
            human(buffers.get("relay")),
            "pending write",
            human(buffers.get("pending_write")),
        )
    )
    out.append(
        row2(
            "queued",
            human(buffers.get("queued")),
            "ME pending",
            human(me.get("pending_buffer_bytes")),
        )
    )
    depth = sum(int(dc.get("ready_queue_depth", 0)) for dc in dcs)
    clients = sum(int(dc.get("ready_queue_clients", 0)) for dc in dcs)
    frames = sum(int(dc.get("frames_queued_bytes", 0)) for dc in dcs)
    outgoing = sum(int(dc.get("out_queued_bytes", 0)) for dc in dcs)
    out.append(
        row2(
            "ready queue",
            "{} ({})".format(num(depth), num(clients) + " \u043a\u043b."),
            "frames / out",
            "{} / {}".format(human(frames), human(outgoing)),
        )
    )
    out.append(
        row2(
            "\u0431\u044e\u0434\u0436\u0435\u0442 \u0431\u0443\u0444\u0435\u0440\u043e\u0432",
            human(prom_scalar(prom, "mtdd_buffer_budget_bytes")),
            "\u043f\u0443\u043b \u043a\u043b\u0438\u0435\u043d\u0442\u043e\u0432",
            pnum(prom, "mtdd_client_pool_objects"),
        )
    )

    out.append(section("ME / DC"))
    visible = [dc for dc in dcs if dc.get("connected") or dc.get("connections") or dc.get("pool_target")]
    if not visible:
        visible = dcs

    def dc_order(dc):
        label = str(dc.get("dc", "other"))
        try:
            return (0, int(label))
        except ValueError:
            return (1, 0)

    visible.sort(key=dc_order)
    if dcs:
        out.append(
            "  "
            + GRAY
            + cell("DC", 6)
            + cell("\u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435", 11)
            + cell("ready/conn", 12)
            + cell("target", 8)
            + cell("\u043a\u043b\u0438\u0435\u043d\u0442\u044b", 9)
            + cell("RTT", 9)
            + cell("\u043e\u0447\u0435\u0440\u0435\u0434\u044c", 10)
            + "\u0442\u0440\u0430\u0444\u0438\u043a"
            + RESET
        )
        for dc in visible:
            up = bool(dc.get("connected"))
            state = (
                GREEN + cell("\u25cf up", 11) + RESET
                if up
                else RED + cell("\u25cb down", 11) + RESET
            )
            rtt = float(dc.get("ping_rtt_us", 0)) / 1000.0
            if up and rtt > 0:
                rtt_text = "{:.0f} ms".format(rtt)
                rtt_color = GREEN if rtt < 80 else (YELLOW if rtt < 150 else RED)
            else:
                rtt_text = "\u2014"
                rtt_color = ""
            queue = "{}/{}".format(
                num(dc.get("ready_queue_depth", 0)), num(dc.get("ready_queue_clients", 0))
            )
            traffic = human(
                float(dc.get("rx_bytes_total", 0)) + float(dc.get("tx_bytes_total", 0))
            )
            out.append(
                "  "
                + GRAY
                + cell(str(dc.get("dc", "?")), 6)
                + RESET
                + state
                + cell(
                    "{}/{}".format(
                        num(dc.get("ready_connections", 0)), num(dc.get("connections", 0))
                    ),
                    12,
                )
                + cell(num(dc.get("pool_target", 0)), 8)
                + cell(num(dc.get("bound_clients", 0)), 9)
                + cell(rtt_text, 9, rtt_color)
                + cell(queue, 10)
                + traffic
            )
        connected = sum(1 for dc in dcs if dc.get("connected"))
        out.append(
            note(
                "DC \u0432 \u0441\u0435\u0442\u0438: {} \u0438\u0437 {} \u00b7 \u0437\u0430\u043f\u0440\u043e\u0441\u043e\u0432 ME {} \u00b7 \u043f\u0435\u0440\u0435\u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0439 {} \u00b7 \u043e\u0448\u0438\u0431\u043e\u043a \u0441\u043e\u0437\u0434\u0430\u043d\u0438\u044f {}".format(
                    connected,
                    len(dcs),
                    num(me.get("requests_total")),
                    num(me.get("reconnects_total")),
                    num(sum(int(dc.get("creation_failures_total", 0)) for dc in dcs)),
                )
            )
        )
        answers = sum(int(dc.get("proxy_ans_received_total", 0)) for dc in dcs)
        if answers:
            delivered = sum(int(dc.get("proxy_ans_delivered_total", 0)) for dc in dcs)
            dropped = sum(
                int(dc.get("proxy_ans_dropped_unknown_total", 0))
                + int(dc.get("proxy_ans_dropped_other_total", 0))
                for dc in dcs
            )
            age = max((int(dc.get("last_proxy_ans_age_seconds", 0)) for dc in dcs), default=0)
            out.append(
                note(
                    "proxy-answer: \u043f\u043e\u043b\u0443\u0447\u0435\u043d\u043e {} \u00b7 \u0434\u043e\u0441\u0442\u0430\u0432\u043b\u0435\u043d\u043e {} \u00b7 \u043f\u043e\u0442\u0435\u0440\u044f\u043d\u043e {} \u00b7 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0439 \u043e\u0442\u0432\u0435\u0442 {} \u043d\u0430\u0437\u0430\u0434".format(
                        num(answers), num(delivered), num(dropped), human_duration(age)
                    )
                )
            )
    else:
        out.append(note("\u043d\u0435\u0442 \u0434\u0430\u043d\u043d\u044b\u0445: ME \u0435\u0449\u0451 \u043d\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0430\u043b\u0441\u044f"))

    out.append(section("\u0422\u0440\u0430\u0444\u0438\u043a"))
    rx = sum(float(dc.get("rx_bytes_total", 0)) for dc in dcs)
    tx = sum(float(dc.get("tx_bytes_total", 0)) for dc in dcs)
    out.append(row2("\u043f\u0440\u0438\u043d\u044f\u0442\u043e", human(rx), "\u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u043e", human(tx)))
    direct_active = sum(int(dc.get("direct_active", 0)) for dc in dcs)
    direct_accepted = sum(int(dc.get("direct_accepted_total", 0)) for dc in dcs)
    if direct_active or direct_accepted:
        out.append(
            note(
                "\u043f\u0440\u044f\u043c\u044b\u0435 DC: {} \u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0445 \u00b7 {} \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e \u00b7 {} \u043e\u0448\u0438\u0431\u043e\u043a \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f".format(
                    num(direct_active),
                    num(direct_accepted),
                    num(sum(int(dc.get("direct_connect_fail_total", 0)) for dc in dcs)),
                )
            )
        )

    out.append(section("\u0423\u043d\u0438\u043a\u0430\u043b\u044c\u043d\u044b\u0435 IP"))
    history = data.get("unique_ip_history") or {}
    hour = (history.get("hour") or {}).get("estimate", 0)
    day = (history.get("day") or {}).get("estimate", 0)
    week = (history.get("week") or {}).get("estimate", 0)
    out.append(
        row2(
            "\u0441\u0435\u0439\u0447\u0430\u0441",
            num(data.get("unique_ips_active")),
            "\u0447\u0430\u0441",
            "\u2248 " + num(hour),
        )
    )
    out.append(row2("\u0434\u0435\u043d\u044c", "\u2248 " + num(day), "\u043d\u0435\u0434\u0435\u043b\u044f", "\u2248 " + num(week)))
    period = ""
    started = (history.get("hour") or {}).get("started_at")
    if started:
        period = " \u00b7 \u0442\u0435\u043a\u0443\u0449\u0438\u0439 \u0447\u0430\u0441 \u0441 " + time.strftime(
            "%H:%M UTC", time.gmtime(started)
        )
    out.append(
        note(
            "\u043e\u0446\u0435\u043d\u043a\u0430 HyperLogLog, \u043e\u0448\u0438\u0431\u043a\u0430 \u00b1{:.1f}%{}".format(
                100.0 * float(history.get("relative_standard_error", 0.0325)), period
            )
        )
    )

    rows = history_load(history_path())
    if len(rows) < 2:
        out.append(section("\u0414\u0438\u043d\u0430\u043c\u0438\u043a\u0430"))
        out.append(
            note(
                "\u0438\u0441\u0442\u043e\u0440\u0438\u044f \u043a\u043e\u043f\u0438\u0442\u0441\u044f: \u0442\u043e\u0447\u043a\u0430 \u0434\u043e\u0431\u0430\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u043f\u0440\u0438 status/metrics (\u043d\u0435 \u0447\u0430\u0449\u0435 \u0440\u0430\u0437\u0430 \u0432 25 \u0441)"
            )
        )
        out.append(note("\u0436\u0438\u0432\u043e\u0439 \u0440\u0435\u0436\u0438\u043c \u0441 \u0433\u0440\u0430\u0444\u0438\u043a\u0430\u043c\u0438: sudo mtdd-ctl metrics --watch"))
    else:
        points = rows[-90:]
        span = points[-1][0] - points[0][0]
        out.append(
            section(
                "\u0414\u0438\u043d\u0430\u043c\u0438\u043a\u0430 \u00b7 {} {} \u0437\u0430 {}".format(
                    num(len(points)),
                    plural(len(points), "\u0442\u043e\u0447\u043a\u0430", "\u0442\u043e\u0447\u043a\u0438", "\u0442\u043e\u0447\u0435\u043a"),
                    human_duration(span),
                )
            )
        )
        active = [row[1] for row in points]
        ips = [row[2] for row in points]
        rtts = [row[4] for row in points if row[4] > 0]
        out.append(
            graph(
                "\u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0435",
                active,
                "{} \u2192 {} \u00b7 max {}".format(num(active[0]), num(active[-1]), num(max(active))),
            )
        )
        out.append(
            graph(
                "\u0443\u043d\u0438\u043a\u0430\u043b\u044c\u043d\u044b\u0435 IP",
                ips,
                "{} \u2192 {} \u00b7 max {}".format(num(ips[0]), num(ips[-1]), num(max(ips))),
            )
        )
        rates = rate_series(points)
        if rates:
            out.append(
                graph(
                    "\u0442\u0440\u0430\u0444\u0438\u043a/\u0441",
                    rates,
                    "\u043f\u0438\u043a {}/s".format(human(max(rates))),
                )
            )
        if rtts:
            out.append(
                graph(
                    "ME RTT",
                    rtts,
                    "{:.0f} ms \u00b7 {:.0f}\u2013{:.0f}".format(rtts[-1], min(rtts), max(rtts)),
                    zero=False,
                )
            )
        out.append(
            note(
                "q \u2014 \u0432\u044b\u0445\u043e\u0434 \u0438\u0437 \u0436\u0438\u0432\u043e\u0433\u043e \u0440\u0435\u0436\u0438\u043c\u0430"
                if live
                else "\u0442\u043e\u0447\u043a\u0430 \u043a\u0430\u0436\u0434\u044b\u0435 ~25 \u0441 \u00b7 \u0436\u0438\u0432\u043e\u0439 \u0440\u0435\u0436\u0438\u043c: sudo mtdd-ctl metrics --watch"
            )
        )

    return "\n".join(out)


def main():
    path = os.environ.get("MTDD_JSON", "")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh).get("data", {})
    except (OSError, ValueError):
        print("  \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0440\u0430\u0437\u043e\u0431\u0440\u0430\u0442\u044c \u043e\u0442\u0432\u0435\u0442 API")
        return 1

    if os.environ.get("MTDD_RECORD_ONLY") == "1":
        sample(data, force=os.environ.get("MTDD_METRICS_FORCE") == "1")
        return 0

    sample(data, force=os.environ.get("MTDD_METRICS_FORCE") == "1")
    prom = load_prom(os.environ.get("MTDD_METRICS_TXT", ""))
    print(render(data, prom))
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
}

metrics_render() { # metrics_render JSON-ФАЙЛ [ФАЙЛ-МЕТРИК] — печатает дашборд
    local json=$1 txt=${2-} script rc=0
    script=$(mktemp) || return 1
    if ! metrics_python >"$script"; then
        rm -f -- "$script"
        err 'Не удалось подготовить рендер метрик'
        return 1
    fi
    MTDD_JSON=$json MTDD_METRICS_TXT=$txt MTDD_COLOR=$ui_color \
    MTDD_C_RESET=$reset MTDD_C_BOLD=$bold MTDD_C_DIM=$dim MTDD_C_GRAY=$gray \
    MTDD_C_ACCENT=$accent MTDD_C_VIOLET=$violet MTDD_C_GREEN=$green \
    MTDD_C_YELLOW=$yellow MTDD_C_RED=$red \
        python3 "$script" || rc=$?
    rm -f -- "$script"
    return $rc
}

metrics_record() { # metrics_record JSON — добавить точку в историю метрик
    local json=${1-} script data
    [[ -n $json && -d $MTDD_STATE ]] || return 0
    script=$(mktemp) || return 0
    data=$(mktemp) || { rm -f -- "$script"; return 0; }
    if metrics_python >"$script" 2>/dev/null; then
        printf '%s' "$json" >"$data"
        MTDD_JSON=$data MTDD_RECORD_ONLY=1 MTDD_HISTORY_FILE=$MTDD_METRICS_HISTORY \
            python3 "$script" >/dev/null 2>&1 || true
    fi
    rm -f -- "$script" "$data"
    return 0
}

metrics_watch_loop() { # metrics_watch_loop РАБОЧАЯ-ПАПКА — живой дашборд до q
    local work=$1 key
    while :; do
        if ((ui_color)); then printf '\033[H\033[2J'; fi
        api GET /v1/status 2>/dev/null >"$work/status.json" || true
        api GET /metrics 2>/dev/null >"$work/metrics.txt" || true
        if [[ -s $work/status.json ]]; then
            MTDD_LIVE=1 MTDD_METRICS_FORCE=1 MTDD_HISTORY_FILE=$work/live.tsv \
                metrics_render "$work/status.json" "$work/metrics.txt" || true
        else
            warn "API ($(api_endpoint)) не отвечает — повторяю…"
        fi
        if read -rsn1 -t 2 key </dev/tty; then
            case $key in q|Q) break ;; esac
        fi
    done
}

cmd_metrics() {
    local filter= watch=0 arg work rc=0
    for arg in "$@"; do
        case $arg in
            --watch|-w) watch=1 ;;
            --all) filter=all ;;
            '') ;;
            *) filter=$arg ;;
        esac
    done
    if [[ $filter == all ]]; then
        api GET /metrics 2>/dev/null || { err 'Не удалось получить метрики'; return 1; }
        return 0
    fi
    if [[ -n $filter ]]; then
        local out lines
        out=$(api GET /metrics 2>/dev/null) || { err 'Не удалось получить метрики'; return 1; }
        lines=$(printf '%s\n' "$out" | grep -E '^mtdd_' | grep -F -- "$filter" || true)
        [[ -n $lines ]] || { warn 'Метрики mtdd_ не найдены'; return 0; }
        printf '%s\n' "$lines"
        return 0
    fi
    work=$(mktemp -d) || { err 'Не удалось создать временный каталог'; return 1; }
    if ! api GET /v1/status 2>/dev/null >"$work/status.json" || [[ ! -s $work/status.json ]]; then
        rm -rf -- "$work"
        err "API ($(api_endpoint)) не отвечает; метрики недоступны"
        return 1
    fi
    api GET /metrics 2>/dev/null >"$work/metrics.txt" || true
    if ((watch)) && has_tty; then
        metrics_watch_loop "$work"
        rm -rf -- "$work"
        return 0
    fi
    MTDD_HISTORY_FILE=$MTDD_METRICS_HISTORY \
        metrics_render "$work/status.json" "$work/metrics.txt" || rc=$?
    rm -rf -- "$work"
    return $rc
}

cmd_host() {
    ((${#cargs[@]} >= 1)) || { err 'Использование: install.sh host АДРЕС [ПОРТ]'; return 1; }
    local host=$1 port=${2-} candidate
    valid_public_host "$host" || { err 'Неверный публичный адрес; укажите IP или DNS-имя'; return 1; }
    if [[ -n $port ]]; then
        valid_port "$port" || { err 'Порт должен быть в диапазоне 1–65535'; return 1; }
    fi
    candidate=$(mktemp /etc/mtdd/.config.XXXXXXXX)
    MTDD_NEW_HOST=$host MTDD_NEW_PORT=$port python3 - "$candidate" <<'PY' || { rm -f -- "$candidate"; err 'Не удалось обновить конфигурацию'; return 1; }
import json, os, sys
from pathlib import Path
config = json.loads(Path('/etc/mtdd/config.json').read_text())
config['public_host'] = os.environ['MTDD_NEW_HOST']
if os.environ['MTDD_NEW_PORT']:
    config['public_port'] = int(os.environ['MTDD_NEW_PORT'])
Path(sys.argv[1]).write_text(json.dumps(config, indent=2) + '\n')
PY
    chown root:mtdd "$candidate"
    chmod 0640 "$candidate"
    mv -f -- "$candidate" "$MTDD_CONF"
    ok "Публичный адрес: $host${port:+:$port}"
    if ! "$MTDD_BIN" --config "$MTDD_CONF" --check-config >/dev/null; then
        err 'Проверка конфигурации не пройдена'
        return 1
    fi
    systemctl restart "$MTDD_SERVICE" || { err 'Не удалось перезапустить службу'; return 1; }
    ok 'Служба перезапущена; новые ссылки:'
    cargs=()
    cmd_links
}

cmd_check_config() {
    [[ -x $MTDD_BIN ]] || { err "Бинарник не найден: $MTDD_BIN"; return 1; }
    "$MTDD_BIN" --config "$MTDD_CONF" --check-config \
        && ok 'Конфигурация корректна'
}

cmd_uninstall() {
    local force=${1-}
    if [[ ! -e $MTDD_UNIT && ! -e $MTDD_BIN && ! -e $MTDD_CONF ]]; then
        err 'Установка mtdd не найдена'
        return 1
    fi
    if [[ $force != --yes && $yes_flag != 1 ]]; then
        section 'mtdd · удаление'
        warn 'Будут остановлены служба и удалены бинарники.'
        confirm 'Продолжить удаление службы и бинарников?' \
            || { warn 'Удаление отменено'; return 1; }
    fi
    systemctl disable --now "$MTDD_SERVICE" 2>/dev/null || warn 'Служба уже неактивна или отсутствует'
    rm -f -- "$MTDD_UNIT"
    # Stopping the tuning unit restores exactly the interface values it set.
    systemctl disable --now "$MTDD_NETTUNE_SERVICE" 2>/dev/null || true
    rm -f -- "$MTDD_NETTUNE_UNIT" "$MTDD_NETTUNE"
    systemctl daemon-reload 2>/dev/null || true
    rm -f -- "$MTDD_BIN" "$MTDD_CTL"
    ok 'Служба, бинарник и менеджер mtdd-ctl удалены'
    local remove_state=0
    if [[ $force == --yes || $yes_flag == 1 ]]; then
        remove_state=1
    elif confirm 'Удалить конфигурацию, токен и пользователей (/etc/mtdd, /var/lib/mtdd)?'; then
        remove_state=1
    fi
    if ((remove_state)); then
        rm -rf -- /etc/mtdd "$MTDD_STATE"
        getent passwd mtdd >/dev/null 2>&1 && userdel mtdd 2>/dev/null || true
        ok 'Конфигурация, токен и пользователи удалены'
    else
        warn "Сохранено: $MTDD_CONF, $MTDD_CREDS, $MTDD_STATE"
        warn 'Повторная установка подхватит сохранённые данные; для полной очистки удалите их вручную.'
    fi
    ok 'mtdd удалён с сервера'
}

# ---------------------------------------------------------------------------
# Меню управления
# ---------------------------------------------------------------------------
menu_read() { # menu_read ПЕРЕМЕННАЯ ПРИГЛАШЕНИЕ
    local answer
    printf '%s' "$2" >/dev/tty
    IFS= read -r answer </dev/tty || return 1
    printf -v "$1" '%s' "$answer"
}

menu_pause() {
    menu_read _ '  Нажмите Enter, чтобы продолжить… ' || true
}

menu_run() { # menu_run КОМАНДА [АРГУМЕНТЫ…] — не даёт set -e уронить меню
    printf '\n'
    set +e
    "$@"
    local rc=$?
    set -e
    ((rc == 0)) || warn "Команда завершилась с ошибкой (код $rc)"
    return 0
}

menu_users() {
    local choice name
    while :; do
        menu_frame 'Пользователи' ''
        menu_row 1 'Список' 4 'Отключить'
        menu_row 2 'Добавить' 5 'Удалить'
        menu_row 3 'Включить' 6 'Новый секрет'
        menu_row 0 'Назад'
        menu_footer
        menu_read choice '  › ' || return 0
        case $choice in
            1)
                menu_run cmd_users_list
                menu_pause ;;
            2)
                menu_read name '  › Имя нового пользователя: ' || return 0
                [[ -n $name ]] && menu_run cmd_users_add "$name"
                menu_pause ;;
            3)
                menu_read name '  › Имя пользователя: ' || return 0
                [[ -n $name ]] && menu_run cmd_users_set_enabled "$name" true 'включён'
                menu_pause ;;
            4)
                menu_read name '  › Имя пользователя: ' || return 0
                [[ -n $name ]] && menu_run cmd_users_set_enabled "$name" false 'отключён'
                menu_pause ;;
            5)
                menu_read name '  › Имя пользователя: ' || return 0
                if [[ -n $name ]] && confirm "Удалить пользователя $name? Ссылка перестанет работать"; then
                    menu_run cmd_users_remove "$name" --yes
                fi
                menu_pause ;;
            6)
                menu_read name '  › Имя пользователя: ' || return 0
                [[ -n $name ]] && menu_run cmd_users_rotate "$name"
                menu_pause ;;
            0|q|Q) return 0 ;;
            *) : ;;
        esac
    done
}

run_installer_channel() { # обновление бинарника из меню в изолированном подпроцессе
    local choice
    printf '  Каналы: 1) main — основной  2) dev — тестовый\n' >/dev/tty
    menu_read choice '  → Канал [main]: ' || return 0
    case $choice in
        2|dev) channel=dev ;;
        *) channel=main ;;
    esac
    channel_set=1
    printf '\n'
    set +e
    (run_install)
    local rc=$?
    set -e
    ((rc == 0)) || warn "Обновление завершилось с ошибкой (код $rc)"
    return 0
}

menu_frame() { # menu_frame ЗАГОЛОВОК [МЕТКА СПРАВА]
    printf '\n  %s▌%s %s' "$violet" "$reset" "$bold" >/dev/tty
    pad "${1-}" 40 >/dev/tty
    printf '%s%s\n  ' "$reset" "${2-}" >/dev/tty
    hr >/dev/tty
}
menu_row() { # menu_row НОМЕР ПУНКТ [НОМЕР ПУНКТ]
    printf '  %s%s%s  ' "$accent" "$1" "$reset" >/dev/tty
    pad "$2" 26 >/dev/tty
    if [[ -n ${3-} ]]; then
        printf '%s%s%s  %s\n' "$accent" "$3" "$reset" "$4" >/dev/tty
    else
        printf '\n' >/dev/tty
    fi
}
menu_footer() { printf '  ' >/dev/tty; hr >/dev/tty; }

cmd_menu() {
    mg_require_root || return 1
    mg_require_install || return 1
    mg_require_tools || return 1
    has_tty || die 'Меню требует терминала; используйте подкоманды (справка: --help)'
    local choice host port
    while :; do
        if ((ui_color)); then printf '\033[H\033[2J' >/dev/tty; fi
        banner 'управление прокси · MTProto / FakeTLS' >/dev/tty
        menu_frame 'Разделы' "$(service_badge)"
        menu_row 1 'Статус' 6 'Метрики · графики'
        menu_row 2 'Пользователи' 7 'Обновить бинарник'
        menu_row 3 'Ссылки' 8 'Публичный адрес'
        menu_row 4 'Журнал' 9 'Проверить конфигурацию'
        menu_row 5 'Перезапуск службы' 0 'Выход'
        menu_footer
        printf '  %sРаздел — цифра · q — выход%s\n\n' "$dim" "$reset" >/dev/tty
        menu_read choice '  › ' || break
        case $choice in
            1)
                menu_run cmd_status
                menu_pause ;;
            2) menu_users ;;
            3)
                menu_run cmd_links
                menu_pause ;;
            4)
                menu_run cmd_logs 50
                menu_pause ;;
            5)
                menu_run cmd_service restart
                menu_pause ;;
            6)
                menu_run cmd_metrics
                menu_pause ;;
            7)
                step 'Обновление скачает бинарник выбранного канала и перезапустит службу.'
                run_installer_channel
                break ;;
            8)
                menu_read host '  › Публичный IP или DNS: ' || break
                menu_read port '  › Публичный порт (Enter — не менять): ' || break
                if [[ -n $host ]]; then
                    menu_run cmd_host "$host" "$port"
                fi
                menu_pause ;;
            9)
                menu_run cmd_check_config
                menu_pause ;;
            0|q|Q) break ;;
            *) : ;;
        esac
    done
    printf '\n'
    ok 'Готово'
}

# ---------------------------------------------------------------------------
# Режим установки и обновления
# ---------------------------------------------------------------------------
init_base_url() {
    if [[ -z $base_url ]]; then base_url="https://github.com/$repo/releases/download"; fi
    case $base_url in
        https://*) ;;
        http://127.0.0.1:*|http://localhost:*) ;;
        *) die 'Зеркало должно использовать HTTPS (HTTP разрешён только для localhost)' ;;
    esac
    base_url=${base_url%/}
}

launcher_installed=0
src_desc=${BASH_SOURCE[0]:-}
if [[ -z $src_desc || $src_desc == /dev/stdin || $src_desc == /dev/fd/* || ! -f $src_desc ]]; then
    src_desc='install.sh'
fi

print_links_from_files() {
    python3 - <<'PY'
import json
from pathlib import Path
from urllib.parse import urlencode
config = json.loads(Path('/etc/mtdd/config.json').read_text())
users_path = Path(config['users_path'])
if not users_path.is_absolute():
    users_path = Path('/etc/mtdd') / users_path
users = json.loads(users_path.read_text())['users']
for user in users:
    query = urlencode({'server': config['public_host'],
                       'port': config.get('public_port', config['proxy_port']),
                       'secret': 'ee' + user['secret'] + config['tls_domain'].encode('ascii').hex()})
    print(f"  {user['name']}{' (disabled)' if not user['enabled'] else ''}: https://t.me/proxy?{query}")
PY
}

install_launcher_copy() {
    local src=${BASH_SOURCE[0]:-}
    if [[ -z $src || $src == /dev/stdin || $src == /dev/fd/* || ! -f $src ]]; then
        # Pipe mode: the script is a stream, so fetch the canonical installer
        # for the same repository and install that copy as the manager.
        local self_url="https://raw.githubusercontent.com/$repo/main/install.sh"
        local self_copy="$work/mtdd-ctl.src"
        if curl -fsSL --retry 3 --connect-timeout 20 -o "$self_copy" "$self_url" \
            && [[ -s $self_copy ]] && grep -q '^#!/usr/bin/env bash' "$self_copy"; then
            src="$self_copy"
            ok 'Копия установщика получена из репозитория'
        else
            warn 'Не удалось получить установщик для mtdd-ctl; управляйте этим же скриптом'
            warn 'Скачайте install.sh на сервер и запустите его из файла'
            return 0
        fi
    fi
    if [[ $src -ef $MTDD_CTL ]]; then
        launcher_installed=1
        ok "Менеджер управления уже установлен: sudo mtdd-ctl"
        return 0
    fi
    if install -m 0755 "$src" "$MTDD_CTL"; then
        launcher_installed=1
        ok "Менеджер управления: sudo mtdd-ctl ($MTDD_CTL)"
    else
        warn 'Не удалось установить mtdd-ctl; управление доступно через этот же скрипт'
    fi
}

download_and_stage() {
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    asset=mtdd-linux-x86_64
    url="$base_url/channel-$channel"
    step "Скачиваю бинарник и контрольную сумму канала $channel…"
    spin --quiet 'Скачивание бинарника' \
        curl -fsSL --retry 3 --connect-timeout 20 "$url/$asset" -o "$work/$asset" \
        || die 'Не удалось скачать бинарник; проверьте доступность release-канала'
    spin --quiet 'Скачивание контрольных сумм' \
        curl -fsSL --retry 3 --connect-timeout 20 "$url/SHA256SUMS" -o "$work/SHA256SUMS" \
        || die 'Не удалось скачать контрольные суммы'
    step 'Проверяю SHA-256 скачанного бинарника…'
    digest=$(awk -v name="$asset" '$2 == name {print $1; count++} END {if (count != 1) exit 1}' "$work/SHA256SUMS") || die 'Некорректный файл контрольных сумм'
    [[ $digest =~ ^[[:xdigit:]]{64}$ ]] || die 'Некорректная контрольная сумма SHA-256'
    printf '%s  %s\n' "$digest" "$work/$asset" | sha256sum -c - >/dev/null || die 'Контрольная сумма бинарника не совпадает'
    target_dir=$(dirname -- "$output")
    [[ -d $target_dir ]] || die "Каталог назначения не существует: $target_dir"
    staged=$(mktemp "$target_dir/.mtdd.XXXXXXXX")
    trap 'rm -rf -- "$work"; rm -f -- "$staged"' EXIT
    install -m 0755 "$work/$asset" "$staged"
}

run_install() {
    init_base_url
    banner 'установка прокси · MTProto / FakeTLS'
    ((EUID == 0)) || die 'Для установки службы нужны права root: запустите через sudo'
    [[ $output == /usr/local/bin/mtdd ]] || die '--output доступен только вместе с --binary-only'
    for cmd in python3 systemctl useradd getent; do need "$cmd"; done
    [[ -d /run/systemd/system ]] || die 'Для установки службы требуется systemd'
    if [[ -e $MTDD_CONF || -e $MTDD_CREDS ]]; then
        [[ -f $MTDD_CONF && -f $MTDD_CREDS ]] ||
            die 'Предыдущая установка неполная; сохраните и проверьте /etc/mtdd перед повтором'
        fresh=0
    else
        fresh=1
        needs_dialog=0
        if [[ -z $domain || -z $ad_tag ]]; then needs_dialog=1; fi
        [[ ! -e $MTDD_STATE/users.json ]] || die 'Найдены существующие пользователи; перезапись запрещена'
        section 'Настройка прокси'
        step 'FakeTLS-домен — маскировка, а не адрес вашего сервера.'
        if ((needs_dialog)); then
            has_tty || die 'Для новой установки укажите --domain и --ad-tag (либо запустите установщик в терминале)'
            if ((!channel_set)); then
                printf '  Каналы: main — основной, dev — тестовый\n\n' >/dev/tty
                prompt channel 'Канал сборки (main/dev)' "$channel"
                [[ $channel == main || $channel == dev ]] || die 'Для --branch укажите main или dev'
            fi
            [[ -n $domain ]] || prompt domain 'Домен FakeTLS'
            [[ -n $ad_tag ]] || prompt ad_tag 'Рекламный тег Telegram (32 hex)'
            ((!port_set)) && prompt proxy_port 'TCP-порт прокси' "$proxy_port"
            ((!user_set)) && prompt user_name 'Имя первого пользователя' "$user_name"
        fi
        [[ -n $domain ]] || die 'Укажите домен FakeTLS через --domain'
        [[ -n $ad_tag ]] || die 'Укажите рекламный тег через --ad-tag'
    fi
    if ((fresh)); then
        [[ $ad_tag =~ ^[[:xdigit:]]{32}$ && $ad_tag != 00000000000000000000000000000000 ]] || die 'Тег должен содержать 32 hex-символа и не состоять из нулей'
        valid_port "$proxy_port" || die 'Порт прокси должен быть в диапазоне 1–65535'
        [[ $user_name =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die 'Имя пользователя: 1–32 символа A–Z, a–z, 0–9, _ или -'
        valid_dns_name "$domain" || die 'Неверное DNS-имя FakeTLS'
    fi
    if ((!fresh)) && [[ -z $public_host ]]; then
        public_host=$(python3 -c "import json; print(json.load(open('$MTDD_CONF')).get('public_host', ''))") || die 'Не удалось прочитать существующую конфигурацию'
    fi
    if [[ -z $public_host ]]; then
        step 'Определяю внешний IPv4-адрес…'
        public_host=$(curl -4fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)
        if ! valid_public_host "$public_host"; then public_host=; fi
        if [[ -z $public_host ]]; then
            if has_tty; then
                prompt public_host 'Публичный IP или DNS сервера'
            else
                die 'Не удалось определить публичный IP; укажите --public-host'
            fi
        fi
    fi
    valid_public_host "$public_host" || die 'Неверный публичный адрес; укажите IP или DNS-имя'
    if [[ -n $public_port ]]; then
        valid_port "$public_port" || die 'Публичный порт должен быть в диапазоне 1–65535'
    fi
    section 'Параметры установки'
    if ((fresh)); then
        step "Режим: новая установка · канал: $channel"
        step "FakeTLS: $domain · локальный порт: $proxy_port · пользователь: $user_name"
        step 'Маскировка проб: автоматический релей по SNI на реальный сайт'
    else
        step "Режим: обновление · канал: $channel · пользователи и токен сохраняются"
    fi
    step "Публичный адрес для ссылок: $public_host${public_port:+:$public_port}"

    download_and_stage

    if ! getent passwd mtdd >/dev/null; then
        useradd --system --user-group --home-dir "$MTDD_STATE" --shell /usr/sbin/nologin mtdd
    fi
    step 'Создаю конфигурацию и проверяю её…'
    install -d -m 0750 -o root -g mtdd /etc/mtdd
    install -d -m 0700 -o mtdd -g mtdd "$MTDD_STATE"
    if ((fresh)); then
        MTDD_INSTALL_DOMAIN=$domain MTDD_INSTALL_TAG=$ad_tag MTDD_INSTALL_PORT=$proxy_port \
        MTDD_INSTALL_USER=$user_name MTDD_PUBLIC_HOST=$public_host MTDD_PUBLIC_PORT=$public_port python3 - <<'PY'
import json
import os
import secrets
from pathlib import Path

config = {"proxy_host": "0.0.0.0", "proxy_port": int(os.environ["MTDD_INSTALL_PORT"]),
          "control_host": "127.0.0.1", "control_port": 9090,
          "api_token_env": "MTDD_API_TOKEN", "tls_domain": os.environ["MTDD_INSTALL_DOMAIN"],
          "ad_tag": os.environ["MTDD_INSTALL_TAG"], "users_path": "/var/lib/mtdd/users.json"}
config["public_host"] = os.environ["MTDD_PUBLIC_HOST"]
if os.environ["MTDD_PUBLIC_PORT"]:
    config["public_port"] = int(os.environ["MTDD_PUBLIC_PORT"])
users = {"version": 1, "revision": 1, "users": [{"name": os.environ["MTDD_INSTALL_USER"],
         "secret": secrets.token_hex(16), "enabled": True, "max_connections": None, "generation": 1}]}
Path('/etc/mtdd/config.json').write_text(json.dumps(config, indent=2) + '\n')
Path('/etc/mtdd/credentials.env').write_text('MTDD_API_TOKEN=' + secrets.token_hex(32) + '\n')
Path('/var/lib/mtdd/users.json').write_text(json.dumps(users, indent=2) + '\n')
PY
        chown root:mtdd /etc/mtdd/config.json
        chmod 0640 /etc/mtdd/config.json
        chown root:root /etc/mtdd/credentials.env
        chmod 0600 /etc/mtdd/credentials.env
        chown mtdd:mtdd "$MTDD_STATE/users.json"
        chmod 0600 "$MTDD_STATE/users.json"
    fi
    config_candidate=$(mktemp /etc/mtdd/.config.XXXXXXXX)
    trap 'rm -rf -- "$work"; rm -f -- "$staged" "$config_candidate"' EXIT
    MTDD_PUBLIC_HOST=$public_host MTDD_PUBLIC_PORT=$public_port python3 - "$config_candidate" <<'PY'
import json, os, sys
from pathlib import Path
config = json.loads(Path('/etc/mtdd/config.json').read_text())
config['public_host'] = os.environ['MTDD_PUBLIC_HOST']
if os.environ['MTDD_PUBLIC_PORT']:
    config['public_port'] = int(os.environ['MTDD_PUBLIC_PORT'])
# Capacity defaults for thousands of concurrent clients. Only missing keys are
# filled, so an operator's explicit values survive every update. The relay
# buffer budget scales with RAM (a quarter, 64 MiB..1 GiB): the old 64 MiB
# default is split over the reactors and runs out at a few thousand clients,
# which pauses the shared ME reads and stalls everyone.
try:
    ram = next(int(l.split()[1]) * 1024 for l in open('/proc/meminfo') if l.startswith('MemTotal:'))
except (OSError, StopIteration, ValueError):
    ram = 0
if ram:
    config.setdefault('global_buffer_bytes', max(64 << 20, min(ram // 4, 1 << 30)))
config.setdefault('me_connections_per_dc', 16)
Path(sys.argv[1]).write_text(json.dumps(config, indent=2) + '\n')
PY
    "$staged" --config "$config_candidate" --check-config >/dev/null || die 'Проверка конфигурации не пройдена'
    chown root:mtdd "$config_candidate"
    chmod 0640 "$config_candidate"
    mv -f -- "$config_candidate" "$MTDD_CONF"
    mv -f -- "$staged" "$output"
    tune_kernel
    tune_network
    install -d -m 0755 /etc/systemd/system
    install -m 0644 /dev/stdin "$MTDD_UNIT" <<'EOF'
[Unit]
Description=mtdd MTProto proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mtdd
Group=mtdd
EnvironmentFile=/etc/mtdd/credentials.env
ExecStart=/usr/local/bin/mtdd --config /etc/mtdd/config.json
# systemctl reload mtdd: re-read me_clients_per_writer/me_connections_per_dc
# without dropping clients (other settings still need a restart).
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/mtdd

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    step 'Запускаю службу systemd…'
    systemctl enable --now "$MTDD_SERVICE"
    if ((!fresh)); then systemctl restart "$MTDD_SERVICE"; fi
    install_launcher_copy
    section 'Готово · ссылки для Telegram'
    ok "Бинарник: $channel · служба: mtdd"
    warn 'Ссылки содержат секреты. Передавайте их только своим пользователям.'
    printf '\n'
    print_links_from_files
    printf '\n'
    if ((launcher_installed)); then
        step 'Управление: sudo mtdd-ctl (меню)'
    else
        step 'Управление: sudo bash '"$src_desc"' (то же меню, что и mtdd-ctl)'
    fi
    step 'Состояние:  sudo systemctl status mtdd'
    step 'Журнал:     sudo journalctl -u mtdd -f'
    step 'Настройки:  /etc/mtdd/config.json'
    step 'API-токен:  /etc/mtdd/credentials.env (только root)'
    warn 'Откройте публичный TCP-порт в firewall и настройте NAT при необходимости.'
    line
}

# Ядро по умолчанию рассчитано на сотни соединений: очередь приёма, число
# orphan-сокетов и лимит памяти TCP быстро упираются в потолок при тысячах
# клиентов (ListenOverflows, «too many orphaned sockets», обрывы рукопожатий).
# Значения только повышаются: если оператор уже задал больше, оно сохраняется.
tune_kernel() {
    local conf=/etc/sysctl.d/99-mtdd-load.conf
    step 'Настраиваю параметры ядра для большого числа клиентов…'
    install -d -m 0755 /etc/sysctl.d
    if ! python3 - "$conf" <<'PY'
import os, sys
from pathlib import Path

def read(key):
    try:
        return Path('/proc/sys/' + key.replace('.', '/')).read_text().split()
    except OSError:
        return None

try:
    pages = next(int(l.split()[1]) // 4 for l in open('/proc/meminfo') if l.startswith('MemTotal:'))
except (OSError, StopIteration, ValueError):
    pages = 0
orphans = max(65536, min(pages // 2, 262144)) if pages else 65536
wanted = {
    'net.core.somaxconn': ('max', [16384]),
    'net.ipv4.tcp_max_syn_backlog': ('max', [16384]),
    'net.core.netdev_max_backlog': ('max', [16384]),
    'net.ipv4.tcp_max_orphans': ('max', [orphans]),
    # FIN, не подтверждённый ушедшим клиентом, не должен висеть минутами.
    'net.ipv4.tcp_orphan_retries': ('low', [3]),
    'net.ipv4.tcp_fin_timeout': ('low', [15]),
    'net.ipv4.tcp_tw_reuse': ('set', [2]),
}
if pages:
    wanted['net.ipv4.tcp_mem'] = ('max', [pages // 16, pages // 8, pages // 4])
lines = []
for key, (mode, target) in wanted.items():
    current = read(key)
    if current is None:
        continue
    try:
        current = [int(v) for v in current]
    except ValueError:
        continue
    if len(current) != len(target):
        continue
    if mode == 'max':
        value = [max(c, t) for c, t in zip(current, target)]
    elif mode == 'low':
        # 0 means "kernel default" for orphan_retries; any smaller positive wins.
        value = [t if c == 0 or c > t else c for c, t in zip(current, target)]
        if key == 'net.ipv4.tcp_fin_timeout':
            value = [min(c, t) for c, t in zip(current, target)]
    else:
        value = target if current[0] == 0 else current
    lines.append('%s = %s' % (key, ' '.join(str(v) for v in value)))
Path(sys.argv[1]).write_text(
    '# Managed by the mtdd installer; values are only ever raised.\n' + '\n'.join(lines) + '\n')
PY
    then
        warn 'Не удалось подготовить параметры ядра; продолжаю без них'
        return 0
    fi
    chmod 0644 "$conf"
    # Контейнеры и песочницы часто запрещают запись в sysctl: это не ошибка.
    if ! sysctl -q -p "$conf" >/dev/null 2>&1; then
        warn 'Часть параметров ядра применить не удалось (контейнер или ограничения хоста)'
    fi
}

# Настройки сетевого интерфейса не хранятся в sysctl.d и сбрасываются при
# перезагрузке, поэтому их применяет отдельная служба mtdd-nettune при каждом
# старте. Она сама определяет интерфейсы маршрутов по умолчанию, пропускает
# ядра без нужных параметров и значения, которые оператор уже изменил, а при
# остановке возвращает только то, что поставила сама. Отключение:
# systemctl disable --now mtdd-nettune.
tune_network() {
    step 'Настраиваю обработку сетевых прерываний (mtdd-nettune)…'
    install -d -m 0755 "$(dirname "$MTDD_NETTUNE")" /etc/systemd/system
    install -m 0755 /dev/stdin "$MTDD_NETTUNE" <<'NETTUNE'
#!/bin/sh
# mtdd-nettune: per-interface network tuning that sysctl.d cannot persist.
#   start  apply to the interfaces that carry the default routes
#   stop   restore exactly the values this script changed
# Each knob is skipped when the kernel lacks it or the operator already set a
# non-default value, so the script is safe on any Linux host.
set -u
SYSFS=${MTDD_NETTUNE_SYSFS:-/sys}
STATE=${MTDD_NETTUNE_STATE:-/run/mtdd-nettune}

ifaces() {
    { ip -4 route show default 2>/dev/null; ip -6 route show default 2>/dev/null; } |
        awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' | sort -u
}

# set_if_default FILE DEFAULT VALUE: write VALUE only while FILE still holds
# the kernel default, and remember the previous value for "stop".
set_if_default() {
    file=$1 default=$2 value=$3
    [ -w "$file" ] || return 0
    current=$(cat "$file" 2>/dev/null) || return 0
    [ "$current" = "$default" ] || return 0
    if echo "$value" > "$file" 2>/dev/null; then
        printf '%s %s %s\n' "$file" "$current" "$value" >> "$STATE/restore"
    fi
}

start() {
    mkdir -p "$STATE" && : > "$STATE/restore" || exit 0
    for dev in $(ifaces); do
        net="$SYSFS/class/net/$dev"
        [ -d "$net" ] || continue
        # NAPI IRQ deferral (Linux 5.10+): after a busy poll the driver keeps
        # the IRQ masked and drains again from a 1 ms timer. Far fewer
        # interrupts and larger GRO batches under load; an idle link still
        # interrupts immediately. Measured on a 2 vCPU virtio host: 1 ms beat
        # 0.2 ms by ~17% process CPU per Gbit; 2 ms only moved work between
        # process and softirq while adding latency.
        set_if_default "$net/napi_defer_hard_irqs" 0 2
        set_if_default "$net/gro_flush_timeout" 0 1000000
    done
}

stop() {
    [ -f "$STATE/restore" ] || return 0
    # Revert only values still equal to what start wrote: a later operator
    # change is kept.
    while read -r file old new; do
        [ -w "$file" ] || continue
        [ "$(cat "$file" 2>/dev/null)" = "$new" ] && echo "$old" > "$file" 2>/dev/null
    done < "$STATE/restore"
    rm -f "$STATE/restore"
}

case ${1:-start} in
    start) start ;;
    stop) stop ;;
    *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
exit 0
NETTUNE
    install -m 0644 /dev/stdin "$MTDD_NETTUNE_UNIT" <<UNIT
[Unit]
Description=mtdd network interface tuning (NAPI IRQ deferral)
After=network-online.target
Wants=network-online.target
Before=$MTDD_SERVICE

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$MTDD_NETTUNE start
ExecStop=$MTDD_NETTUNE stop

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload 2>/dev/null || true
    # restart = stop (restore) + start (apply), so an update re-evaluates.
    if ! { systemctl enable "$MTDD_NETTUNE_SERVICE" >/dev/null 2>&1 &&
           systemctl restart "$MTDD_NETTUNE_SERVICE" >/dev/null 2>&1; }; then
        warn 'Настройку сетевого интерфейса применить не удалось (контейнер или ограничения хоста)'
    fi
}

# ---------------------------------------------------------------------------
# Диспетчер
# ---------------------------------------------------------------------------
for cmd_dep in curl sha256sum awk mktemp install; do need "$cmd_dep"; done
if [[ -n $command ]]; then
    case $command in
        help) usage; exit 0 ;;
        menu) mg_require_root && mg_require_install && mg_require_tools && cmd_menu ;;
        status) mg_require_root && mg_require_install && mg_require_tools && cmd_status ;;
        service) mg_require_root && mg_require_install && mg_require_tools && cmd_service "${cargs[0]-}" ;;
        start) mg_require_root && mg_require_install && mg_require_tools && cmd_service start ;;
        stop) mg_require_root && mg_require_install && mg_require_tools && cmd_service stop ;;
        restart) mg_require_root && mg_require_install && mg_require_tools && cmd_service restart ;;
        logs) mg_require_root && mg_require_install && mg_require_tools && cmd_logs "${cargs[0]-}" ;;
        users) mg_require_root && mg_require_install && mg_require_tools && cmd_users "${cargs[@]}" ;;
        links) mg_require_root && mg_require_install && mg_require_tools && cmd_links "${cargs[@]}" ;;
        rotate) mg_require_root && mg_require_install && mg_require_tools && cmd_rotate "${cargs[@]}" ;;
        metrics) mg_require_root && mg_require_install && mg_require_tools && cmd_metrics "${cargs[@]}" ;;
        host) mg_require_root && mg_require_install && mg_require_tools && cmd_host "${cargs[@]}" ;;
        check-config) mg_require_root && mg_require_install && cmd_check_config ;;
        uninstall) mg_require_root && cmd_uninstall "${cargs[0]-}" ;;
    esac
    exit $?
fi

# Установленная система и запуск без единого аргумента — меню управления.
# Запуск с флагами сохраняет прежнее поведение: установка или обновление.
if ((invocation_args == 0)) && mg_installed; then
    if mg_require_root && mg_require_tools; then
        cmd_menu
        exit $?
    fi
    exit 1
fi

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die 'Поддерживается только Linux x86_64'
[[ $channel == main || $channel == dev ]] || die 'Для --branch укажите main или dev'
init_base_url
if ((binary_only)); then
    banner 'загрузка бинарника · MTProto / FakeTLS'
    step "Скачивание бинарника · канал: $channel"
    download_and_stage
    mv -f -- "$staged" "$output"
    ok "Бинарник $channel установлен: $output"
    exit 0
fi
run_install
