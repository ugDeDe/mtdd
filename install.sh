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
  users show ИМЯ                  Политики и статистика пользователя
  users set ИМЯ ПОЛЕ ЗНАЧЕНИЕ     Срок, квота, лимиты IP/скорости, заметка (none — снять)
  users reset-quota ИМЯ           Сбросить использованную квоту
  users audit [N]                 Последние N событий журнала аудита
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

api_request() { # api_request ФЛАГ_CURL|'' МЕТОД ПУТЬ [JSON-ТЕЛО]
    local flag=$1 method=$2 path=$3 body=${4-} token host port
    token=$(token_read) || return 1
    host=$(cfg_get control_host 127.0.0.1)
    port=$(cfg_get control_port 9090)
    [[ $host == 0.0.0.0 || $host == '::' || $host == '*' ]] && host=127.0.0.1
    [[ $host == *:* ]] && host="[$host]"
    local -a extra=()
    [[ -n $flag ]] && extra+=("$flag")
    if [[ -n $body ]]; then
        extra+=(-H 'Content-Type: application/json' -d "$body")
    elif [[ -z $flag && $method == POST ]]; then
        extra+=(-d '') # пустое тело действия: Content-Length: 0
    fi
    curl -sS --max-time 10 -X "$method" -H "Authorization: Bearer $token" \
        "${extra[@]}" "http://${host}:${port}${path}"
}

api() { # api МЕТОД ПУТЬ [JSON-ТЕЛО] — печатает тело ответа или завершается ошибкой
    api_request -f "$@"
}

api_try() { # как api, но без -f: тело ошибки сервера доступно вызывающему
    api_request '' "$@"
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

# ---------------------------------------------------------------------------
# Политики пользователей: срок, квота, лимиты, заметка, журнал аудита
# ---------------------------------------------------------------------------
policy_body() { # policy_body ПОЛЕ ЗНАЧЕНИЕ — печатает JSON-тело PATCH или причину отказа (код 1)
    python3 - "${1-}" "${2-}" <<'PY'
import datetime
import json
import re
import sys
from decimal import Decimal

field, raw = sys.argv[1], sys.argv[2].strip()
CLEAR = ("", "none", "null", "off", "-", "нет")
UNITS = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
INT63 = 2 ** 63 - 1


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def parse_size(text):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(?:([kmgt])(?:i?b)?|b)?", text, re.I)
    if not m:
        fail("Неверный размер «{}»: примеры 500M, 10G, 1T или число байт".format(text))
    number = Decimal(m.group(1)) * UNITS[(m.group(2) or "").lower()]
    if number != number.to_integral_value():
        fail("Размер должен быть целым числом байт")
    value = int(number)
    if value > INT63:
        fail("Слишком большой размер")
    return value


def parse_expiry(text):
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        try:
            datetime.date.fromisoformat(text)
        except ValueError:
            fail("Нет такой даты: " + text)
        return text + "T23:59:59Z"
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})", text)
    if not m:
        fail("Дата: ГГГГ-ММ-ДД, RFC 3339 (2030-01-01T00:00:00Z) или none для снятия срока")
    try:
        datetime.date.fromisoformat(m.group(1))
        ok = int(m.group(2)) < 24 and int(m.group(3)) < 60 and int(m.group(4)) < 60
        zone = m.group(6)
        if zone[0] in "+-":
            ok = ok and int(zone[1:3]) < 24 and int(zone[4:6]) < 60
    except ValueError:
        ok = False
    if not ok:
        fail("Некорректная дата или время: " + text)
    return text.upper()


if field == "expires_at":
    value = None if raw.lower() in CLEAR else parse_expiry(raw)
elif field == "data_quota_bytes":
    value = None if raw.lower() in CLEAR else parse_size(raw)
    if value is not None and value < 1:
        fail("Квота должна быть не меньше 1 байта")
elif field in ("rate_limit_up_bytes_per_sec", "rate_limit_down_bytes_per_sec"):
    value = None if raw.lower() in CLEAR else parse_size(raw)
    if value is not None and value < 1024:
        fail("Лимит скорости должен быть не меньше 1K (1024 байт/с)")
elif field == "max_unique_ips":
    if raw.lower() in CLEAR:
        value = None
    else:
        if not re.fullmatch(r"\d{1,10}", raw) or not 1 <= int(raw) <= 2 ** 32 - 1:
            fail("Лимит IP: целое число от 1 до 4294967295 или none")
        value = int(raw)
elif field == "max_devices":
    if raw.lower() in CLEAR:
        value = None
    else:
        if not re.fullmatch(r"\d{1,7}", raw) or not 1 <= int(raw) <= 1000000:
            fail("Лимит устройств: целое число от 1 до 1000000 или none")
        value = int(raw)
elif field == "note":
    try:
        raw.encode("utf-8")
    except UnicodeEncodeError:
        fail("Заметка содержит некорректные символы")
    if len(raw) > 256:
        fail("Заметка: не более 256 символов")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        fail("Заметка не должна содержать управляющие символы")
    value = raw
else:
    fail("Неизвестное поле: " + field)
print(json.dumps({field: value}, ensure_ascii=True, separators=(",", ":")))
PY
}

api_check() { # api_check ОТВЕТ — 0 если {"ok":true}; иначе печатает сообщение сервера и возвращает 1
    printf '%s' "${1-}" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    doc = json.loads(raw)
except Exception:
    print("  ответ сервера не разобран" if raw.strip() else "  пустой ответ сервера", file=sys.stderr)
    sys.exit(1)
if doc.get("ok") is True:
    sys.exit(0)
error = doc.get("error") or {}
print("  {}: {}".format(error.get("type", "error"), error.get("message", "неизвестная ошибка")), file=sys.stderr)
sys.exit(1)
'
}

cmd_users_set() { # cmd_users_set ИМЯ ПОЛЕ ЗНАЧЕНИЕ — изменить одно поле политики
    local name=${1-} field=${2-} value=${3-} body response msg
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    body=$(policy_body "$field" "$value" 2>&1) || { err "$body"; return 1; }
    response=$(api_try PATCH "/v1/users/$name" "$body" 2>&1) \
        || { err "Нет связи с API: ${response:-ошибка curl}"; return 1; }
    msg=$(api_check "$response" 2>&1) || { err "Не удалось изменить $name:${msg}"; return 1; }
    ok "Пользователь $name: $field обновлён"
}

cmd_users_action() { # cmd_users_action ИМЯ enable|disable|reset-quota
    local name=${1-} action=${2-} response msg
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    response=$(api_try POST "/v1/users/$name/$action" 2>&1) \
        || { err "Нет связи с API: ${response:-ошибка curl}"; return 1; }
    msg=$(api_check "$response" 2>&1) || { err "Не удалось выполнить $action для $name:${msg}"; return 1; }
    case $action in
        enable) ok "Пользователь $name включён" ;;
        disable) ok "Пользователь $name отключён · активные сессии отозваны" ;;
        reset-quota) ok "Использованная квота $name сброшена" ;;
        *) ok "Пользователь $name: $action выполнен" ;;
    esac
}

cmd_users_show() { # cmd_users_show ИМЯ — подробности и политики
    local name=${1-} response rows label value
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    response=$(api_try GET "/v1/users/$name" 2>&1) \
        || { err "Нет связи с API: ${response:-ошибка curl}"; return 1; }
    api_check "$response" 2>/dev/null || { err "Не удалось получить $name:$(api_check "$response" 2>&1 || true)"; return 1; }
    rows=$(printf '%s' "$response" | python3 -c '
import datetime
import json
import sys

doc = json.load(sys.stdin)
data = doc.get("data") or {}
user = data.get("user") or {}
stats = user.get("stats") or data.get("stats") or {}


def size(n):
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return "{} B".format(int(value)) if unit == "B" else "{:.1f} {}".format(value, unit)
        value /= 1024


def expiry(v):
    if v is None:
        return "бессрочно"
    text = str(v)
    try:
        when = datetime.datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        mark = " · истёк" if when < datetime.datetime.now(datetime.timezone.utc) else ""
        return "{}{}".format(text.replace("T", " ").replace("Z", " UTC"), mark)
    except ValueError:
        return text


def quota(limit, used):
    if limit is None:
        return "без лимита" + (" · использовано {}".format(size(used)) if used is not None else "")
    if used is None:
        return size(limit)
    return "{} / {} ({:.0f}%)".format(size(used), size(limit), 100.0 * used / limit if limit else 0)


def rate(v):
    return "без лимита" if v is None else size(v) + "/s"


used = user.get("quota_used_bytes", data.get("quota_used_bytes", stats.get("quota_used_bytes")))
rows = [
    ("Имя", user.get("name", "?")),
    ("Состояние", "включён" if user.get("enabled") else "отключён"),
    ("Срок действия", expiry(user.get("expires_at"))),
    ("Квота трафика", quota(user.get("data_quota_bytes"), used)),
    ("Лимит IP", "без лимита" if user.get("max_unique_ips") is None else str(user["max_unique_ips"])),
    ("Лимит устройств", "без лимита" if user.get("max_devices") is None else str(user["max_devices"])),
    ("Скорость ↑", rate(user.get("rate_limit_up_bytes_per_sec"))),
    ("Скорость ↓", rate(user.get("rate_limit_down_bytes_per_sec"))),
    ("Макс. соединений", "без лимита" if user.get("max_connections") is None else str(user["max_connections"])),
    ("Заметка", user.get("note") or "—"),
    ("Соединений", str(stats.get("active_connections", 0))),
    ("Уникальных IP", str(stats.get("unique_ips_active", 0))),
    ("Устройств", "{} подключено · {} за 15 мин".format(stats.get("devices_connected", 0), stats.get("devices", 0))),
]
for label, value in rows:
    print("{}\t{}".format(label, str(value).replace("\n", " ")))
') || { err "Не удалось разобрать данные $name"; return 1; }
    section "Пользователь · $name"
    while IFS=$'\t' read -r label value; do
        kv "$label" "$value"
    done <<<"$rows"
}

cmd_audit() { # cmd_audit [ЧИСЛО] — последние события журнала аудита
    local limit=${1:-20} response
    [[ $limit =~ ^[0-9]{1,3}$ ]] && ((10#$limit >= 1 && 10#$limit <= 256)) || { err 'Использование: users audit [1–256]'; return 1; }
    response=$(api_try GET "/v1/events?limit=$((10#$limit))" 2>&1) \
        || { err "Нет связи с API: ${response:-ошибка curl}"; return 1; }
    api_check "$response" 2>/dev/null || { err "Не удалось получить журнал:$(api_check "$response" 2>&1 || true)"; return 1; }
    printf '%s' "$response" | python3 -c '
import datetime
import json
import sys

events = (json.load(sys.stdin).get("data") or {}).get("events") or []
if not events:
    print("  Событий нет")
    sys.exit(0)


def when(v):
    if isinstance(v, (int, float)):
        v = v / 1000.0 if v > 1e11 else v
        return datetime.datetime.utcfromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
    return str(v).replace("T", " ").rstrip("Zz")[:19]


print("  {:<19}  {:<18} {:<16} {}".format("Время (UTC)", "Действие", "Пользователь", "Поля"))
for e in events:
    fields = e.get("fields") or []
    if isinstance(fields, dict):
        text = ", ".join("{}={}".format(k, fields[k]) for k in sorted(fields))
    elif isinstance(fields, list):
        text = ", ".join(str(f) for f in fields)
    else:
        text = str(fields)
    print("  {:<19}  {:<18} {:<16} {}".format(
        when(e.get("at", "")), str(e.get("action", "?")), str(e.get("user") or "—"), text.replace("\n", " ")))
' || { err 'Не удалось разобрать журнал'; return 1; }
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
        show)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users show ИМЯ'; return 1; }
            cmd_users_show "${cargs[1]}" ;;
        set)
            ((${#cargs[@]} >= 4)) || { err 'Использование: install.sh users set ИМЯ expires_at|data_quota_bytes|max_unique_ips|max_devices|rate_limit_up_bytes_per_sec|rate_limit_down_bytes_per_sec|note ЗНАЧЕНИЕ'; return 1; }
            cmd_users_set "${cargs[1]}" "${cargs[2]}" "${cargs[3]}" ;;
        reset-quota)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users reset-quota ИМЯ'; return 1; }
            cmd_users_action "${cargs[1]}" reset-quota ;;
        audit)
            cmd_audit "${cargs[1]-}" ;;
        *)
            err "Неизвестное действие users: $action (list|add|enable|disable|remove|rotate|show|set|reset-quota|audit)"
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
import re
import shutil
import sys
import textwrap
import time
import unicodedata

# Цвета приходят из bash; без MTDD_COLOR=1 (NO_COLOR, не TTY) они пустые,
# и статус передаётся только символами и текстом.
COLOR = os.environ.get("MTDD_COLOR") == "1"


def c(name):
    return os.environ.get("MTDD_C_" + name, "") if COLOR else ""


RESET = c("RESET")
BOLD = c("BOLD")
DIM = c("DIM")
GRAY = c("GRAY")
ACCENT = c("ACCENT")
VIOLET = c("VIOLET")
GREEN = c("GREEN")
YELLOW = c("YELLOW")
RED = c("RED")

# 8 уровней в одной строке; 3 строки дают 24
BLOCKS = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
GRAPH_ROWS = 3
LEVELS = GRAPH_ROWS * len(BLOCKS)
# минимальная ширина карточки KPI
CARD_MIN = 28
HISTORY_POINTS = 120
ANSI = re.compile(r"\033\[[0-9;]*m")

# Статус: (символ, цвет). Символ есть всегда — цвет его только усиливает.
STATUS = {
    "ok": ("\u2713", GREEN),
    "warn": ("!", YELLOW),
    "bad": ("\u2717", RED),
    "na": ("\u00b7", GRAY),
}


def term_width():
    # Ширина области вывода: на колонку уже терминала, чтобы не переносилось.
    cols = shutil.get_terminal_size((80, 24)).columns
    return max(38, min(119, cols - 1))


WIDTH = term_width()
# ширина содержимого после отступа в 2 пробела
AVAIL = WIDTH - 2


# --- Текст и ширина -------------------------------------------------------

def char_width(ch):
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def width(text):
    return sum(char_width(ch) for ch in ANSI.sub("", text))


def pad(text, size):
    return text + " " * max(0, size - width(text))


def rpad(text, size):
    return " " * max(0, size - width(text)) + text


def clip(text, size):
    # Обрезает по отображаемой ширине, не ломая ANSI-последовательности.
    if width(text) <= size:
        return text
    out, used = [], 0
    for part in re.split(r"(\033\[[0-9;]*m)", text):
        if ANSI.fullmatch(part):
            out.append(part)
            continue
        for ch in part:
            if used + char_width(ch) > size - 1:
                return "".join(out) + "\u2026" + RESET
            out.append(ch)
            used += char_width(ch)
    return "".join(out)


def cell(text, size, color=""):
    body = pad(clip(text, size), size)
    return (color + body + RESET) if color else body


def spread(left, right, size):
    # left у левого края, right у правого, в одну строку шириной size.
    right_w = width(right)
    left = clip(left, max(1, size - right_w - 1))
    return left + " " * max(1, size - width(left) - right_w) + right


def plural(count, one, few, many):
    count = int(count)
    if count % 10 == 1 and count % 100 != 11:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


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


def human_rate(value):
    return human(value) + "/\u0441"


def ms(value):
    return "{:.0f} ms".format(value)


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


# --- Оформление: статусы, секции, заметки ----------------------------------

def badge(status):
    symbol, color = STATUS[status]
    return color + BOLD + symbol + RESET


def status_text(status, text):
    return badge(status) + " " + STATUS[status][1] + text + RESET


def rtt_status(value):
    if value is None:
        return "na"
    return "ok" if value < 80 else ("warn" if value < 150 else "bad")


def rtt_color(value):
    return STATUS[rtt_status(value)][1]


def section(title):
    return (
        "\n  " + VIOLET + "\u258c" + RESET + " " + BOLD + clip(title, AVAIL - 2) + RESET
        + "\n  " + GRAY + "\u2500" * AVAIL + RESET
    )


def note(text):
    return "  " + DIM + clip(text, AVAIL) + RESET


def wrap_note(text):
    # Длинную заметку переносит по словам на несколько строк.
    return [note(line) for line in textwrap.wrap(text, AVAIL)]


def wrap_items(items):
    # Элементы через « · » с переносом по ширине (для сводок в одну-две строки).
    lines, current = [], ""
    for item in items:
        candidate = (current + " \u00b7 " + item) if current else item
        if current and width(candidate) > AVAIL:
            lines.append(current)
            current = item
        else:
            current = candidate
    if current:
        lines.append(current)
    return [note(line) for line in lines]


def pairs(items):
    # Пары «подпись — значение»: две колонки на широком экране, одна на узком.
    cols = 3 if AVAIL >= 100 else (2 if AVAIL >= 60 else 1)
    col_w = AVAIL // cols
    label_w = 18
    out = []
    for start in range(0, len(items), cols):
        line = "  "
        for label, value in items[start:start + cols]:
            line += GRAY + pad(clip(label, label_w), label_w) + RESET
            line += cell(str(value), col_w - label_w)
        out.append(line.rstrip())
    return out


# --- Разбор данных -----------------------------------------------------------

def load_prom(path):
    series = {}
    if not path:
        return series
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or " " not in line:
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
    # TSV из 8 колонок; строки другого вида (старые/битые) пропускаются.
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
    traffic = 0.0
    rtts = []
    for dc in me.get("dcs") or []:
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


def rate_series(points):
    rates = []
    for prev, cur in zip(points, points[1:]):
        delta_t = cur[0] - prev[0]
        if delta_t <= 0:
            continue
        rates.append(max(0.0, (cur[3] - prev[3]) / delta_t))
    return rates


def estimate(node):
    # Оценка из {"estimate": N} или голого числа; None, если поля нет.
    if isinstance(node, dict):
        node = node.get("estimate")
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        return int(node)
    return None


def period_active(history, key):
    # «Активные» IP за период: имена полей у разных версий сервера могут отличаться.
    own = history.get(key)
    candidates = [history.get(key + "_active")]
    if isinstance(own, dict):
        candidates += [own.get("active"), own.get("active_estimate")]
    for node in candidates:
        value = estimate(node)
        if value is not None:
            return value
    return None


def ip_rows(data, history):
    # [(подпись, замеченные, активные)] — активные None у старых серверов.
    now_active = estimate(data.get("unique_ips_active"))
    now_seen = estimate(data.get("unique_ips_seen"))
    has_active = now_seen is not None or any(
        period_active(history, key) is not None for key in ("hour", "day", "week")
    )
    if has_active:
        rows = [("\u0441\u0435\u0439\u0447\u0430\u0441", now_seen, now_active)]
    else:
        rows = [("\u0441\u0435\u0439\u0447\u0430\u0441", now_active, None)]
    for key, label in (("hour", "\u0447\u0430\u0441"), ("day", "\u0434\u0435\u043d\u044c"), ("week", "\u043d\u0435\u0434\u0435\u043b\u044f")):
        rows.append((label, estimate(history.get(key)), period_active(history, key)))
    return rows, has_active


def fmt_ip(value, approx):
    if value is None:
        return "\u2014"
    return ("\u2248" if approx else "") + num(value)


# --- Карточки KPI ------------------------------------------------------------

def card(title, big, lines, size, body_height):
    # Рамка ╭─ Заголовок ─╮ с body_height строками внутри.
    inner = size - 4
    title = clip(title, size - 6)
    top = (
        GRAY + "\u256d\u2500" + RESET + " " + BOLD + title + RESET + " "
        + GRAY + "\u2500" * (size - width(title) - 5) + "\u256e" + RESET
    )
    body = [big] + lines
    body += [""] * (body_height - len(body))
    out = [top]
    for text in body:
        out.append(
            GRAY + "\u2502" + RESET + " " + pad(clip(text, inner), inner) + " " + GRAY + "\u2502" + RESET
        )
    out.append(GRAY + "\u2570" + "\u2500" * (size - 2) + "\u256f" + RESET)
    return out


def card_columns():
    # Сколько карточек в ряд: 4 на широком терминале, 2 на среднем, 1 на узком.
    if AVAIL >= 4 * CARD_MIN + 3:
        return 4
    if AVAIL >= 2 * CARD_MIN + 1:
        return 2
    return 1


def render_cards(cards):
    per_row = card_columns()
    size = (AVAIL - (per_row - 1)) // per_row
    out = []
    for start in range(0, len(cards), per_row):
        group = cards[start:start + per_row]
        height = max(1 + len(item[2]) for item in group)
        boxes = [card(t, big, lines, size, height) for t, big, lines in group]
        for parts in zip(*boxes):
            out.append("  " + " ".join(parts))
    return out


def with_status(status, value, unit=""):
    text = BOLD + value + RESET
    if unit:
        text += " " + DIM + unit + RESET
    if status:
        text = badge(status) + " " + text
    return text


def connections_card(data):
    accepted = int(data.get("connections_accepted_total") or 0)
    rejected = int(data.get("connections_rejected_total") or 0)
    # Много отказов относительно принятых — повод заглянуть в причины.
    share = rejected / float(accepted + rejected) if accepted + rejected else 0.0
    status = "warn" if accepted + rejected >= 20 and share > 0.2 else "ok"
    return (
        "\u0421\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f",
        with_status(status, num(data.get("connections_active")), "\u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0445"),
        [
            GRAY + "\u043f\u0440\u0438\u043d\u044f\u0442\u043e " + RESET + num(accepted),
            GRAY + "\u043e\u0442\u043a\u043b\u043e\u043d\u0435\u043d\u043e " + RESET + num(rejected),
            GRAY + "\u0440\u0443\u043a\u043e\u043f\u043e\u0436\u0430\u0442\u0438\u0439 " + RESET + num(data.get("handshakes_total")),
        ],
    )


def ips_card(data, history):
    rows, has_active = ip_rows(data, history)
    now = rows[0]
    if has_active:
        head = BOLD + fmt_ip(now[2], False) + RESET + " / " + fmt_ip(now[1], False)
        head += " " + DIM + "\u0430\u043a\u0442. / \u0432\u0438\u0434." + RESET
    else:
        head = BOLD + fmt_ip(now[1], False) + RESET + " " + DIM + "\u0441\u0435\u0439\u0447\u0430\u0441" + RESET
    lines = []
    for label, seen, active in rows[1:]:
        if has_active:
            value = fmt_ip(active, True) + " / " + fmt_ip(seen, True)
        else:
            value = fmt_ip(seen, True)
        lines.append(GRAY + pad(label, 7) + RESET + value)
    return "\u0423\u043d\u0438\u043a\u0430\u043b\u044c\u043d\u044b\u0435 IP", head, lines


def traffic_card(dcs, rates):
    rx = sum(float(dc.get("rx_bytes_total", 0)) for dc in dcs)
    tx = sum(float(dc.get("tx_bytes_total", 0)) for dc in dcs)
    if rates:
        head = with_status(None, human_rate(rates[-1]))
        peak = GRAY + "\u043f\u0438\u043a " + RESET + human_rate(max(rates))
    else:
        head = DIM + "\u0441\u043e\u0431\u0438\u0440\u0430\u044e \u0438\u0441\u0442\u043e\u0440\u0438\u044e\u2026" + RESET
        peak = GRAY + "\u043f\u0438\u043a " + RESET + "\u2014"
    return (
        "\u0422\u0440\u0430\u0444\u0438\u043a \u0432 \u0441\u0435\u043a\u0443\u043d\u0434\u0443",
        head,
        [GRAY + "\u2193 \u043f\u0440\u0438\u043d\u044f\u0442\u043e " + RESET + human(rx), GRAY + "\u2191 \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u043e " + RESET + human(tx), peak],
    )


def rtt_card(dcs):
    live = [float(dc["ping_rtt_us"]) / 1000.0 for dc in dcs if dc.get("connected") and dc.get("ping_rtt_us")]
    up = sum(1 for dc in dcs if dc.get("connected"))
    if live:
        avg = sum(live) / len(live)
        head = with_status(rtt_status(avg), ms(avg))
        spread_text = "{:.0f}\u2013{:.0f} ms".format(min(live), max(live))
    else:
        head = with_status("na", "\u2014")
        spread_text = "\u2014"
    return (
        "ME RTT",
        head,
        [GRAY + "\u043f\u043e DC " + RESET + spread_text, GRAY + "DC \u0432 \u0441\u0435\u0442\u0438 " + RESET + "{} \u0438\u0437 {}".format(up, len(dcs))],
    )


# --- Графики ------------------------------------------------------------------

def resample(values, size):
    # Подгоняет ряд под size колонок: растягивает или усредняет по корзинам.
    count = len(values)
    if count == size:
        return list(values)
    if count < size:
        return [values[min(count - 1, int(i * count / size))] for i in range(size)]
    out = []
    for i in range(size):
        first = int(i * count / size)
        last = max(first + 1, int((i + 1) * count / size))
        chunk = values[first:last]
        out.append(sum(chunk) / len(chunk))
    return out


def level_of(value, low, high):
    # Уровень 1..24: минимум 1, чтобы нулевая линия всегда была видна.
    if high <= low:
        return LEVELS // 2 if low > 0 else 1
    ratio = (value - low) / (high - low)
    return 1 + max(0, min(LEVELS - 1, int(ratio * (LEVELS - 0.001))))


def block_for(level, row):
    # Символ ячейки: row=0 — нижняя строка графика, 2 — верхняя.
    fill = max(0, min(len(BLOCKS), level - row * len(BLOCKS)))
    return BLOCKS[fill - 1] if fill else " "


def paint_columns(levels, colors, row):
    out, current = [], None
    for level, color in zip(levels, colors):
        if color != current:
            out.append(RESET + color if current is not None else color)
            current = color
        out.append(block_for(level, row))
    return "".join(out) + (RESET if current else "")


def bounds(values, ranged=False):
    # Границы оси: от нуля, если разброс большой, иначе от минимума ряда.
    #
    # ranged=True — всегда от минимума (RTT: ноль на оси ничего не говорит).
    high = max(values)
    low = min(values) if ranged or min(values) >= 0.5 * high else 0.0
    return low, high


def graph(title, values, fmt, axis, color_of=None, status_of=None, ranged=False):
    # Трёхстрочный график: заголовок и текущее значение, ось min/max слева.
    if len(values) < 2:
        return [
            "  " + BOLD + title + RESET,
            "  " + DIM + "\u0441\u043e\u0431\u0438\u0440\u0430\u044e \u0438\u0441\u0442\u043e\u0440\u0438\u044e\u2026" + RESET,
            "",
        ]
    low, high = bounds(values, ranged)
    columns = AVAIL - axis - 2
    series = resample(values, columns)
    levels = [level_of(v, low, high) for v in series]
    colors = [color_of(v) if color_of else ACCENT for v in series]

    current = fmt(values[-1])
    if status_of:
        current = badge(status_of(values[-1])) + " " + current
    head = spread(
        "  " + BOLD + title + RESET,
        GRAY + "\u0441\u0435\u0439\u0447\u0430\u0441 " + RESET + BOLD + current + RESET,
        AVAIL + 2,
    )
    labels = {2: fmt(high), 1: "", 0: fmt(low)}
    out = [head]
    for row in (2, 1, 0):
        mark = "\u2502" if row == 1 else "\u2524"
        out.append(
            "  " + GRAY + rpad(labels[row], axis) + " " + mark + RESET
            + paint_columns(levels, colors, row)
        )
    out.append("")
    return out


def axis_width(specs):
    # Общая ширина подписей оси, чтобы все графики начинались с одной колонки.
    size = 0
    for _, values, fmt, extra in specs:
        if len(values) >= 2:
            low, high = bounds(values, extra.get("ranged", False))
            size = max(size, width(fmt(low)), width(fmt(high)))
    return size


def dynamics(rows, live):
    # Секция графиков по истории измерений.
    if len(rows) < 2:
        return [section("\u0414\u0438\u043d\u0430\u043c\u0438\u043a\u0430")] + [
            note("\u0441\u043e\u0431\u0438\u0440\u0430\u044e \u0438\u0441\u0442\u043e\u0440\u0438\u044e\u2026 \u0442\u043e\u0447\u043a\u0430 \u0434\u043e\u0431\u0430\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u043f\u0440\u0438 status/metrics (\u043d\u0435 \u0447\u0430\u0449\u0435 \u0440\u0430\u0437\u0430 \u0432 25 \u0441)"),
            note("\u0436\u0438\u0432\u043e\u0439 \u0440\u0435\u0436\u0438\u043c \u0441 \u0433\u0440\u0430\u0444\u0438\u043a\u0430\u043c\u0438: sudo mtdd-ctl metrics --watch"),
        ]
    points = rows[-HISTORY_POINTS:]
    span = points[-1][0] - points[0][0]
    out = [section("\u0414\u0438\u043d\u0430\u043c\u0438\u043a\u0430 \u00b7 {} {} \u0437\u0430 {}".format(
        num(len(points)), plural(len(points), "\u0442\u043e\u0447\u043a\u0430", "\u0442\u043e\u0447\u043a\u0438", "\u0442\u043e\u0447\u0435\u043a"), human_duration(span)))]
    out.append("")
    rtts = [row[4] for row in points if row[4] > 0]
    # (заголовок, ряд, формат, расширенные параметры)
    specs = [
        ("\u0410\u043a\u0442\u0438\u0432\u043d\u044b\u0435 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f", [row[1] for row in points], num, {}),
        ("\u0423\u043d\u0438\u043a\u0430\u043b\u044c\u043d\u044b\u0435 IP", [row[2] for row in points], num, {}),
        ("\u0422\u0440\u0430\u0444\u0438\u043a \u0432 \u0441\u0435\u043a\u0443\u043d\u0434\u0443", rate_series(points), human_rate, {}),
        ("ME RTT", rtts, ms, {"color_of": rtt_color, "status_of": rtt_status, "ranged": True}),
    ]
    axis = axis_width(specs)
    for title, values, fmt, extra in specs:
        out += graph(title, values, fmt, axis, **extra)
    out.append(note("\u0441\u043b\u0435\u0432\u0430 \u2014 {} \u043d\u0430\u0437\u0430\u0434, \u0441\u043f\u0440\u0430\u0432\u0430 \u2014 \u0441\u0435\u0439\u0447\u0430\u0441".format(human_duration(span))))
    out += wrap_note(
        "q \u2014 \u0432\u044b\u0445\u043e\u0434 \u0438\u0437 \u0436\u0438\u0432\u043e\u0433\u043e \u0440\u0435\u0436\u0438\u043c\u0430" if live
        else "\u0442\u043e\u0447\u043a\u0430 \u043a\u0430\u0436\u0434\u044b\u0435 ~25 \u0441 \u00b7 \u0436\u0438\u0432\u043e\u0439 \u0440\u0435\u0436\u0438\u043c: sudo mtdd-ctl metrics --watch"
    )
    return out


# --- Заголовок и общее состояние ----------------------------------------------

def overall(data, dcs):
    if not data.get("ready"):
        return "bad", "\u043d\u0435 \u0433\u043e\u0442\u043e\u0432"
    if dcs:
        up = sum(1 for dc in dcs if dc.get("connected"))
        if up == 0:
            return "bad", "\u043d\u0435\u0442 \u0441\u0432\u044f\u0437\u0438 \u0441 ME"
        if up < len(dcs):
            return "warn", "ME: {} \u0438\u0437 {} DC".format(up, len(dcs))
    return "ok", "\u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442"


def header(data, dcs, live):
    status, text = overall(data, dcs)
    right = status_text(status, text)
    if live:
        right += "  " + GREEN + "\u25cf live" + RESET
    right += "  " + GRAY + time.strftime("%H:%M:%S") + RESET
    out = ["\n" + spread("  " + VIOLET + "\u258c" + RESET + " " + BOLD + "\u041c\u0435\u0442\u0440\u0438\u043a\u0438" + RESET, right, WIDTH)]
    build = data.get("build") or {}
    out += wrap_items([
        "\u0430\u043f\u0442\u0430\u0439\u043c {}".format(human_duration(data.get("uptime_seconds"))),
        "\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439 {} (\u0432\u043a\u043b. {})".format(num(data.get("users_total")), num(data.get("users_enabled"))),
        "\u0432\u0435\u0440\u0441\u0438\u044f {}".format(build.get("version", "?")),
        "\u0440\u0435\u0432\u0438\u0437\u0438\u044f {}".format(num(data.get("revision"))),
    ])
    return out


def ip_notes(data, history, prom):
    # Пояснения к карточке IP: что значит «активные» и откуда оценка.
    _, has_active = ip_rows(data, history)
    out = []
    if has_active:
        min_bytes = history.get("min_bytes", data.get("unique_ip_min_bytes"))
        if min_bytes is None:
            min_bytes = prom_scalar(prom, "mtdd_unique_ips_min_bytes")
        limit = " \u2265 " + human(min_bytes) if min_bytes else ""
        out += wrap_note("\u0430\u043a\u0442. \u2014 IP, \u043f\u0435\u0440\u0435\u0434\u0430\u0432\u0448\u0438\u0435{}; \u0432\u0438\u0434. \u2014 \u0432\u0441\u0435 \u0437\u0430\u043c\u0435\u0447\u0435\u043d\u043d\u044b\u0435 \u043f\u0440\u0438 \u0440\u0443\u043a\u043e\u043f\u043e\u0436\u0430\u0442\u0438\u0438".format(limit))
    period = ""
    started = (history.get("hour") or {}).get("started_at")
    if started:
        period = " \u00b7 \u0442\u0435\u043a\u0443\u0449\u0438\u0439 \u0447\u0430\u0441 \u0441 " + time.strftime("%H:%M UTC", time.gmtime(started))
    out += wrap_note("\u0447\u0430\u0441/\u0434\u0435\u043d\u044c/\u043d\u0435\u0434\u0435\u043b\u044f \u2014 \u043e\u0446\u0435\u043d\u043a\u0430 HyperLogLog, \u043e\u0448\u0438\u0431\u043a\u0430 \u00b1{:.1f}%{}".format(
        100.0 * float(history.get("relative_standard_error", 0.0325)), period))
    return out


# --- Таблицы и подробные секции -----------------------------------------------

# (ключ, заголовок, ширина, приоритет): при нехватке места уходят колонки
# с большим приоритетом; DC и состояние остаются всегда.
DC_COLUMNS = [
    ("dc", "DC", 5, 0),
    ("state", "\u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435", 10, 0),
    ("rtt", "RTT", 8, 1),
    ("ready", "ready/conn", 12, 2),
    ("clients", "\u043a\u043b\u0438\u0435\u043d\u0442\u044b", 9, 3),
    ("traffic", "\u0442\u0440\u0430\u0444\u0438\u043a", 11, 4),
    ("queue", "\u043e\u0447\u0435\u0440\u0435\u0434\u044c", 9, 5),
    ("target", "target", 8, 6),
]


def pick_columns():
    chosen, used = [], 0
    for column in sorted(DC_COLUMNS, key=lambda item: item[3]):
        if column[3] and used + column[2] > AVAIL:
            continue
        chosen.append(column)
        used += column[2]
    return [col for col in DC_COLUMNS if col in chosen]


def dc_values(dc):
    up = bool(dc.get("connected"))
    rtt = float(dc.get("ping_rtt_us", 0)) / 1000.0
    has_rtt = up and rtt > 0
    return {
        "dc": (str(dc.get("dc", "?")), GRAY),
        "state": (("\u2713 up" if up else "\u2717 down"), GREEN if up else RED),
        "rtt": ((ms(rtt) if has_rtt else "\u2014"), rtt_color(rtt) if has_rtt else ""),
        "ready": ("{}/{}".format(num(dc.get("ready_connections", 0)), num(dc.get("connections", 0))), ""),
        "clients": (num(dc.get("bound_clients", 0)), ""),
        "traffic": (human(float(dc.get("rx_bytes_total", 0)) + float(dc.get("tx_bytes_total", 0))), ""),
        "queue": ("{}/{}".format(num(dc.get("ready_queue_depth", 0)), num(dc.get("ready_queue_clients", 0))), ""),
        "target": (num(dc.get("pool_target", 0)), ""),
    }


def dc_order(dc):
    try:
        return (0, int(str(dc.get("dc", "other"))))
    except ValueError:
        return (1, 0)


def me_section(me, dcs):
    out = [section("ME / DC")]
    if not dcs:
        return out + [note("\u043d\u0435\u0442 \u0434\u0430\u043d\u043d\u044b\u0445: ME \u0435\u0449\u0451 \u043d\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0430\u043b\u0441\u044f")]
    visible = [dc for dc in dcs if dc.get("connected") or dc.get("connections") or dc.get("pool_target")]
    visible = sorted(visible or dcs, key=dc_order)
    columns = pick_columns()
    out.append("  " + GRAY + "".join(cell(col[1], col[2]) for col in columns).rstrip() + RESET)
    for dc in visible:
        values = dc_values(dc)
        out.append("  " + "".join(cell(values[col[0]][0], col[2], values[col[0]][1]) for col in columns).rstrip())
    connected = sum(1 for dc in dcs if dc.get("connected"))
    out += wrap_items([
        "DC \u0432 \u0441\u0435\u0442\u0438: {} \u0438\u0437 {}".format(connected, len(dcs)),
        "\u0437\u0430\u043f\u0440\u043e\u0441\u043e\u0432 ME {}".format(num(me.get("requests_total"))),
        "\u043f\u0435\u0440\u0435\u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0439 {}".format(num(me.get("reconnects_total"))),
        "\u043e\u0448\u0438\u0431\u043e\u043a \u0441\u043e\u0437\u0434\u0430\u043d\u0438\u044f {}".format(num(sum(int(dc.get("creation_failures_total", 0)) for dc in dcs))),
    ])
    answers = sum(int(dc.get("proxy_ans_received_total", 0)) for dc in dcs)
    if answers:
        delivered = sum(int(dc.get("proxy_ans_delivered_total", 0)) for dc in dcs)
        dropped = sum(
            int(dc.get("proxy_ans_dropped_unknown_total", 0)) + int(dc.get("proxy_ans_dropped_other_total", 0))
            for dc in dcs
        )
        age = max((int(dc.get("last_proxy_ans_age_seconds", 0)) for dc in dcs), default=0)
        out += wrap_items([
            "proxy-answer: \u043f\u043e\u043b\u0443\u0447\u0435\u043d\u043e {}".format(num(answers)),
            "\u0434\u043e\u0441\u0442\u0430\u0432\u043b\u0435\u043d\u043e {}".format(num(delivered)),
            "\u043f\u043e\u0442\u0435\u0440\u044f\u043d\u043e {}".format(num(dropped)),
            "\u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0439 \u043e\u0442\u0432\u0435\u0442 {} \u043d\u0430\u0437\u0430\u0434".format(human_duration(age)),
        ])
    return out


def connections_section(data, prom):
    out = [section("\u0421\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f")]
    backpressure = data.get("backpressure_events_total") or {}
    out += pairs([
        ("\u0432 \u0440\u0430\u0431\u043e\u0442\u0435", pnum(prom, "mtdd_handshakes_pending")),
        ("replay-\u043a\u044d\u0448", num(data.get("replay_cache_entries"))),
        ("backpressure c2s", num(backpressure.get("c2s"))),
        ("backpressure s2c", num(backpressure.get("s2c"))),
    ])
    handshakes = {}
    for labels, value in prom.get("mtdd_handshakes_total", []):
        handshakes[labels.get("result", "")] = int(value)
    parts = []
    for key, label in (("success", "\u0443\u0441\u043f\u0435\u0448\u043d\u043e"), ("failure", "\u043e\u0448\u0438\u0431\u043a\u0430"), ("timeout", "\u0442\u0430\u0439\u043c\u0430\u0443\u0442"), ("replay", "replay")):
        if key in handshakes:
            parts.append(num(handshakes[key]) + " " + label)
    if parts:
        out += wrap_items(["\u0440\u0443\u043a\u043e\u043f\u043e\u0436\u0430\u0442\u0438\u044f: " + parts[0]] + parts[1:])
    reasons = {}
    for labels, value in prom.get("mtdd_connections_rejected_total", []):
        if int(value):
            reasons[labels.get("reason", "other")] = int(value)
    if reasons:
        out += wrap_items(["\u043f\u0440\u0438\u0447\u0438\u043d\u044b \u043e\u0442\u043a\u0430\u0437\u0430: " + ", ".join(
            "{} {}".format(name, num(value)) for name, value in sorted(reasons.items()))])
    return out


def buffers_section(data, me, dcs, prom):
    buffers = data.get("buffer_bytes") or {}
    depth = sum(int(dc.get("ready_queue_depth", 0)) for dc in dcs)
    clients = sum(int(dc.get("ready_queue_clients", 0)) for dc in dcs)
    frames = sum(int(dc.get("frames_queued_bytes", 0)) for dc in dcs)
    outgoing = sum(int(dc.get("out_queued_bytes", 0)) for dc in dcs)
    return [section("\u0411\u0443\u0444\u0435\u0440\u044b \u0438 \u043e\u0447\u0435\u0440\u0435\u0434\u0438")] + pairs([
        ("relay", human(buffers.get("relay"))),
        ("pending write", human(buffers.get("pending_write"))),
        ("queued", human(buffers.get("queued"))),
        ("ME pending", human(me.get("pending_buffer_bytes"))),
        ("ready queue", "{} ({} \u043a\u043b.)".format(num(depth), num(clients))),
        ("frames / out", "{} / {}".format(human(frames), human(outgoing))),
        ("\u0431\u044e\u0434\u0436\u0435\u0442 \u0431\u0443\u0444\u0435\u0440\u043e\u0432", human(prom_scalar(prom, "mtdd_buffer_budget_bytes"))),
        ("\u043f\u0443\u043b \u043a\u043b\u0438\u0435\u043d\u0442\u043e\u0432", pnum(prom, "mtdd_client_pool_objects")),
    ])


def traffic_section(dcs):
    rx = sum(float(dc.get("rx_bytes_total", 0)) for dc in dcs)
    tx = sum(float(dc.get("tx_bytes_total", 0)) for dc in dcs)
    out = [section("\u0422\u0440\u0430\u0444\u0438\u043a")] + pairs([("\u043f\u0440\u0438\u043d\u044f\u0442\u043e", human(rx)), ("\u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u043e", human(tx))])
    direct_active = sum(int(dc.get("direct_active", 0)) for dc in dcs)
    direct_accepted = sum(int(dc.get("direct_accepted_total", 0)) for dc in dcs)
    if direct_active or direct_accepted:
        out += wrap_items([
            "\u043f\u0440\u044f\u043c\u044b\u0435 DC: {} \u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0445".format(num(direct_active)),
            "{} \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e".format(num(direct_accepted)),
            "{} \u043e\u0448\u0438\u0431\u043e\u043a \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f".format(num(sum(int(dc.get("direct_connect_fail_total", 0)) for dc in dcs))),
        ])
    return out


def render(data, prom):
    live = os.environ.get("MTDD_LIVE") == "1"
    me = data.get("me") or {}
    dcs = me.get("dcs") or []
    history = data.get("unique_ip_history") or {}
    rows = history_load(history_path())
    rates = rate_series(rows[-HISTORY_POINTS:])

    out = header(data, dcs, live)
    out.append("")
    out += render_cards([
        connections_card(data),
        ips_card(data, history),
        traffic_card(dcs, rates),
        rtt_card(dcs),
    ])
    out += ip_notes(data, history, prom)
    out += dynamics(rows, live)
    out += connections_section(data, prom)
    out += buffers_section(data, me, dcs, prom)
    out += me_section(me, dcs)
    out += traffic_section(dcs)

    # Страховка: ни одна строка не должна переноситься терминалом.
    return "\n".join(clip(line, WIDTH) for line in "\n".join(out).split("\n"))


def main():
    path = os.environ.get("MTDD_JSON", "")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh).get("data", {})
    except (OSError, ValueError):
        print("  \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0440\u0430\u0437\u043e\u0431\u0440\u0430\u0442\u044c \u043e\u0442\u0432\u0435\u0442 API")
        return 1

    force = os.environ.get("MTDD_METRICS_FORCE") == "1"
    sample(data, force=force)
    if os.environ.get("MTDD_RECORD_ONLY") == "1":
        return 0
    prom = load_prom(os.environ.get("MTDD_METRICS_TXT", ""))
    print(render(data, prom))
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
}

url_host() { # url_host ХОСТ — хост для URL: wildcard -> loopback, IPv6 в скобках
    local host=$1
    [[ $host == 0.0.0.0 || $host == '::' || $host == '*' ]] && host=127.0.0.1
    [[ $host == *:* ]] && host="[$host]"
    printf '%s' "$host"
}

metrics_token_read() { # metrics_token_read ИМЯ-ПЕРЕМЕННОЙ — значение из credentials.env
    local name=$1
    [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    sed -n "s|^\(export \)\{0,1\}${name}=\([A-Za-z0-9._~+=/-]\{16,\}\)\$|\2|p" "$MTDD_CREDS" 2>/dev/null | head -1
}

# Метрики Prometheus: сначала отдельный listener (metrics_host:metrics_port),
# затем устаревший GET /metrics на порту API с админским токеном.
metrics_fetch() { # metrics_fetch — печатает текст Prometheus или завершается ошибкой
    local port host token_env token= out
    # Ключа нет — у бинарника тот же дефолт 9091; старый бинарник даст fallback.
    port=$(cfg_get metrics_port 9091 2>/dev/null) || port=
    if [[ $port =~ ^[0-9]+$ ]] && ((port > 0)); then
        host=$(url_host "$(cfg_get metrics_host 127.0.0.1)")
        token_env=$(cfg_get metrics_token_env '' 2>/dev/null) || token_env=
        if [[ -n $token_env ]]; then
            token=$(metrics_token_read "$token_env") || token=
        fi
        # Токен передаётся через stdin (-K -), чтобы не светиться в списке процессов.
        if [[ -n $token ]]; then
            out=$(printf 'header = "Authorization: Bearer %s"\n' "$token" |
                curl -fsS --max-time 5 -K - "http://${host}:${port}/metrics" 2>/dev/null) || out=
        else
            out=$(curl -fsS --max-time 5 "http://${host}:${port}/metrics" 2>/dev/null) || out=
        fi
        if [[ -n $out ]]; then
            printf '%s\n' "$out"
            return 0
        fi
    fi
    api GET /metrics 2>/dev/null
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
        metrics_fetch 2>/dev/null >"$work/metrics.txt" || true
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
        metrics_fetch 2>/dev/null || { err 'Не удалось получить метрики'; return 1; }
        return 0
    fi
    if [[ -n $filter ]]; then
        local out lines
        out=$(metrics_fetch 2>/dev/null) || { err 'Не удалось получить метрики'; return 1; }
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
    metrics_fetch 2>/dev/null >"$work/metrics.txt" || true
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
    remove_ctl_links
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

menu_ask_set() { # menu_ask_set ИМЯ ПОЛЕ ПОДСКАЗКА — спросить значение и применить
    local value
    menu_read value "  › $3: " || return 0
    menu_run cmd_users_set "$1" "$2" "$value"
}

menu_user_policy() { # menu_user_policy ИМЯ — политики одного пользователя
    local name=$1 choice
    valid_user_name "$name" || { err 'Неверное имя пользователя'; menu_pause; return 0; }
    while :; do
        menu_frame "Пользователь · $name" ''
        menu_row 1 'Подробности' 6 'Лимит скорости ↓'
        menu_row 2 'Срок действия' 7 'Заметка'
        menu_row 3 'Квота трафика' 8 'Включить'
        menu_row 4 'Лимит уникальных IP' 9 'Отключить'
        menu_row 5 'Лимит скорости ↑' 10 'Сбросить квоту'
        menu_row 11 'Лимит устройств' 0 'Назад'
        menu_footer
        menu_read choice '  › ' || return 0
        case $choice in
            1) menu_run cmd_users_show "$name"; menu_pause ;;
            2) menu_ask_set "$name" expires_at 'Срок (ГГГГ-ММ-ДД или RFC 3339, Enter/none — бессрочно)'; menu_pause ;;
            3) menu_ask_set "$name" data_quota_bytes 'Квота (10G, 500M, 1T, байты; Enter/none — без лимита)'; menu_pause ;;
            4) menu_ask_set "$name" max_unique_ips 'Макс. уникальных IP (число; Enter/none — без лимита)'; menu_pause ;;
            5) menu_ask_set "$name" rate_limit_up_bytes_per_sec 'Скорость ↑ в секунду (например 2M, минимум 1K; Enter/none — без лимита)'; menu_pause ;;
            6) menu_ask_set "$name" rate_limit_down_bytes_per_sec 'Скорость ↓ в секунду (например 2M, минимум 1K; Enter/none — без лимита)'; menu_pause ;;
            7) menu_ask_set "$name" note 'Заметка (до 256 символов; Enter — очистить)'; menu_pause ;;
            8) menu_run cmd_users_action "$name" enable; menu_pause ;;
            9) menu_run cmd_users_action "$name" disable; menu_pause ;;
            10) menu_run cmd_users_action "$name" reset-quota; menu_pause ;;
            11) menu_ask_set "$name" max_devices 'Макс. устройств (по auth_key_id; Enter/none — без лимита)'; menu_pause ;;
            0|q|Q) return 0 ;;
            *) : ;;
        esac
    done
}

menu_users() {
    local choice name
    while :; do
        menu_frame 'Пользователи' ''
        menu_row 1 'Список' 4 'Отключить'
        menu_row 2 'Добавить' 5 'Удалить'
        menu_row 3 'Включить' 6 'Новый секрет'
        menu_row 7 'Политики пользователя' 8 'Журнал аудита'
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
            7)
                menu_read name '  › Имя пользователя: ' || return 0
                [[ -n $name ]] && menu_user_policy "$name" ;;
            8)
                menu_run cmd_audit 20
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

# URL установщика для mtdd-ctl: ветка совпадает с выбранным каналом (main|dev).
# MTDD_LAUNCHER_URL — только для тестов.
launcher_source_url() {
    printf '%s' "${MTDD_LAUNCHER_URL:-https://raw.githubusercontent.com/$repo/$channel/install.sh}"
}

# Команда для ручной установки менеджера, если автоматическая не удалась.
launcher_manual_command() {
    printf 'sudo curl -fsSLo %s https://raw.githubusercontent.com/%s/%s/install.sh && sudo chmod 755 %s' \
        "$MTDD_CTL" "$repo" "$channel" "$MTDD_CTL"
}

# Файл похож на наш установщик: shebang и функция установки менеджера.
launcher_source_valid() {
    [[ -s $1 ]] && head -n 1 -- "$1" | grep -q '^#!/usr/bin/env bash' \
        && grep -q 'install_launcher_copy' "$1"
}

# fetch_launcher_source ПУТЬ: скачать установщик канала (3 попытки) и проверить его.
fetch_launcher_source() {
    local dest=$1 url
    url=$(launcher_source_url)
    for _ in 1 2 3; do
        if curl -fsSL --connect-timeout 20 -o "$dest" "$url" && launcher_source_valid "$dest"; then
            return 0
        fi
        sleep 1
    done
    rm -f -- "$dest"
    return 1
}

# Атомарная установка менеджера: временный файл в том же каталоге + mv -f,
# чтобы не портить запущенный скрипт (bash читает его постепенно).
install_launcher_file() {
    local src=$1 tmp
    tmp=$(mktemp "$(dirname -- "$MTDD_CTL")/.mtdd-ctl.XXXXXXXX") || return 1
    if install -m 0755 -- "$src" "$tmp" && chmod 0755 -- "$tmp" && mv -f -- "$tmp" "$MTDD_CTL"; then
        return 0
    fi
    rm -f -- "$tmp"
    return 1
}

# secure_path из sudo (пусто, если определить не удалось).
sudo_secure_path() {
    local value=
    if command -v sudo >/dev/null 2>&1; then
        value=$(sudo -V 2>/dev/null | sed -n "s/^[[:space:]]*Value to override user's \$PATH with:[[:space:]]*//p" | head -n 1 || true)
    fi
    if [[ -z $value ]]; then
        value=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
            | sed -n 's/^[[:space:]]*Defaults.*secure_path[[:space:]]*=[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' \
            | head -n 1 || true)
    fi
    printf '%s' "$value"
}

path_has_dir() { # path_has_dir СПИСОК_ЧЕРЕЗ_ДВОЕТОЧИЕ КАТАЛОГ
    case ":$1:" in *":$2:"*) return 0 ;; *) return 1 ;; esac
}

# Если /usr/local/bin нет в secure_path sudo (RHEL/Alma/Rocky/CentOS/Fedora),
# делаем симлинк, чтобы работало `sudo mtdd-ctl`.
ensure_sudo_visibility() {
    local sp link_dir=/usr/sbin link
    sp=$(sudo_secure_path)
    if [[ -n $sp ]]; then
        path_has_dir "$sp" /usr/local/bin && return 0
        if ! path_has_dir "$sp" /usr/sbin && path_has_dir "$sp" /usr/bin; then link_dir=/usr/bin; fi
    fi
    [[ -d $link_dir ]] || return 0
    link=$link_dir/mtdd-ctl
    if [[ -L $link && $(readlink -- "$link") == "$MTDD_CTL" ]]; then
        return 0
    fi
    if [[ -e $link || -L $link ]]; then
        warn "$link уже существует и не наш; sudo mtdd-ctl может не найтись, используйте sudo $MTDD_CTL"
        return 0
    fi
    if ln -s -- "$MTDD_CTL" "$link"; then
        ok "secure_path sudo без /usr/local/bin: создана ссылка $link"
    else
        warn "Не удалось создать ссылку $link; используйте sudo $MTDD_CTL"
    fi
}

remove_ctl_links() {
    local link
    for link in /usr/sbin/mtdd-ctl /usr/bin/mtdd-ctl; do
        if [[ -L $link && $(readlink -- "$link") == "$MTDD_CTL" ]]; then rm -f -- "$link"; fi
    done
}

# Итоговая проверка: находит ли `sudo mtdd-ctl` менеджер при secure_path.
verify_launcher_resolves() {
    local sp
    sp=$(sudo_secure_path)
    [[ -n $sp ]] || sp=/sbin:/bin:/usr/sbin:/usr/bin
    if env -i PATH="$sp" bash -c 'command -v mtdd-ctl' >/dev/null 2>&1; then
        return 0
    fi
    warn "'sudo mtdd-ctl' не найдёт команду (secure_path: $sp)"
    warn "Используйте абсолютный путь: sudo $MTDD_CTL"
    return 1
}

install_launcher_copy() {
    local src=${BASH_SOURCE[0]:-}
    local self_copy="$work/mtdd-ctl.src"
    if [[ -z $src || $src == /dev/stdin || $src == /dev/fd/* || ! -f $src ]] || [[ $src -ef $MTDD_CTL ]]; then
        # Конвейер или запуск самого mtdd-ctl: берём свежий установщик нужного канала.
        if fetch_launcher_source "$self_copy"; then
            src=$self_copy
            ok "Копия установщика получена из репозитория (канал $channel)"
        else
            if [[ -x $MTDD_CTL ]]; then
                launcher_installed=1
                warn "Не удалось обновить mtdd-ctl, оставлена прежняя версия ($MTDD_CTL)"
                warn "Обновить вручную: $(launcher_manual_command)"
                ensure_sudo_visibility
                return 0
            fi
            warn '!!! mtdd-ctl НЕ УСТАНОВЛЕН: не удалось скачать install.sh из репозитория'
            warn "!!! Установите менеджер вручную: $(launcher_manual_command)"
            return 0
        fi
    fi
    if install_launcher_file "$src"; then
        launcher_installed=1
        ok "Менеджер управления: sudo mtdd-ctl ($MTDD_CTL)"
    else
        warn 'Не удалось установить mtdd-ctl; управление доступно через этот же скрипт'
        warn "Установите вручную: $(launcher_manual_command)"
        return 0
    fi
    ensure_sudo_visibility
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
    # Менеджер ставим сразу после проверки бинарника: сбой запуска службы ниже
    # (set -e) не должен оставить сервер без mtdd-ctl.
    install_launcher_copy

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
Path('/etc/mtdd/credentials.env').write_text(''.join(
    f'{name}={secrets.token_hex(32)}\n'
    for name in ('MTDD_API_TOKEN', 'MTDD_API_READ_TOKEN', 'MTDD_METRICS_TOKEN')))
Path('/var/lib/mtdd/users.json').write_text(json.dumps(users, indent=2) + '\n')
PY
        chown root:mtdd /etc/mtdd/config.json
        chmod 0640 /etc/mtdd/config.json
        chown root:root /etc/mtdd/credentials.env
        chmod 0600 /etc/mtdd/credentials.env
        chown mtdd:mtdd "$MTDD_STATE/users.json"
        chmod 0600 "$MTDD_STATE/users.json"
    else
        # Обновление: дописываем недостающие токены, существующие значения не трогаем.
        python3 - "$MTDD_CREDS" <<'PY'
import re
import secrets
import sys

path = sys.argv[1]
with open(path, 'r+') as f:  # открытие на месте сохраняет владельца и режим файла
    text = f.read()
    add = ''
    for name in ('MTDD_API_READ_TOKEN', 'MTDD_METRICS_TOKEN'):
        if not re.search(r'^(export\s+)?' + name + r'=', text, re.M):
            add += f'{name}={secrets.token_hex(32)}\n'
    if add:
        if text and not text.endswith('\n'):
            add = '\n' + add
        f.write(add)
PY
    fi
    config_candidate=$(mktemp /etc/mtdd/.config.XXXXXXXX)
    trap 'rm -rf -- "$work"; rm -f -- "$staged" "$config_candidate"' EXIT
    # Отдельные токены read/metrics и файл расхода квот знает только новый бинарник:
    # сначала пробуем конфиг с ними, при отказе (старый канал) — без них.
    local scoped
    for scoped in 1 0; do
        MTDD_SCOPED_TOKENS=$scoped MTDD_PUBLIC_HOST=$public_host MTDD_PUBLIC_PORT=$public_port \
            python3 - "$config_candidate" <<'PY'
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
scoped = {'api_read_token_env': 'MTDD_API_READ_TOKEN', 'metrics_token_env': 'MTDD_METRICS_TOKEN',
          'usage_state_path': '/var/lib/mtdd/usage.json'}
if os.environ['MTDD_SCOPED_TOKENS'] == '1':
    for key, value in scoped.items():
        config.setdefault(key, value)
else:
    for key in scoped:
        config.pop(key, None)
Path(sys.argv[1]).write_text(json.dumps(config, indent=2) + '\n')
PY
        if "$staged" --config "$config_candidate" --check-config >/dev/null 2>&1; then break; fi
        ((scoped)) && continue
        "$staged" --config "$config_candidate" --check-config >/dev/null || die 'Проверка конфигурации не пройдена'
    done
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
    section 'Готово · ссылки для Telegram'
    ok "Бинарник: $channel · служба: mtdd"
    warn 'Ссылки содержат секреты. Передавайте их только своим пользователям.'
    printf '\n'
    print_links_from_files
    printf '\n'
    if ((launcher_installed)); then
        if verify_launcher_resolves; then
            step 'Управление: sudo mtdd-ctl (меню)'
        else
            step "Управление: sudo $MTDD_CTL (меню)"
        fi
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
# Тестовый хук: подключить функции без запуска (MTDD_INSTALLER_SOURCE_ONLY=1 source install.sh).
if [[ ${MTDD_INSTALLER_SOURCE_ONLY:-} == 1 ]]; then return 0 2>/dev/null || exit 0; fi
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
