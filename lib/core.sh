# shellcheck shell=bash
say() { printf '%s\n' "$*"; }
die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
redact() { sed -E 's/[A-Za-z0-9+\/]{43}=/[KEY REDACTED]/g'; }
usage() {
    cat <<'HELP'
socks2awg — SOCKS-вход → персональный AmneziaWG-туннель

socks2awg                            Меню
socks2awg add NAME [FILE] [--port N]  Импорт файла или вставка до строки END
socks2awg list                       Профили и состояние контейнеров
socks2awg show NAME                  Пароль и ссылка подключения
socks2awg check [NAME]               Запрос через один / все SOCKS
socks2awg stats [NAME] [--watch]      Трафик, CPU, RAM, handshake
socks2awg logs NAME                  Последние 100 строк логов
socks2awg start NAME                 Запустить профиль
socks2awg stop NAME                  Остановить профиль
socks2awg remove NAME [--yes]         Удалить профиль и его секреты
socks2awg version                    Версия

Имя: строчные латинские буквы, цифры, дефис; до 32 символов.
Менять настройки можно удалением и повторным добавлением профиля.
HELP
}
require_runtime() {
    local tool
    [[ $(uname -s) == Linux ]] || die 'Утилита предназначена для Linux-сервера.'
    [[ $EUID == 0 ]] || die 'Запустите через sudo или от root.'
    for tool in docker curl jq openssl flock ss awk; do
        command -v "$tool" >/dev/null || die "Не найден $tool. Повторите установку."
    done
    [[ $DATA_DIR == /* && $DATA_DIR != *[[:space:]]* ]] || die 'Некорректный каталог данных'
    mkdir -p "$DATA_DIR/profiles"
    chmod 700 "$DATA_DIR" "$DATA_DIR/profiles"
    docker info >/dev/null 2>&1 || die 'Docker недоступен. Проверьте службу docker.'
    docker compose version >/dev/null 2>&1 || die 'Нужен Docker Compose v2.'
}
lock_mutation() {
    exec 9>"$DATA_DIR/.lock"
    flock -w 30 9 || die 'Другая операция ещё выполняется. Повторите позже.'
}
valid_name() { [[ $1 =~ ^[a-z][a-z0-9-]{0,31}$ ]]; }
profile_exists() {
    valid_name "$1" || die 'Некорректное имя профиля'
    [[ -f $DATA_DIR/profiles/$1/profile.json ]] || die "Профиль $1 не найден"
}
container_name() { printf 'socks2awg-%s' "$1"; }
metadata() { jq -er "$2" "$DATA_DIR/profiles/$1/profile.json"; }
profile_names() {
    local file
    for file in "$DATA_DIR"/profiles/*/profile.json; do
        [[ -f $file ]] || continue
        basename "$(dirname "$file")"
    done
}
compose() {
    local name=$1; shift
    docker compose --project-name "socks2awg-$name" --file "$DATA_DIR/profiles/$name/compose.json" "$@"
}
state() {
    docker inspect --format '{{.State.Status}}' "$(container_name "$1")" 2>/dev/null || printf 'missing\n'
}
list_profiles() {
    local name
    printf '%-32s %-7s %s\n' 'PROFILE' 'PORT' 'CONTAINER'
    while IFS= read -r name; do
        printf '%-32s %-7s %s\n' "$name" "$(metadata "$name" '.port')" "$(state "$name")"
    done < <(profile_names)
    say 'Статус контейнера не заменяет проверку подключения: socks2awg check'
}
ensure_host() {
    local host
    [[ -s $DATA_DIR/host ]] && return 0
    [[ -t 0 ]] || die 'Сначала запустите socks2awg в терминале и укажите адрес сервера.'
    read -r -p 'Публичный IPv4 или домен РУ-сервера (для ссылок SOCKS): ' host
    [[ $host =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && ${#host} -le 253 ]] || die 'Введите IPv4 или домен без схемы и порта.'
    printf '%s\n' "$host" >"$DATA_DIR/host.tmp"
    mv "$DATA_DIR/host.tmp" "$DATA_DIR/host"
}
show_profile() {
    local name=$1 host port password
    profile_exists "$name"
    host=$(cat "$DATA_DIR/host")
    port=$(metadata "$name" '.port')
    password=$(metadata "$name" '.password')
    printf 'Профиль: %s\nАдрес:   %s:%s\nЛогин:   %s\nПароль:  %s\n\nsocks5h://%s:%s@%s:%s\n' \
        "$name" "$host" "$port" "$name" "$password" "$name" "$password" "$host" "$port"
}
port_available() {
    local port=$1 file sockets
    sockets=$(ss -H -ltn) || die 'Не удалось прочитать занятые порты'
    # Both listening sockets and stopped profiles reserve their ports.
    if printf '%s\n' "$sockets" | awk -v p=":$port" '$4 ~ (p "$") {found=1} END {exit !found}'; then return 1; fi
    for file in "$DATA_DIR"/profiles/*/profile.json; do
        [[ -f $file ]] || continue
        if jq -e --argjson p "$port" '.port == $p or .metrics_port == $p' "$file" >/dev/null; then return 1; fi
    done
    return 0
}
allocate_port() {
    local port=$1 end=$2 excluded=${3:-0}
    while ((port <= end)); do
        if ((port != excluded)) && port_available "$port"; then printf '%s\n' "$port"; return 0; fi
        port=$((port + 1))
    done
    return 1
}
ensure_engine() {
    docker image inspect "$ENGINE_IMAGE" >/dev/null 2>&1 && return 0
    say 'Первая сборка wireproxy-awg: понадобится интернет и несколько минут.'
    docker build --tag "$ENGINE_IMAGE" --file "$APP_DIR/Dockerfile" "$APP_DIR" || die 'Не удалось собрать ядро.'
}
write_compose() {
    local name=$1 dir=$2 metrics=$3
    jq -n --arg name "$(container_name "$name")" --arg image "$ENGINE_IMAGE" \
        --arg config "$dir/wireproxy.conf" --arg info "127.0.0.1:$metrics" \
        '{services:{proxy:{image:$image,container_name:$name,network_mode:"host",
          user:"0:0",read_only:true,cap_drop:["ALL"],security_opt:["no-new-privileges:true"],
          restart:"unless-stopped",stop_grace_period:"10s",
          labels:{"io.socks2awg.managed":"true"},
          command:["-s","-c","/etc/wireproxy/config.conf","-i",$info],
          volumes:[{type:"bind",source:$config,target:"/etc/wireproxy/config.conf",read_only:true}],
          logging:{driver:"json-file",options:{"max-size":"5m","max-file":"2"}}
        }}}'
}
private_key_hash() {
    awk -F ' = ' 'tolower($1)=="privatekey" {print $2}' "$1" | openssl dgst -sha256 | awk '{print $NF}'
}
add_profile() (
    local name=${1:-} input='' port='' metrics dir stage password hash other rc=0 line
    [[ -n $name ]] || die 'Использование: socks2awg add NAME [FILE] [--port N]'
    shift
    valid_name "$name" || die 'Имя: [a-z][a-z0-9-], от 1 до 32 символов'
    while (($#)); do
        case "$1" in
            --port) (($# >= 2)) || die 'После --port нужен номер'; port=$2; shift 2 ;;
            -*) die "Неизвестный аргумент: $1" ;;
            *) [[ -z $input ]] || die 'Укажите только один файл'; input=$1; shift ;;
        esac
    done
    lock_mutation
    dir=$DATA_DIR/profiles/$name
    [[ ! -e $dir ]] || die "Профиль $name уже существует"
    # Never adopt an unrelated container with the same name.
    if docker inspect "$(container_name "$name")" >/dev/null 2>&1; then die 'Имя контейнера уже занято.'; fi
    ensure_host
    stage=$(mktemp -d "$DATA_DIR/profiles/.adding-$name.XXXXXX")
    # Capture the local path now: Bash may unwind function locals before EXIT.
    # shellcheck disable=SC2064
    trap "$(printf 'rm -rf -- %q' "$stage")" EXIT
    if [[ -n $input ]]; then
        [[ -f $input && -r $input ]] || die 'Файл конфигурации не найден или недоступен.'
        [[ $(wc -c <"$input") -le 65536 ]] || die 'Конфиг слишком большой (максимум 64 KiB).'
        cp -- "$input" "$stage/source.conf"
    else
        say 'Вставьте AWG-конфиг. Для завершения — END отдельной строкой (ввод виден).'
        local finished=0
        while IFS= read -r line; do
            [[ $line != END ]] || { finished=1; break; }
            printf '%s\n' "$line" >>"$stage/source.conf"
            [[ $(wc -c <"$stage/source.conf") -le 65536 ]] || die 'Конфиг слишком большой.'
        done
        ((finished)) || die 'Ввод прерван: ожидается END. Профиль не создан.'
    fi
    [[ -s $stage/source.conf ]] || die 'Пустой конфиг'
    awk -f "$APP_DIR/lib/normalize.awk" "$stage/source.conf" >"$stage/awg.conf" || die 'Импорт отклонён. Профиль не создан.'
    chmod 600 "$stage"/*.conf
    hash=$(private_key_hash "$stage/awg.conf")
    for other in "$DATA_DIR"/profiles/*/profile.json; do
        [[ -f $other ]] || continue
        if [[ $(jq -r '.key_hash' "$other") == "$hash" ]]; then die 'Этот AWG-ключ уже используется другим профилем.'; fi
    done
    if [[ -z $port ]]; then
        port=$(allocate_port 11001 19999) || die 'Нет свободных SOCKS-портов'
    else
        if ! [[ $port =~ ^[1-9][0-9]{3,4}$ ]] || ((port < 1024 || port > 65535)); then
            die 'Порт должен быть от 1024 до 65535'
        fi
        port_available "$port" || die "Порт $port занят или зарезервирован"
    fi
    metrics=$(allocate_port 31001 39999 "$port") || die 'Нет свободного локального порта статистики'
    password=$(openssl rand -hex 24)
    jq -n --arg name "$name" --arg password "$password" --arg hash "$hash" \
        --arg image "$ENGINE_IMAGE" --argjson port "$port" --argjson metrics "$metrics" \
        '{name:$name,password:$password,key_hash:$hash,image:$image,port:$port,metrics_port:$metrics}' >"$stage/profile.json"
    cat "$stage/awg.conf" >"$stage/wireproxy.conf"
    printf '\n[Socks5]\nBindAddress = 0.0.0.0:%s\nUsername = %s\nPassword = %s\n' "$port" "$name" "$password" >>"$stage/wireproxy.conf"
    ensure_engine
    if ! docker run --rm --network host --user 0:0 --read-only --cap-drop ALL \
        --security-opt no-new-privileges:true --mount "type=bind,src=$stage/wireproxy.conf,dst=/etc/wireproxy/config.conf,readonly" \
        "$ENGINE_IMAGE" -n -c /etc/wireproxy/config.conf >"$stage/validation.log" 2>&1; then
        redact <"$stage/validation.log" >&2
        die 'Ядро отклонило конфиг. Профиль не создан.'
    fi
    rm -f "$stage/validation.log"
    write_compose "$name" "$dir" "$metrics" >"$stage/compose.json"
    mv -- "$stage" "$dir"
    if ! compose "$name" up -d --pull never; then
        say "Профиль сохранён, но запуск не удался. Проверьте logs $name и выполните start $name." >&2
        return 1
    fi
    say "Профиль $name создан. SOCKS-порт: $port. Данные: socks2awg show $name"
    say 'Если входящие соединения закрыты, откройте этот TCP-порт в фаерволле сервера/хостера.'
    # Allow the listener to start; a successful HTTP request is required for success.
    check_one "$name" 1 || rc=$?
    return "$rc"
)
check_one() {
    local name=$1 retry=${2:-0} result port password options
    profile_exists "$name"
    if [[ $(state "$name") != running ]]; then say "$name: контейнер не работает"; return 1; fi
    port=$(metadata "$name" '.port'); password=$(metadata "$name" '.password')
    options=$(printf 'proxy = "socks5h://127.0.0.1:%s"\nproxy-user = "%s:%s"\n' "$port" "$name" "$password")
    # Credentials go over stdin, not command arguments. Ignore ambient proxy variables.
    if result=$(printf '%s\n' "$options" | curl -q --config - --noproxy '' --fail --silent --show-error \
        --proto '=https' --connect-timeout 10 --max-time 20 --retry "$retry" --retry-connrefused --retry-delay 1 "$CHECK_URL" 2>&1); then
        # A malformed response must not inject escape sequences into the terminal.
        if [[ $result =~ ^[0-9a-fA-F:.]+$ && ${#result} -le 45 ]]; then
            say "$name: OK · внешний IP $result"; return 0
        fi
        say "$name: проверочный сервис вернул неожиданный ответ"; return 1
    fi
    say "$name: запрос через SOCKS не выполнен (туннель или проверочный сервис недоступен)."
    printf '%s\n' "$result" | redact
    return 1
}
check_profiles() {
    local name=${1:-} failed=0
    if [[ -n $name ]]; then check_one "$name"; return; fi
    while IFS= read -r name; do check_one "$name" || failed=1; done < <(profile_names)
    return "$failed"
}
lifecycle() (
    local action=$1 name=$2 port metrics
    lock_mutation
    profile_exists "$name"
    if [[ $action == start ]]; then
        if [[ $(state "$name") == running ]]; then say "$name уже запущен"; return 0; fi
        # Temporarily ignore this profile's own reservations, but check actual host sockets.
        port=$(metadata "$name" '.port'); metrics=$(metadata "$name" '.metrics_port')
        if ss -H -ltn | awk -v a=":$port" -v b=":$metrics" '$4 ~ (a "$") || $4 ~ (b "$") {found=1} END {exit !found}'; then
            die 'Один из портов профиля занят другим процессом.'
        fi
        compose "$name" up -d --pull never
    else
        compose "$name" stop
    fi
)
remove_profile() (
    local name=${1:-} confirm=${2:-} answer
    if (($# < 1 || $# > 2)) || [[ -n $confirm && $confirm != --yes ]]; then
        die 'Использование: socks2awg remove NAME [--yes]'
    fi
    profile_exists "$name"
    if [[ $confirm != --yes ]]; then
        [[ -t 0 ]] || die 'Для удаления без терминала укажите --yes.'
        read -r -p "Удалить $name вместе с конфигом и паролем? Введите имя профиля: " answer
        [[ $answer == "$name" ]] || { say 'Отменено'; return 0; }
    fi
    lock_mutation
    profile_exists "$name"
    compose "$name" down --remove-orphans || die 'Контейнер не удалён; файлы сохранены.'
    rm -rf -- "$DATA_DIR/profiles/$name"
    say "Профиль $name удалён"
)

stats_snapshot() {
    local selected=${1:-} names=() name raw docker_stats now started age status metrics_port values rx tx handshake cpu ram total_rx=0 total_tx=0
    if [[ -n $selected ]]; then profile_exists "$selected"; names=("$selected");
    else while IFS= read -r name; do names+=("$name"); done < <(profile_names); fi
    if ((${#names[@]} == 0)); then say 'Профилей пока нет'; return 0; fi
    local containers=()
    for name in "${names[@]}"; do
        [[ $(state "$name") != running ]] || containers+=("$(container_name "$name")")
    done
    docker_stats=''
    if ((${#containers[@]})); then
        docker_stats=$(docker stats --no-stream --format '{{json .}}' "${containers[@]}" 2>/dev/null || true)
    fi
    printf '%-20s %-7s %-12s %-12s %-12s %-10s %s\n' 'PROFILE' 'CPU' 'RAM' 'RX MiB' 'TX MiB' 'UPTIME' 'HANDSHAKE'
    now=$(date +%s)
    for name in "${names[@]}"; do
        status=$(state "$name")
        if [[ $status != running ]]; then printf '%-20s %s\n' "$name" "$status"; continue; fi
        cpu=$(printf '%s\n' "$docker_stats" | jq -rs --arg n "$(container_name "$name")" '[.[] | select(.Name==$n)][0].CPUPerc // "—"')
        ram=$(printf '%s\n' "$docker_stats" | jq -rs --arg n "$(container_name "$name")" '[.[] | select(.Name==$n)][0].MemUsage // "—" | split(" / ")[0]')
        started=$(docker inspect --format '{{.State.StartedAt}}' "$(container_name "$name")")
        age=$(date -d "$started" +%s 2>/dev/null || printf '%s' "$now")
        age=$(( (now - age) / 60 ))
        metrics_port=$(metadata "$name" '.metrics_port')
        if raw=$(curl -q --noproxy '*' --fail --silent --max-time 1 "http://127.0.0.1:$metrics_port/metrics"); then
            values=$(printf '%s\n' "$raw" | awk -F= '$1=="rx_bytes" && $2~/^[0-9]+$/ {rx+=$2; r=1} $1=="tx_bytes" && $2~/^[0-9]+$/ {tx+=$2; t=1} $1=="last_handshake_time_sec" && $2~/^[0-9]+$/ {hs=$2} END {if(r&&t) printf "%.0f %.0f %.0f",rx,tx,hs; else exit 1}') || values=''
        else values=''; fi
        if [[ -n $values ]]; then
            read -r rx tx handshake <<<"$values"
            total_rx=$((total_rx + rx)); total_tx=$((total_tx + tx))
            if ((handshake > 0)); then handshake="$((now - handshake))s ago"; else handshake='never'; fi
            rx=$(awk -v v="$rx" 'BEGIN {printf "%.2f",v/1048576}')
            tx=$(awk -v v="$tx" 'BEGIN {printf "%.2f",v/1048576}')
        else rx='—'; tx='—'; handshake='unavailable'; fi
        printf '%-20s %-7s %-12s %-12s %-12s %-10s %s\n' "$name" "$cpu" "$ram" "$rx" "$tx" "${age}m" "$handshake"
    done
    awk -v r="$total_rx" -v t="$total_tx" 'BEGIN {printf "Трафик доступных счётчиков: RX %.2f MiB / TX %.2f MiB\n",r/1048576,t/1048576}'
    say 'RX/TX — AWG-трафик с запуска ядра, включая служебные данные. Handshake не заменяет check.'
}
stats_command() {
    local selected='' watch=0 answer
    while (($#)); do
        case "$1" in
            --watch) watch=1 ;;
            -*) die "Неизвестный аргумент: $1" ;;
            *) [[ -z $selected ]] || die 'Укажите один профиль'; selected=$1 ;;
        esac
        shift
    done
    if ((watch)); then
        [[ -t 0 && -t 1 ]] || die '--watch требует терминал'
        while :; do
            printf '\033[2J\033[H'
            stats_snapshot "$selected"
            say 'Enter / 0 — назад. Обновление примерно каждые 3 секунды.'
            if read -r -t 3 answer; then return 0; fi
        done
    else stats_snapshot "$selected"; fi
}
