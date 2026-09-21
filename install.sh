#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
REPOSITORY='omssky/socks2awg'
REF=${SOCKS2AWG_REF:-master}
INSTALL_ROOT='/opt/socks2awg'
INSTALL_DOCKER=0
FROM=''
fail() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
while (($#)); do
    case "$1" in
        --install-docker) INSTALL_DOCKER=1; shift ;;
        --from) (($# >= 2)) || fail 'После --from нужен путь'; FROM=$2; shift 2 ;;
        --help|-h) printf 'sudo bash install.sh [--install-docker] [--from /path/to/checkout]\n'; exit 0 ;;
        *) fail "Неизвестный аргумент: $1" ;;
    esac
done
[[ $(uname -s) == Linux && $EUID == 0 ]] || fail 'Запустите установщик от root на Ubuntu/Debian.'
# shellcheck source=/dev/null
source /etc/os-release
case "${ID:-}" in ubuntu|debian) ;; *) fail 'Пока поддерживаются Ubuntu и Debian.' ;; esac
command -v apt-get >/dev/null || fail 'Нужен apt-get'
exec 9>/run/lock/socks2awg-install.lock
flock -w 30 9 || fail 'Уже выполняется другой установщик'

work=$(mktemp -d)
staged=''
trap 'rm -rf -- "$work"; if [[ -n $staged ]]; then rm -rf -- "$staged"; fi' EXIT

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl jq openssl util-linux iproute2 tar coreutils

if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    # Existing Docker installations are not replaced automatically.
    if command -v docker >/dev/null; then
        fail 'Docker уже установлен, но нет Compose v2. Установите совместимый Compose plugin и повторите запуск.'
    fi
    if ((INSTALL_DOCKER == 0)); then
        if [[ -t 0 ]]; then
            read -r -p 'Docker не найден. Установить Docker Engine через get.docker.com? [y/N] ' answer
            [[ $answer == y || $answer == Y ]] || fail 'Установите Docker и повторите запуск.'
        else fail 'Нет Docker. Повторите с --install-docker или установите его самостоятельно.'; fi
    fi
    curl -fsSL --retry 3 https://get.docker.com -o "$work/get-docker.sh" \
        || fail 'Не удалось скачать установщик Docker.'
    sh "$work/get-docker.sh" || fail 'Установка Docker завершилась с ошибкой.'
fi
docker info >/dev/null 2>&1 || fail 'Docker установлен, но daemon недоступен. Запустите его и повторите установку.'
docker compose version >/dev/null 2>&1 || fail 'Требуется Docker Compose v2'

if [[ -n $FROM ]]; then
    [[ -d $FROM ]] || fail 'Локальная папка не найдена'
    bundle=$(cd -- "$FROM" && pwd)
    revision="local-$(date +%Y%m%d%H%M%S)-$$"
else
    [[ $REF =~ ^[a-zA-Z0-9._/-]+$ && $REF != *..* ]] || fail 'Некорректный SOCKS2AWG_REF'
    revision=$(curl -fsSL --retry 3 "https://api.github.com/repos/$REPOSITORY/commits/$REF" | jq -er '.sha')
    [[ $revision =~ ^[a-f0-9]{40}$ ]] || fail 'Не удалось определить commit репозитория'
    curl -fsSL --retry 3 "https://codeload.github.com/$REPOSITORY/tar.gz/$revision" -o "$work/source.tar.gz"
    mkdir "$work/source"
    tar --extract --gzip --file "$work/source.tar.gz" --directory "$work/source" --strip-components=1 --no-same-owner
    bundle=$work/source
fi
for required in VERSION socks2awg lib/core.sh lib/menu.sh lib/normalize.awk; do
    [[ -f $bundle/$required ]] || fail "В пакете отсутствует $required"
done
for script in "$bundle/socks2awg" "$bundle/lib/core.sh" "$bundle/lib/menu.sh"; do
    bash -n "$script"
done
version=$(cat "$bundle/VERSION")
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Некорректная версия пакета'
mkdir -p "$INSTALL_ROOT/versions" /var/lib/socks2awg/profiles
chmod 700 "$INSTALL_ROOT" "$INSTALL_ROOT/versions" /var/lib/socks2awg /var/lib/socks2awg/profiles
staged=$(mktemp -d "$INSTALL_ROOT/versions/.install.XXXXXX")
cp -R "$bundle/socks2awg" "$bundle/lib" "$bundle/VERSION" "$staged/"
chmod 755 "$staged/socks2awg"
# Pull before switching the installed command. Existing containers are untouched.
image='ghcr.io/artem-russkikh/wireproxy-awg@sha256:55346f15716f09428363d8b990042ee3bd40c23ef934c5d9ab916ac1a0acc788'
if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker pull "$image" || fail 'Не удалось скачать образ wireproxy-awg.'
fi
release="$INSTALL_ROOT/versions/$revision"
if [[ -d $release ]]; then rm -rf -- "$staged"; else mv -- "$staged" "$release"; fi
staged=''
ln -s "$release" "$INSTALL_ROOT/.current-$$"
mv -Tf "$INSTALL_ROOT/.current-$$" "$INSTALL_ROOT/current"
mkdir -p /usr/local/bin
wrapper=$(mktemp /usr/local/bin/.socks2awg.XXXXXX)
printf '#!/usr/bin/env bash\nexec /opt/socks2awg/current/socks2awg "$@"\n' >"$wrapper"
chmod 755 "$wrapper"
mv -f "$wrapper" /usr/local/bin/socks2awg
printf '\nsocks2awg %s установлен. Запустите: sudo socks2awg\n' "$version"
printf 'Профили сохранены. Утилита не настраивает SSH/UFW.\n'
