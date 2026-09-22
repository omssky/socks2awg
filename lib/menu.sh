# shellcheck shell=bash
pause_menu() { read -r -p 'Enter — продолжить' _ || true; }
run_action() {
    # A separate Bash process preserves errexit even when the menu catches failure.
    if "$APP_DIR/socks2awg" "$@"; then :; else say 'Операция завершилась с ошибкой.'; fi
    pause_menu
}
add_menu() {
    local name method file port
    while :; do
        read -r -p 'Название профиля (латиница, например agent1): ' name || return 0
        if valid_name "$name"; then break; fi
        name_error "$name"
    done
    say '1. Вставить AWG-конфиг'
    say '2. Указать файл на сервере'
    say '0. Назад'
    read -r -p 'Выбор: ' method || return 0
    case "$method" in
        0) return ;;
        1) file='' ;;
        2) read -r -p 'Путь к .conf: ' file || return 0; [[ -n $file ]] || return 0 ;;
        *) say 'Неизвестный пункт'; return ;;
    esac
    read -r -p 'SOCKS-порт (Enter — автоматически): ' port || return 0
    local args=(add "$name")
    [[ -z $file ]] || args+=("$file")
    [[ -z $port ]] || args+=(--port "$port")
    run_action "${args[@]}"
}
profile_menu() {
    local name=$1 choice status
    while [[ -f $DATA_DIR/profiles/$name/profile.json ]]; do
        status=$(state "$name")
        printf '\n%s · SOCKS :%s · %s\n\n' "$name" "$(metadata "$name" '.port')" "$status"
        say '1. Данные подключения (покажет пароль)'
        say '2. Статистика'
        say '3. Проверить подключение'
        say '4. Последние логи'
        if [[ $status == running ]]; then say '5. Остановить'; else say '5. Запустить'; fi
        say '6. Удалить профиль'
        say '0. Назад'
        read -r -p 'Выбор: ' choice || return 0
        case "$choice" in
            1) run_action show "$name" ;;
            2) stats_command "$name" --watch ;;
            3) run_action check "$name" ;;
            4) run_action logs "$name" ;;
            5) if [[ $status == running ]]; then run_action stop "$name"; else run_action start "$name"; fi ;;
            6) run_action remove "$name" ;;
            0) return ;;
            *) say 'Неизвестный пункт' ;;
        esac
    done
}
select_profile() {
    local name choice i=0 names=()
    while IFS= read -r name; do
        names+=("$name"); i=$((i + 1))
        printf '%2s. %-32s :%-6s %s\n' "$i" "$name" "$(metadata "$name" '.port')" "$(state "$name")"
    done < <(profile_names)
    if ((i == 0)); then say 'Профилей пока нет'; return; fi
    read -r -p 'Номер или имя профиля (0 — назад): ' choice || return 0
    [[ $choice != 0 ]] || return 0
    if [[ $choice =~ ^[1-9][0-9]{0,2}$ ]] && ((choice <= i)); then
        name=${names[$((choice - 1))]}
    elif valid_name "$choice" && [[ -f $DATA_DIR/profiles/$choice/profile.json ]]; then name=$choice
    else say 'Профиль не найден'; return; fi
    profile_menu "$name"
}
menu() {
    [[ -t 0 && -t 1 ]] || die 'Меню требует терминал. Справка: socks2awg help'
    # Host setting is also protected from concurrent first runs.
    (lock_mutation; ensure_host)
    local choice
    while :; do
        printf '\nsocks2awg %s\n\n' "$(cat "$APP_DIR/VERSION")"
        say '1. Добавить профиль'
        say '2. Выбрать профиль'
        say '3. Статистика всех профилей'
        say '4. Проверить все подключения'
        say '0. Выход'
        read -r -p 'Выбор: ' choice || return 0
        case "$choice" in
            1) add_menu ;;
            2) select_profile ;;
            3) stats_command --watch ;;
            4) run_action check ;;
            0) return ;;
            *) say 'Неизвестный пункт' ;;
        esac
    done
}
