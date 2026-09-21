# Treat imported configuration strictly as data. Never run wg-quick hooks.
function fail(message) {
    print "Строка " NR ": " message > "/dev/stderr"
    failed = 1
    exit 1
}
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function finish_interface() {
    if (!seen["Interface:privatekey"] || !seen["Interface:address"])
        fail("нужны PrivateKey и Address в [Interface]")
    if (!seen["Interface:dns"]) print "DNS = 1.1.1.1"
    # Each client gets an ephemeral UDP port, avoiding collisions in host networking.
    print "ListenPort = 0"
}
BEGIN {
    interface_keys = " privatekey address dns mtu listenport jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 headerprotectionkey contentpaddingaddition rekeyaftertime rekeytimeout rejectaftertime keepalivetimeout maxhandshakeattempts randomtrailers disablecookies "
    peer_keys = " publickey presharedkey endpoint allowedips persistentkeepalive "
}
{
    sub(/\r$/, "")
    line = trim($0)
    if (line == "" || line ~ /^[#;]/) next
    # Inline comments are supported only after whitespace, not inside values.
    sub(/[ \t]+[#;].*$/, "", line)
    if (line ~ /^\[/) {
        if (tolower(line) == "[interface]" && !interface_count && !peer_count) {
            interface_count++; section = "Interface"; print "[Interface]"; next
        }
        if (tolower(line) == "[peer]" && interface_count && !peer_count) {
            finish_interface(); peer_count++; section = "Peer"; print "\n[Peer]"; next
        }
        fail("поддерживается один [Interface] и один [Peer]; дополнительные секции запрещены")
    }
    if (section == "" || !index(line, "=")) fail("ожидается параметр внутри секции")
    key = trim(substr(line, 1, index(line, "=") - 1))
    value = trim(substr(line, index(line, "=") + 1))
    lower = tolower(key)
    if (lower !~ /^[a-z][a-z0-9]*$/) fail("некорректное имя параметра")
    if (lower ~ /^(preup|postup|predown|postdown)$/) fail("команды wg-quick не поддерживаются: " key)
    if (value == "" || value ~ /[[:cntrl:]]/ || value ~ /[\\`$]/) fail("пустое или неподдерживаемое значение параметра " key)
    if (seen[section ":" lower]++) fail("повторный параметр " key)
    # These are wg-quick host settings, not userspace tunnel settings.
    if (section == "Interface" && (lower == "table" || lower == "saveconfig")) next
    allowed = (section == "Interface" ? interface_keys : peer_keys)
    if (!index(allowed, " " lower " ")) fail("неподдерживаемый параметр " key)
    if (section == "Interface" && lower == "listenport") next
    if (section == "Peer" && lower == "allowedips") {
        count = split(value, nets, ",")
        for (i = 1; i <= count; i++) if (trim(nets[i]) == "0.0.0.0/0") full_route = 1
    }
    print key " = " value
}
END {
    if (failed) exit 1
    if (!interface_count || !peer_count) fail("нужны секции [Interface] и [Peer]")
    if (!seen["Peer:publickey"] || !seen["Peer:endpoint"] || !full_route)
        fail("нужны PublicKey, Endpoint и AllowedIPs с 0.0.0.0/0 в [Peer]")
}
