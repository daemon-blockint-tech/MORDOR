#!/bin/bash

MORDOR_BANNER=$(cat <<'BANNER'
╔══════════════════════════════════════════════════╗
║             MORDOR SANDBOX CONTAINER             ║
║   Malware Orchestration & Reverse Engineering    ║
║         Detection Operations Runtime             ║
╚══════════════════════════════════════════════════╝
BANNER
)

wait_for_network() {
    local retries=30
    local delay=2
    echo "[*] Waiting for network..."
    for i in $(seq 1 $retries); do
        if ip route get 1.1.1.1 &>/dev/null; then
            echo "[+] Network is ready"
            return 0
        fi
        sleep $delay
    done
    echo "[-] Network did not become ready within timeout"
    return 1
}

setup_iptables() {
    if command -v iptables &>/dev/null; then
        echo "[*] Setting up iptables rules..."
        iptables -F
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT DROP
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
        
        # Log dropped packets before they hit the default DROP policy
        iptables -A OUTPUT -j LOG --log-prefix "SANDBOX_DROP_OUT: "
        iptables -A INPUT -j LOG --log-prefix "SANDBOX_DROP_IN: "
        
        echo "[+] iptables rules applied"
    else
        echo "[-] iptables not available, skipping"
    fi
}

mount_volumes() {
    if [ -d /cases ]; then
        echo "[*] Mounting /cases"
    fi
    if [ -d /output ]; then
        echo "[*] Mounting /output"
    fi
}

echo "$MORDOR_BANNER"
echo "[*] MORDOR Sandbox $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "[*] Container PID: $$"

wait_for_network
setup_iptables
mount_volumes

if [ $# -eq 0 ]; then
    echo "[*] No command provided, sleeping indefinitely"
    exec sleep infinity
fi

echo "[*] Executing: $@"
exec "$@"
