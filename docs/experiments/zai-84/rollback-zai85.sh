#!/bin/sh
# Test ONLY. Restore ZAI-84 units while retaining ZAI-85 fail-closed hooks.
# sh rollback-zai85.sh --check: read-only prerequisites, never executes the hook.
# PASS is a point-in-time check, not rollback approval or proof of recovery.
set -eu
fail() { echo "Rollback preflight: $*" >&2; exit 1; }
case "$#:${1:-}" in 0:) check_only=no ;; 1:--check) check_only=yes ;; *) fail 'usage: rollback-zai85.sh [--check]' ;; esac
[ "$(hostname)" = Test ] || fail 'hostname must be Test'
cd /root/zai85 || fail 'missing /root/zai85'
for f in test-mihomo.service test-routing-guard.service test-route-restore.service docker-zai84.conf test-gateway-routes ufw-before.rules ufw-after.init config.sha256; do
    [ -f "backup/$f" ] || { echo "Missing backup: $f" >&2; exit 1; }
done
sha256sum -c backup/config.sha256 >/dev/null 2>&1 || fail 'backup configuration checksum failed'
for unit in docker.service ssh.service test-mihomo.service test-routing-guard.service test-route-restore.service test-awg-return.service; do
    [ "$(systemctl show "$unit" -p LoadState --value)" = loaded ] || fail "unit missing/unreadable: $unit"
done
[ -x /usr/local/libexec/test-gateway-routes ] || fail 'routing hook missing/not executable'
[ -f /etc/ufw/after.init ] && [ -f /etc/ufw/before.rules ] || fail 'retained UFW files missing'
[ "$(docker network inspect -f '{{.Driver}} {{(index .IPAM.Config 0).Subnet}} {{.EnableIPv6}}' bridge)" = 'bridge 172.17.0.0/16 false' ] || fail 'unexpected/unreadable Docker bridge'
for entry in 'awg-server-test 172.17.0.2 unless-stopped' 'awg-client-test 172.17.0.3 no'; do
    set -- $entry
    [ "$(docker inspect -f '{{.HostConfig.NetworkMode}} {{.NetworkSettings.Networks.bridge.IPAddress}} {{.HostConfig.RestartPolicy.Name}}' "$1")" = "bridge $2 $3" ] || fail "missing container or network/IP/restart mismatch: $1"
done
rules=$(iptables -w 5 -t mangle -S FORWARD) || fail 'cannot read independent firewall protection'
first=$(printf '%s\n' "$rules" | sed -n '/^-A /{p;q;}')
[ "$first" = '-A FORWARD -s 10.30.0.0/24 ! -o mitun0 -m comment --comment ZAI85-client-failclosed -j DROP' ] || fail 'independent DROP missing or not first'
# No hook execution: guard/tun/docker modes write routing/firewall state.
if [ "$check_only" = yes ]; then echo 'Rollback preflight: PASS (read-only; not live rollback validation)'; exit 0; fi
systemctl disable --now test-awg-return.service
# Release both dynamic addresses; keep the synthetic client stopped on daemon start.
docker update --restart=no awg-client-test
docker stop --timeout 5 awg-client-test awg-server-test
cp -a backup/test-mihomo.service backup/test-routing-guard.service backup/test-route-restore.service /etc/systemd/system/
cp -a backup/docker-zai84.conf /etc/systemd/system/docker.service.d/zai84.conf
# Keep the hardened route hook and UFW files together; never downgrade the guard.
rm -f /etc/systemd/system/test-awg-return.service
systemctl daemon-reload
/usr/local/libexec/test-gateway-routes guard
ufw reload
systemctl reset-failed test-mihomo.service docker.service
# Start while the daemon is available: unless-stopped must not remain manually
# stopped when the restored Docker post-start hook waits for this server.
docker start awg-server-test
[ "$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' awg-server-test)" = '172.17.0.2' ]
systemctl restart docker.service
docker start awg-client-test
[ "$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' awg-client-test)" = '172.17.0.3' ]
# Retained hardened Docker hook requires client restart=no and starts it itself.
/usr/local/libexec/test-gateway-routes docker
systemctl restart test-mihomo.service
docker exec awg-client-test wget -q -O- -T 25 http://1.1.1.1/cdn-cgi/trace | grep '^warp=on$'
# Independent fail-closed protection remains installed after recovery.
sha256sum -c backup/config.sha256
systemctl is-active docker test-mihomo ssh
