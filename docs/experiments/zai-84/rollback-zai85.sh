#!/bin/sh
# Test ONLY. Restore ZAI-84 units while retaining ZAI-85 fail-closed hooks.
set -eu
[ "$(hostname)" = Test ]
cd /root/zai85
for f in test-mihomo.service test-routing-guard.service test-route-restore.service docker-zai84.conf test-gateway-routes ufw-before.rules ufw-after.init config.sha256; do
    [ -f "backup/$f" ] || { echo "Missing backup: $f" >&2; exit 1; }
done
sha256sum -c backup/config.sha256
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
