#!/bin/sh
# Test ONLY. Restore the backed-up ZAI-84 deployment, not a production baseline.
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
cp -a backup/test-gateway-routes /usr/local/libexec/test-gateway-routes
cp -a backup/ufw-before.rules /etc/ufw/before.rules
cp -a backup/ufw-after.init /etc/ufw/after.init
rm -f /etc/systemd/system/test-awg-return.service
systemctl daemon-reload
/usr/local/libexec/test-gateway-routes guard
ufw reload
systemctl reset-failed test-mihomo.service docker.service
systemctl restart docker.service
docker start awg-server-test
[ "$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' awg-server-test)" = '172.17.0.2' ]
docker start awg-client-test
[ "$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' awg-client-test)" = '172.17.0.3' ]
docker update --restart=unless-stopped awg-client-test
/usr/local/libexec/test-gateway-routes docker
systemctl restart test-mihomo.service
docker exec awg-client-test wget -q -O- -T 25 http://1.1.1.1/cdn-cgi/trace | grep '^warp=on$'
# Remove the ZAI-85 protection only after the original deployment is healthy.
if iptables -w 5 -t mangle -C FORWARD -s 10.30.0.0/24 ! -o mitun0 -m comment --comment ZAI85-client-failclosed -j DROP 2>/dev/null; then
    iptables -w 5 -t mangle -D FORWARD -s 10.30.0.0/24 ! -o mitun0 -m comment --comment ZAI85-client-failclosed -j DROP
fi
sha256sum -c backup/config.sha256
systemctl is-active docker test-mihomo ssh
