# ZAI-85: append to the inspected stock /etc/ufw/after.init, then make
# that existing root-owned file executable. Preserve its original contents.
# UFW may invoke start twice on reload; this mode is idempotent.
# With the verified MANAGE_BUILTINS=no, reload retains the mangle rule.
if [ "${1:-}" = start ]; then
    /usr/local/libexec/test-gateway-routes firewall
fi
