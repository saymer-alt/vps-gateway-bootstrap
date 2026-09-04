# VPS Snapshot v2: hungry-boyd.1cent.network
_Дата: 2026-09-04 12:04:22 UTC_
_Скрипт: vps-snapshot-v2.sh v2.0_

## 1. Система


### OS

```
NAME="Ubuntu"
VERSION="24.04.4 LTS (Noble Numbat)"
ID=ubuntu
```

```
Linux hungry-boyd.1cent.network 6.8.0-111-generic #111-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 11 23:16:02 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

```
hungry-boyd.1cent.network
```

```
 12:04:22 up 1 day, 21:17,  1 user,  load average: 0.19, 0.15, 0.10
```

```
                Time zone: Etc/UTC (UTC, +0000)
```

```
LANG=en_US.UTF-8
LANGUAGE=
LC_CTYPE="en_US.UTF-8"
LC_NUMERIC="en_US.UTF-8"
LC_TIME="en_US.UTF-8"
```


### Виртуализация

```
kvm
```

```
KVM
```

```
Red Hat
```

```
нет dmesg
```


## 2. CPU / RAM / Disk

```
Architecture:                            x86_64
CPU(s):                                  1
Model name:                              AMD Ryzen 9 7950X3D 16-Core Processor
Thread(s) per core:                      1
Core(s) per socket:                      1
Virtualization:                          AMD-V
Virtualization type:                     full
```

```
               total        used        free      shared  buff/cache   available
Mem:           961Mi       640Mi       156Mi       3.1Mi       361Mi       320Mi
Swap:          1.5Gi       183Mi       1.3Gi
```

```
NAME      TYPE SIZE   USED PRIO
/swapfile file 1.5G 183.8M   -2
```

```
Filesystem      Size  Used Avail Use% Mounted on
/dev/vda2       9.8G  6.6G  2.8G  71% /
```


## 3. Пакеты и версии


### Ключевые пакеты

```
ca-certificates 20260601~24.04.1
curl 8.5.0-2ubuntu10.13
fail2ban 1.0.2-3ubuntu0.1
iproute2 6.1.0-1ubuntu6.4
iptables 1.8.10-3ubuntu2
mita 3.36.0
nftables 1.0.9-1ubuntu0.1
systemd 255.4-1ubuntu8.17
ufw 0.36.2-6
```


### Альтернативы iptables

```
iptables - auto mode
  link best version is /usr/sbin/iptables-nft
  link currently points to /usr/sbin/iptables-nft
  link iptables is /usr/sbin/iptables
  slave iptables-restore is /usr/sbin/iptables-restore
нет alternatives
```


### Репозитории

```
нет apt-cache
```


## 4. Сеть

```
95.85.224.104```

```
нет IPv6
```

```
127.0.0.1/8 lo
95.85.224.104/32 ens3
198.18.0.0/30 tun-mihomo
172.16.0.2/32 wg0
172.29.172.1/24 amn0
172.17.0.1/16 docker0
```

```
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
ens3             UP             52:54:00:ea:ed:d0 <BROADCAST,MULTICAST,UP,LOWER_UP> 
tun-mihomo       UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> 
wg0              UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> 
amn0             UP             9e:ea:e8:6a:23:9f <BROADCAST,MULTICAST,UP,LOWER_UP> 
docker0          UP             26:ea:db:2a:ea:03 <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth704d8a9@if2  UP             3e:3e:7d:b8:52:16 <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth87a2029@if3  UP             e2:06:02:08:e4:20 <BROADCAST,MULTICAST,UP,LOWER_UP> 
```


### Детали интерфейсов

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0  allmulti 0 minmtu 0 maxmtu 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT group default qlen 1000
    link/ether 52:54:00:ea:ed:d0 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 parentbus virtio parentdev virtio1 
    altname enp0s3
3: tun-mihomo: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 5000
    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    tun type tun pi off vnet_hdr on persist off addrgenmode random numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 
4: wg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 500
    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    tun type tun pi off vnet_hdr on persist off addrgenmode random numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 
5: amn0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether 9e:ea:e8:6a:23:9f brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.9e:ea:e8:6a:23:9f designated_root 8000.9e:ea:e8:6a:23:9f root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer  276.50 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
6: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether 26:ea:db:2a:ea:03 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.26:ea:db:2a:ea:3 designated_root 8000.26:ea:db:2a:ea:3 root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer   79.91 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
7: veth704d8a9@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master amn0 state UP mode DEFAULT group default 
    link/ether 3e:3e:7d:b8:52:16 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 
    veth 
    bridge_slave state forwarding priority 32 cost 2 hairpin off guard off root_block off fastleave off learning on flood on port_id 0x8001 port_no 0x1 designated_port 32769 designated_cost 0 designated_bridge 8000.9e:ea:e8:6a:23:9f designated_root 8000.9e:ea:e8:6a:23:9f hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on bcast_flood on mcast_to_unicast off neigh_suppress off group_fwd_mask 0 group_fwd_mask_str 0x0 vlan_tunnel off isolated off locked off addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
8: veth87a2029@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default 
    link/ether e2:06:02:08:e4:20 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 
    veth 
    bridge_slave state forwarding priority 32 cost 2 hairpin off guard off root_block off fastleave off learning on flood on port_id 0x8001 port_no 0x1 designated_port 32769 designated_cost 0 designated_bridge 8000.26:ea:db:2a:ea:3 designated_root 8000.26:ea:db:2a:ea:3 hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on bcast_flood on mcast_to_unicast off neigh_suppress off group_fwd_mask 0 group_fwd_mask_str 0x0 vlan_tunnel off isolated off locked off addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
```


### Интерфейсы WG/TUN

```
```

```
3: tun-mihomo: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 5000
    link/none 
4: wg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 500
    link/none 
```


## 5. MTU

```
amn0: 1500
docker0: 1500
ens3: 1500
lo: 65536
tun-mihomo: 1420
veth704d8a9: 1500
veth87a2029: 1500
wg0: 1420
```

```
нет mtu
```


## 6. Routing / Policy Routing

```
0:	from all lookup local
40:	from all fwmark 0x88 lookup main
100:	from 172.29.172.0/24 lookup mihomo
32766:	from all lookup main
32767:	from all lookup default
```

```
default via 10.0.0.1 dev ens3 onlink 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.29.172.0/24 dev amn0 proto kernel scope link src 172.29.172.1 
198.18.0.0/30 dev tun-mihomo proto kernel scope link src 198.18.0.0 
198.18.0.0/16 dev tun-mihomo scope link 
```

```
default dev tun-mihomo table mihomo scope link 
default via 10.0.0.1 dev ens3 onlink 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.29.172.0/24 dev amn0 proto kernel scope link src 172.29.172.1 
198.18.0.0/30 dev tun-mihomo proto kernel scope link src 198.18.0.0 
198.18.0.0/16 dev tun-mihomo scope link 
local 95.85.224.104 dev ens3 table local proto kernel scope host src 95.85.224.104 
broadcast 95.85.224.104 dev ens3 table local proto kernel scope link src 95.85.224.104 
local 127.0.0.0/8 dev lo table local proto kernel scope host src 127.0.0.1 
local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1 
broadcast 127.255.255.255 dev lo table local proto kernel scope link src 127.0.0.1 
local 172.16.0.2 dev wg0 table local proto kernel scope host src 172.16.0.2 
local 172.17.0.1 dev docker0 table local proto kernel scope host src 172.17.0.1 
broadcast 172.17.255.255 dev docker0 table local proto kernel scope link src 172.17.0.1 
local 172.29.172.1 dev amn0 table local proto kernel scope host src 172.29.172.1 
broadcast 172.29.172.255 dev amn0 table local proto kernel scope link src 172.29.172.1 
local 198.18.0.0 dev tun-mihomo table local proto kernel scope host src 198.18.0.0 
broadcast 198.18.0.3 dev tun-mihomo table local proto kernel scope link src 198.18.0.0 
default dev wg0 table 10230 metric 1024 pref medium
2606:4700:110:8116:f516:6c27:6074:5edd dev wg0 proto kernel metric 256 pref medium
fe80::/64 dev ens3 proto kernel metric 256 pref medium
fe80::/64 dev tun-mihomo proto kernel metric 256 pref medium
fe80::/64 dev wg0 proto kernel metric 256 pref medium
fe80::/64 dev veth704d8a9 proto kernel metric 256 pref medium
fe80::/64 dev amn0 proto kernel metric 256 pref medium
fe80::/64 dev veth87a2029 proto kernel metric 256 pref medium
fe80::/64 dev docker0 proto kernel metric 256 pref medium
local ::1 dev lo table local proto kernel metric 0 pref medium
local 2606:4700:110:8116:f516:6c27:6074:5edd dev wg0 table local proto kernel metric 0 pref medium
local fe80::24ea:dbff:fe2a:ea03 dev docker0 table local proto kernel metric 0 pref medium
```

```
1.1.1.1 via 10.0.0.1 dev ens3 src 95.85.224.104 uid 0 
    cache 
```

```
нет IPv6 route
```


## 7. iptables / nftables

```
iptables v1.8.10 (nf_tables)
```

```
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER
-N DOCKER-BRIDGE
-N DOCKER-CT
-N DOCKER-FORWARD
-N DOCKER-INTERNAL
-N DOCKER-USER
-N f2b-sshd
-N ufw-after-forward
-N ufw-after-input
-N ufw-after-logging-forward
-N ufw-after-logging-input
-N ufw-after-logging-output
-N ufw-after-output
-N ufw-before-forward
-N ufw-before-input
-N ufw-before-logging-forward
-N ufw-before-logging-input
-N ufw-before-logging-output
-N ufw-before-output
-N ufw-logging-allow
-N ufw-logging-deny
-N ufw-not-local
-N ufw-reject-forward
-N ufw-reject-input
-N ufw-reject-output
-N ufw-skip-to-policy-forward
-N ufw-skip-to-policy-input
-N ufw-skip-to-policy-output
-N ufw-track-forward
-N ufw-track-input
-N ufw-track-output
-N ufw-user-forward
-N ufw-user-input
-N ufw-user-limit
-N ufw-user-limit-accept
-N ufw-user-logging-forward
-N ufw-user-logging-input
-N ufw-user-logging-output
-N ufw-user-output
-A INPUT -p tcp -m multiport --dports 22,2222 -j f2b-sshd
-A INPUT -j ufw-before-logging-input
-A INPUT -j ufw-before-input
-A INPUT -j ufw-after-input
-A INPUT -j ufw-after-logging-input
-A INPUT -j ufw-reject-input
-A INPUT -j ufw-track-input
-A FORWARD -s 172.29.172.0/24 -j ACCEPT
нет iptables
```

```
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N DOCKER
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.29.172.0/24 ! -o amn0 -j MASQUERADE
-A POSTROUTING -o tun-mihomo -j MASQUERADE
-A DOCKER ! -i amn0 -p udp -m udp --dport 39551 -j DNAT --to-destination 172.29.172.2:39551
```

```
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-A PREROUTING -s 172.29.172.0/24 -p udp -m udp --sport 39551 -j MARK --set-xmark 0x88/0xffffffff
-A FORWARD -s 172.29.172.0/24 -o tun-mihomo -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

```
nftables v1.0.9 (Old Doc Yak #3)
```

```
table ip filter {
	chain ufw-before-logging-input {
	}

	chain ufw-before-logging-output {
	}

	chain ufw-before-logging-forward {
	}

	chain ufw-before-input {
		iifname "lo" counter packets 6564004 bytes 3972203668 accept
		ct state related,established counter packets 15839124 bytes 14042396860 accept
		ct state invalid counter packets 2916 bytes 156841 jump ufw-logging-deny
		ct state invalid counter packets 2916 bytes 156841 drop
		ip protocol icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		ip protocol icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		ip protocol icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 2107 bytes 122780 accept
		udp sport 67 udp dport 68 counter packets 0 bytes 0 accept
		counter packets 77394 bytes 24097017 jump ufw-not-local
		ip daddr 224.0.0.251 udp dport 5353 counter packets 0 bytes 0 accept
		ip daddr 239.255.255.250 udp dport 1900 counter packets 0 bytes 0 accept
		counter packets 77394 bytes 24097017 jump ufw-user-input
	}

	chain ufw-before-output {
		oifname "lo" counter packets 6564004 bytes 3972203668 accept
		ct state related,established counter packets 17322861 bytes 8491921102 accept
		counter packets 564246 bytes 34692656 jump ufw-user-output
	}

	chain ufw-before-forward {
		ct state related,established counter packets 0 bytes 0 accept
		ip protocol icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		ip protocol icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		ip protocol icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 accept
		counter packets 160 bytes 6400 jump ufw-user-forward
	}

	chain ufw-after-input {
		udp dport 137 counter packets 18 bytes 1402 jump ufw-skip-to-policy-input
		udp dport 138 counter packets 0 bytes 0 jump ufw-skip-to-policy-input
		tcp dport 139 counter packets 22 bytes 1236 jump ufw-skip-to-policy-input
		tcp dport 445 counter packets 98 bytes 4988 jump ufw-skip-to-policy-input
		udp dport 67 counter packets 0 bytes 0 jump ufw-skip-to-policy-input
		udp dport 68 counter packets 2 bytes 56 jump ufw-skip-to-policy-input
		fib daddr type broadcast counter packets 0 bytes 0 jump ufw-skip-to-policy-input
	}

	chain ufw-after-output {
	}

	chain ufw-after-forward {
	}

	chain ufw-after-logging-input {
		limit rate 3/minute burst 10 packets counter packets 8148 bytes 593947 log prefix "[UFW BLOCK] "
	}

	chain ufw-after-logging-output {
	}

	chain ufw-after-logging-forward {
		limit rate 3/minute burst 10 packets counter packets 136 bytes 5440 log prefix "[UFW BLOCK] "
	}

	chain ufw-reject-input {
	}

	chain ufw-reject-output {
	}

	chain ufw-reject-forward {
	}

	chain ufw-track-input {
	}

нет nft ruleset
```


## 8. Sysctl

```
net.ipv4.ip_forward                           = 1
net.ipv6.conf.all.forwarding                  = 0
net.ipv4.tcp_congestion_control               = bbr
net.core.default_qdisc                        = fq
net.ipv4.tcp_fastopen                         = 3
net.ipv4.tcp_tw_reuse                         = 1
net.ipv4.icmp_echo_ignore_all                 = 0
net.ipv6.conf.all.disable_ipv6                = 0
net.core.rmem_max                             = 134217728
net.core.wmem_max                             = 134217728
net.ipv4.tcp_rmem                             = 4096	87380	134217728
net.ipv4.tcp_wmem                             = 4096	65536	134217728
net.core.somaxconn                            = 4096
net.ipv4.ip_local_port_range                  = 10000	39999
net.ipv4.ip_local_reserved_ports              = 
vm.swappiness                                 = 10
vm.overcommit_memory                          = 1
net.ipv4.conf.all.rp_filter                   = 0
net.ipv4.tcp_max_syn_backlog                  = 4096
net.netfilter.nf_conntrack_max                = 8192
net.netfilter.nf_conntrack_count              = 964
```

### Кастомные sysctl.d

- `/etc/sysctl.d/10-bufferbloat.conf` (8 строк)
- `/etc/sysctl.d/10-console-messages.conf` (3 строк)
- `/etc/sysctl.d/10-ipv6-privacy.conf` (12 строк)
- `/etc/sysctl.d/10-kernel-hardening.conf` (25 строк)
- `/etc/sysctl.d/10-magic-sysrq.conf` (26 строк)
- `/etc/sysctl.d/10-map-count.conf` (3 строк)
- `/etc/sysctl.d/10-network-security.conf` (6 строк)
- `/etc/sysctl.d/10-ptrace.conf` (22 строк)
- `/etc/sysctl.d/10-zeropage.conf` (9 строк)
- `/etc/sysctl.d/99-amnezia.conf` (3 строк)
- `/etc/sysctl.d/99-amnezia-mihomo.conf` (3 строк)
- `/etc/sysctl.d/99-sysctl.conf` (116 строк)

## 9. DNS

```
nameserver 1.1.1.1
nameserver 8.8.8.8
options timeout:2 attempts:3
```

```
нет resolvectl
```

```
нет resolvectl dns
```

```
○ systemd-resolved.service - Network Name Resolution
     Loaded: loaded (/usr/lib/systemd/system/systemd-resolved.service; disabled; preset: enabled)
     Active: inactive (dead)
       Docs: man:systemd-resolved.service(8)
             man:org.freedesktop.resolve1(5)
             https://www.freedesktop.org/wiki/Software/systemd/writing-network-configuration-managers
             https://www.freedesktop.org/wiki/Software/systemd/writing-resolver-clients
нет resolved
```

```
UNCONN 0      0                  *:53               *:*    users:(("mihomo",pid=934,fd=8))           
```


## 10. Безопасность


### SSH

```
Port 2222
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
```

```
LISTEN 0      128          0.0.0.0:2222       0.0.0.0:*    users:(("sshd",pid=247494,fd=3))          
LISTEN 0      128             [::]:2222          [::]:*    users:(("sshd",pid=247494,fd=4))          
```


### UFW

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW IN    Anywhere                   # SSH Управление
443/tcp                    ALLOW IN    Anywhere                   # TeleMT
39551/udp                  ALLOW IN    Anywhere                   # AWG 2.0
50000:52000/tcp            ALLOW IN    Anywhere                   # Mieru
8443/tcp                   ALLOW IN    Anywhere                   # XHTTP Reality
2053/tcp                   ALLOW IN    Anywhere                   # VLESS Reality
2083/udp                   ALLOW IN    Anywhere                   # Hysteria2
2096/tcp                   ALLOW IN    Anywhere                   # VLESS gRPC Reality
2443/tcp                   ALLOW IN    Anywhere                   # EE-Reality-TCP-2443
7443/tcp                   ALLOW IN    Anywhere                   # EE-XHTTP-7443
80/tcp                     ALLOW IN    Anywhere                   # acme
9443/tcp                   ALLOW IN    Anywhere                   # Trojan TLS
50000:52000/udp            ALLOW IN    Anywhere                   # Mieru UDP
Anywhere (v6)              DENY IN     Anywhere (v6)              # Block IPv6 inbound (defense in depth)
50000:52000/udp (v6)       ALLOW IN    Anywhere (v6)              # Mieru UDP

```


### Fail2ban

```
active
Status
|- Number of jail:	2
`- Jail list:	3x-ipl, sshd
```


### AppArmor / SELinux

```
apparmor module is loaded.
128 profiles are loaded.
34 profiles are in enforce mode.
   /snap/snapd/27591/usr/lib/snapd/snap-confine
   /snap/snapd/27710/usr/lib/snapd/snap-confine
   /usr/bin/man
   /usr/lib/snapd/snap-confine
   docker-default
   lsb_release
   man_filter
```

```
нет SELinux
```


### Limits (ulimit)

```
65535
```

```
real-time non-blocking time  (microseconds, -R) unlimited
core file size              (blocks, -c) 0
data seg size               (kbytes, -d) unlimited
scheduling priority                 (-e) 0
file size                   (blocks, -f) unlimited
pending signals                     (-i) 3520
max locked memory           (kbytes, -l) 123068
max memory size             (kbytes, -m) unlimited
open files                          (-n) 65535
pipe size                (512 bytes, -p) 8
POSIX message queues         (bytes, -q) 819200
real-time priority                  (-r) 0
stack size                  (kbytes, -s) 8192
cpu time                   (seconds, -t) unlimited
max user processes                  (-u) 3520
```


## 10.5 Cron jobs

```
41 1 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null
# Еженедельная очистка старых логов
0 3 * * 0 find /var/log -name "*.1" -mtime +7 -delete 2>/dev/null; find /var/log -name "*.gz" -mtime +30 -delete 2>/dev/null
0 4 * * 2,5 /usr/local/bin/update-geoip-telemt.sh >> /var/log/geoip-telemt.log 2>&1
15 4 * * 3 /usr/local/bin/update-geoip-mirror.sh >> /var/log/geoip-mirror.log 2>&1
```

```
total 32
drwxr-xr-x   2 root root  4096 May 21 18:06 .
drwxr-xr-x 123 root root 12288 Sep  2 06:37 ..
-rw-r--r--   1 root root    55 May 21 18:05 disk-monitor-telegram
-rw-r--r--   1 root root   201 Apr  8  2024 e2scrub_all
-rw-r--r--   1 root root   102 Apr 23  2024 .placeholder
-rw-r--r--   1 root root   396 Apr 23  2024 sysstat
```

```
=== /etc/cron.d/disk-monitor-telegram ===
0 9 * * * root /usr/local/bin/disk-monitor-telegram.sh
=== /etc/cron.d/e2scrub_all ===
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
=== /etc/cron.d/sysstat ===
# The first element of the path is a directory where the debian-sa1
# script is located
PATH=/usr/lib/sysstat:/usr/sbin:/usr/sbin:/usr/bin:/sbin:/bin

# Activity reports every 10 minutes everyday
5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1

# Additional run at 23:59 to rotate the statistics file
59 23 * * * root command -v debian-sa1 > /dev/null && debian-sa1 60 2
```


## 11. Systemd

```
apparmor.service
apport.service
blk-availability.service
cloud-config.service
cloud-final.service
cloud-init-local.service
cloud-init.service
console-setup.service
containerd.service
cron.service
dmesg.service
docker.service
e2scrub_reap.service
fail2ban.service
finalrd.service
getty@.service
glances.service
gpu-manager.service
grub-common.service
grub-initrd-fallback.service
keyboard-setup.service
lm-sensors.service
lvm2-monitor.service
mihomo.service
mita.service
networkd-dispatcher.service
networking.service
open-iscsi.service
open-vm-tools.service
pollinate.service
rsyslog.service
secureboot-db.service
setvtrgb.service
snap.canonical-livepatch.canonical-livepatchd.service
snapd.apparmor.service
snapd.autoimport.service
snapd.core-fixup.service
snapd.recovery-chooser-trigger.service
snapd.seeded.service
snapd.system-shutdown.service
ssh.service
sysstat.service
systemd-networkd-wait-online.service
systemd-networkd.service
systemd-pstore.service
systemd-timesyncd.service
telemt-panel.service
telemt.service
ua-reboot-cmds.service
ubuntu-advantage.service
ubuntu-fan.service
ufw.service
unattended-upgrades.service
vgauth.service
warp-docker-routing.service
x-ui.service
```

```
docker.service
fail2ban.service
glances.service
mihomo.service
mita.service
ssh.service
telemt-panel.service
telemt.service
x-ui.service
```


### Детали ключевых сервисов

#### mihomo
```
Restart=always
ExecStart={ path=/usr/local/bin/mihomo ; argv[]=/usr/local/bin/mihomo -d /etc/mihomo ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=
LimitNOFILE=65535
User=
Group=
```

#### telemt
```
Restart=on-failure
ExecStart={ path=/usr/bin/telemt ; argv[]=/usr/bin/telemt /etc/telemt/telemt.toml ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=
LimitNOFILE=65536
User=telemt
Group=telemt
```

#### mita
```
Restart=on-failure
ExecStart={ path=/usr/bin/mita ; argv[]=/usr/bin/mita run ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=MITA_LOG_NO_TIMESTAMP=true
LimitNOFILE=65535
User=mita
Group=mita
```

#### x-ui
```
Restart=on-failure
ExecStart={ path=/usr/local/x-ui/x-ui ; argv[]=/usr/local/x-ui/x-ui ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=XRAY_VMESS_AEAD_FORCED=false
LimitNOFILE=524288
User=
Group=
```


## 12. Docker

```
Docker version 29.1.3, build 29.1.3-0ubuntu3~24.04.2
```

```
 Server Version: 29.1.3
 Storage Driver: overlayfs
 Cgroup Driver: systemd
 Cgroup Version: 2
 Kernel Version: 6.8.0-111-generic
 Operating System: Ubuntu 24.04.4 LTS
 Total Memory: 961.5MiB
```

```
NAMES          IMAGE          STATUS        PORTS
amnezia-awg2   amnezia-awg2   Up 45 hours   0.0.0.0:39551->39551/udp, [::]:39551->39551/udp
```

```
NETWORK ID     NAME              DRIVER    SCOPE
338cd7f15fc7   amnezia-dns-net   bridge    local
b9e23a44ae7f   bridge            bridge    local
75f431b18421   host              host      local
c2def934e038   none              null      local
```

```
DRIVER    VOLUME NAME
```


### Docker compose файлы

```
```


## 13. Kernel modules

```
veth                   45056  0
ip6_udp_tunnel         16384  1 vxlan
udp_tunnel             32768  1 vxlan
```

```
нет amneziawg модуля
```


## 14. WireGuard / AmneziaWG

```
wg не запущен
```


## 15. Mihomo

```
● mihomo.service - Mihomo Proxy
     Loaded: loaded (/etc/systemd/system/mihomo.service; enabled; preset: enabled)
    Drop-In: /etc/systemd/system/mihomo.service.d
             └─override.conf
     Active: active (running) since Wed 2026-09-02 14:46:24 UTC; 1 day 21h ago
   Main PID: 934 (mihomo)
      Tasks: 9 (limit: 1056)
     Memory: 82.2M (peak: 124.9M swap: 12.7M swap peak: 18.0M)
        CPU: 36min 18.654s
     CGroup: /system.slice/mihomo.service
             └─934 /usr/local/bin/mihomo -d /etc/mihomo

Sep 04 12:04:18 hungry-boyd.1cent.network mihomo[934]: time="2026-09-04T12:04:18.864204977Z" level=warning msg="because ⚡ Fastest_MASQUE failed multiple times, activate health check"
Sep 04 12:04:20 hungry-boyd.1cent.network mihomo[934]: time="2026-09-04T12:04:20.259819906Z" level=warning msg="[UDP] dial GLOBAL (match Match/) 198.18.0.0:58538 --> 8b91d65a-ed4e-478a-8d02-8087f0bd36e8-netseer-ipaddr-assoc.xy.fbcdn.net:443 error: can't resolve ip: couldn't find ip"
Sep 04 12:04:20 hungry-boyd.1cent.network mihomo[934]: time="2026-09-04T12:04:20.260811362Z" level=warning msg="[UDP] dial GLOBAL (match Match/) 198.18.0.0:58538 --> 8b91d65a-ed4e-478a-8d02-8087f0bd36e8-netseer-ipaddr-assoc.xy.fbcdn.net:443 error: can't resolve ip: couldn't find ip"
```

```
# Файл: /etc/mihomo/config.yaml
# --- ОСНОВНЫЕ НАСТРОЙКИ ---
mixed-port: 7890
allow-lan: true
bind-address: "*"
tcp-concurrent: true
mode: rule
log-level: info
ipv6: false
external-controller: 0.0.0.0:9090
external-ui: ui
external-ui-url: https://github.com/MetaCubeX/metacubexd/releases/latest/download/compressed-dist.tgz
unified-delay: true
profile:
  store-selected: false
  store-fake-ip: false

find-process-mode: off

tun:
  enable: true
  stack: gvisor
  device: tun-mihomo
  auto-route: false
  auto-detect-interface: true
  inet4-address: 10.255.255.1/30
  mtu: 1420
  gso: true

# --- DNS СЕКЦИЯ ---
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/16
  listen: 0.0.0.0:53
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
  proxy-server-nameserver:
    - 1.1.1.1

# --- ПОДПИСКИ (PROXY PROVIDERS) ---
proxy-providers:
  # Старая подписка (четвертый эшелон)
  gist_ee_vps:
    type: http
    header:
      Cache-Control:
        - "no-cache"
      x-hwid:
        - 6144e69a324f5c0725e18962caafaa00
    url: "https://gist.githubusercontent.com/saymer-alt/e16bd81e4a485b6f425a8ae80649cee7/raw/vps"
    interval: 43200
    path: ./vps_nodes.yaml
    health-check:
      enable: true
      interval: 300
      url: "https://google.com/generate_204"
      expected-status: 204

  # Новая подписка Geodema (третий эшелон)
  geodema_vps:
    type: http
    header:
      Cache-Control:
        - "no-cache"
      x-hwid:
        - 6144e69a324f5c0725e18962caafaa00
    url: "https://account.geodema.org/GpDWQktm_dHEV7Un"
    interval: 43200
    path: ./geodema_nodes.yaml
    health-check:
      enable: true
      interval: 300
      url: "https://google.com/generate_204"
      expected-status: 204

# --- ГРУППЫ ПРОКСИ (ИЕРАРХИЯ ЭШЕЛОНОВ) ---
proxy-groups:
  # Главный автоматический шлюз: каскадный перебор эшелонов сверху вниз
  - name: "🚀 EE_EXIT_STRATEGY"
    type: fallback
    proxies:
      - "⚡ Fastest_MASQUE"           # 1 эшелон
      - "WARP EE"                    # 2 эшелон
      - "🛡️ GEODEMA_SUBSCRIPTION"    # 3 эшелон (Новая)
      - "🗲 MY_GIST_SUBSCRIPTION"    # 4 эшелон (Резервное дно)

  # Первый эшелон: выбор лучшего MASQUE-подключения (QUIC vs H2)
  - name: "⚡ Fastest_MASQUE"
    type: url-test
    url: "https://google.com/generate_204"
    interval: 300
    expected-status: 204
    tolerance: 50
    proxies:
      - WARP-MASQUE-QUIC
      - WARP-MASQUE-H2-443

  # Третий эшелон: Автоматический выбор лучшего сервера внутри Geodema
  - name: "🛡️ GEODEMA_SUBSCRIPTION"
    type: url-test
    use:
      - geodema_vps
    url: "https://google.com/generate_204"
    interval: 300
    expected-status: 204
    tolerance: 50

  # Четвертый эшелон: автоматический выбор лучшего сервера из подписки
  - name: "🗲 MY_GIST_SUBSCRIPTION"
    type: url-test
    use:
      - gist_ee_vps
    url: "https://google.com/generate_204"
    interval: 300
    expected-status: 204
    tolerance: 50

  # Ручной селектор для веб-панели управления Yacd / Metacubexd
  - name: "GLOBAL"
    type: select
    proxies:
      - "🚀 EE_EXIT_STRATEGY"
      - "⚡ Fastest_MASQUE"
      - WARP-MASQUE-QUIC
      - WARP-MASQUE-H2-443
      - "WARP EE"
      - "🛡️ GEODEMA_SUBSCRIPTION"
      - "🗲 MY_GIST_SUBSCRIPTION"
      - "DIRECT"
      - "REJECT"

# --- СТАТИЧЕСКИЕ СЕРВЕРЫ ---
proxies:
  # MASQUE поверх QUIC (HTTP/3)
  - name: WARP-MASQUE-QUIC
    type: masque
    server: 162.159.198.2
    port: 443
    private-key: "MHcCAQEEIHObgaCiJSmyucIeiWPx8FthNv4km/J9gBwYopGqfdAeoAoGCCqGSM49AwEHoUQDQgAEeY2TLwB4SFQ/ZCrz5rfYbAvbnwaXLhbij86pQbyStmuI7U7Lcr0RuFggWg9HMSTJP2hSzrt1UhU6hN6j3EX7jQ=="
    public-key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w=="
    ip: 172.16.0.2
    sni: 4pda.to
    udp: true
    remote-dns-resolve: true
    dns:
      - 1.1.1.1
      - 1.0.0.1

  # MASQUE поверх HTTP/2
  - name: WARP-MASQUE-H2-443
    type: masque
    server: 162.159.199.44
    port: 443
    private-key: "MHcCAQEEIHObgaCiJSmyucIeiWPx8FthNv4km/J9gBwYopGqfdAeoAoGCCqGSM49AwEHoUQDQgAEeY2TLwB4SFQ/ZCrz5rfYbAvbnwaXLhbij86pQbyStmuI7U7Lcr0RuFggWg9HMSTJP2hSzrt1UhU6hN6j3EX7jQ=="
    public-key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w=="
    ip: 172.16.0.2
    sni: 4pda.to
    network: h2
    udp: true
    remote-dns-resolve: true
    dns:
      - 1.1.1.1
      - 1.0.0.1

  # Локальный эшелон WireGuard Cloudflare в Эстонии
  - name: "WARP EE"
    type: wireguard
    server: engage.cloudflareclient.com
    port: 2408
    private-key: "8Pj2E6rEqbIT1RKuudVMvoom3CaVzWATSPAaQf57hl8="
    udp: true
    ip: 172.16.0.2
    ipv6: 2606:4700:110:8c50:592a:3c1f:6b7e:ecba
    public-key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    allowed-ips:
      - "0.0.0.0/0"
      - "::/0"
    mtu: 1420

# --- ПРАВИЛА ---
rules:
  - "MATCH,GLOBAL"```


## 16. Cloudflare WARP

_WARP не установлен_

## 17. TeleMT

```
● telemt.service - Telemt
     Loaded: loaded (/etc/systemd/system/telemt.service; enabled; preset: enabled)
     Active: active (running) since Wed 2026-09-02 14:46:24 UTC; 1 day 21h ago
   Main PID: 941 (telemt)
      Tasks: 55 (limit: 1056)
     Memory: 29.1M (peak: 38.2M swap: 5.4M swap peak: 14.4M)
        CPU: 16min 19.106s
     CGroup: /system.slice/telemt.service
             └─941 /usr/bin/telemt /etc/telemt/telemt.toml

Sep 04 12:04:24 hungry-boyd.1cent.network telemt[941]: 2026-09-04T12:04:24.382804Z  INFO telemt::transport::middle_proxy::health: Idle writer refreshed before upstream idle timeout dc=-5 family=V4 endpoint=91.108.56.109:8888 old_writer_id=141659 idle_age_secs=51 threshold_secs=50 alive=3 required=3
Sep 04 12:04:27 hungry-boyd.1cent.network telemt[941]: 2026-09-04T12:04:27.389133Z  INFO telemt::transport::middle_proxy::handshake: ME key derivation parameters local_addr=95.85.224.104:29292 local_addr_nat=95.85.224.104:29292 client_addr_for_kdf=95.85.224.104:29292 reflected_ip="95.85.224.104" peer_addr=91.105.192.110:443 transport_peer_addr=91.105.192.110:443 peer_addr_nat=91.105.192.110:443 key_selector=0xcafaf9c4 crypto_schema=0x00000001 skew_secs=0 socks_kdf_policy=Strict
Sep 04 12:04:27 hungry-boyd.1cent.network telemt[941]: 2026-09-04T12:04:27.390897Z  INFO telemt::transport::middle_proxy::handshake: RPC handshake OK addr=91.105.192.110:443
Sep 04 12:04:27 hungry-boyd.1cent.network telemt[941]: 2026-09-04T12:04:27.391006Z  INFO telemt::transport::middle_proxy::health: Idle writer refreshed before upstream idle timeout dc=203 family=V4 endpoint=91.105.192.110:443 old_writer_id=141661 idle_age_secs=49 threshold_secs=46 alive=3 required=3
Sep 04 12:04:27 hungry-boyd.1cent.network telemt[941]: 2026-09-04T12:04:27.478754Z  INFO telemt::transport::middle_proxy::handshake: ME key derivation parameters local_addr=95.85.224.104:24038 local_addr_nat=95.85.224.104:24038 client_addr_for_kdf=95.85.224.104:24038 reflected_ip="95.85.224.104" peer_addr=91.108.4.193:8888 transport_peer_addr=91.108.4.193:8888 peer_addr_nat=91.108.4.193:8888 key_selector=0xcafaf9c4 crypto_schema=0x00000001 skew_secs=0 socks_kdf_policy=Strict
```

```
# Файл: /etc/telemt/telemt.toml
[general]
ad_tag = "3210772100d8a046c4c3f3e758e2e607"
log_level = "normal"
use_middle_proxy = true
middle_proxy_nat_probe = true
prefer_ipv6 = false
direct_relay_buffer_budget_max_bytes = 0

[general.modes]
classic = false
secure = false
tls = true

[server]
port = 443
max_connections = 400

# DPI fragmentation during TLS handshake
client_mss = "tspu"

# Restore normal MSS for relay traffic
client_mss_bulk = "1400"

[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = [ "127.0.0.1/32" ]

[censorship]
tls_domain = "cdnjs.cloudflare.com"
mask = true
tls_emulation = true

[access.users]
Oleg319 = "4212a8cadd99f7ff9c0e2b3f365cf3e3"
dzm = "276001638771fb2215289abba41caa99"
friends = "b507597e72854a8720eb46d72ec487ba"
public = "be522ef5b21011f4cfaccc5b21d95501"
saymer = "41dd6207c6af0c76e3c0e693bae10772"
snt = "3a386994ee6b93cf710598e3b1afaa44"

[access.user_max_unique_ips]
Oleg319 = 15
dzm = 100
friends = 100
public = 100
saymer = 100
snt = 100

[access.user_max_tcp_conns]
Oleg319 = 15
dzm = 100
friends = 100
public = 100
saymer = 100
snt = 100

[network]
ipv4 = true
prefer = 4```


## 17.5 Mieru (mita)

```
● mita.service - Mieru proxy server
     Loaded: loaded (/usr/lib/systemd/system/mita.service; enabled; preset: enabled)
    Drop-In: /etc/systemd/system/mita.service.d
             └─override.conf
     Active: active (running) since Wed 2026-09-02 14:58:05 UTC; 1 day 21h ago
   Main PID: 3444 (mita)
      Tasks: 5 (limit: 1056)
     Memory: 98.8M (peak: 135.6M swap: 23.9M swap peak: 33.3M)
        CPU: 38min 28.985s
     CGroup: /system.slice/mita.service
             └─3444 /usr/bin/mita run

Sep 04 11:58:05 hungry-boyd.1cent.network mita[3444]: INFO [metrics - cipher - server] DirectDecrypt=47657716 FailedDirectDecrypt=0 FailedHintMatchDecrypt=110 FailedIterateDecrypt=91750 HintMatchDecrypt=259997 IterateDecrypt=362765
Sep 04 11:58:05 hungry-boyd.1cent.network mita[3444]: INFO [metrics - connections] ActiveOpens=0 CurrEstablished=0 MaxConn=197 PassiveOpens=2986192
Sep 04 11:58:05 hungry-boyd.1cent.network mita[3444]: INFO [metrics - replay] KnownSession=0 NewSession=24284 NewSessionDecrypted=0
```

```
# Файл: /etc/mita/server_config.json
{
    "portBindings": [
        {
            "portRange": "50000-52000",
            "protocol": "UDP"
        }
    ],
    "users": [
        {
            "name": "saymer_estonia",
            "password": "***MASKED***"
        },
        {
            "name": "cherepavel_estonia",
            "password": "***MASKED***"
        }
    ],
    "egress": {
        "proxies": [
            {
                "name": "mihomo",
                "protocol": "SOCKS5_PROXY_PROTOCOL",
                "host": "127.0.0.1",
                "port": 7890
            }
        ],
        "rules": [
            {
                "ipRanges": ["*"],
                "domainNames": ["*"],
                "action": "PROXY",
                "proxyNames": ["mihomo"]
            }
        ]
    },
    "loggingLevel": "INFO",
    "mtu": 1400
}
```

```
2001
```

```
LISTEN 0      4096               *:51913            *:*    users:(("mita",pid=3444,fd=117))          
LISTEN 0      4096               *:50377            *:*    users:(("mita",pid=3444,fd=528))          
LISTEN 0      4096               *:50889            *:*    users:(("mita",pid=3444,fd=1040))         
LISTEN 0      4096               *:51401            *:*    users:(("mita",pid=3444,fd=1552))         
LISTEN 0      4096               *:51912            *:*    users:(("mita",pid=3444,fd=116))          
LISTEN 0      4096               *:50376            *:*    users:(("mita",pid=3444,fd=527))          
LISTEN 0      4096               *:50888            *:*    users:(("mita",pid=3444,fd=1039))         
LISTEN 0      4096               *:51400            *:*    users:(("mita",pid=3444,fd=1551))         
LISTEN 0      4096               *:51915            *:*    users:(("mita",pid=3444,fd=119))          
LISTEN 0      4096               *:50379            *:*    users:(("mita",pid=3444,fd=530))          
