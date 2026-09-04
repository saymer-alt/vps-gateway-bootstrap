# VPS Snapshot v2: Saymer2
_Дата: 2026-09-04 14:55:23 MSK_
_Скрипт: vps-snapshot-v2.sh v2.0_

## 1. Система


### OS

```
NAME="Debian GNU/Linux"
VERSION="12 (bookworm)"
ID=debian
```

```
Linux Saymer2 6.1.0-52-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.180-1 (2026-08-03) x86_64 GNU/Linux
```

```
Saymer2
```

```
 14:55:23 up 1 day, 18:30,  1 user,  load average: 0.51, 0.45, 0.37
```

```
                Time zone: Europe/Moscow (MSK, +0300)
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
Standard PC (i440FX + PIIX, 1996)
```

```
QEMU
```

```
нет dmesg
```


## 2. CPU / RAM / Disk

```
Architecture:                            x86_64
CPU(s):                                  2
Model name:                              Intel Xeon Processor (Cascadelake)
Thread(s) per core:                      1
Core(s) per socket:                      1
Virtualization type:                     full
```

```
               total        used        free      shared  buff/cache   available
Mem:           925Mi       684Mi       116Mi       360Ki       263Mi       240Mi
Swap:          1.5Gi        43Mi       1.5Gi
```

```
NAME      TYPE SIZE  USED PRIO
/swap.img file 1.5G 43.7M   -2
```

```
Filesystem      Size  Used Avail Use% Mounted on
/dev/vda3       9.9G  6.0G  3.9G  61% /
/dev/vda2       121M  142K  120M   1% /boot/efi
```


## 3. Пакеты и версии


### Ключевые пакеты

```
ca-certificates 20250419~deb12u1
curl 7.88.1-10+deb12u15
docker-ce 5:29.7.2-1~debian.12~bookworm
fail2ban 1.0.2-2
iproute2 6.1.0-3
iptables 1.8.9-2
mita 3.36.0
nftables 1.0.6-2+deb12u2
systemd 252.39-1~deb12u2
ufw 0.36.2-1
```


### Альтернативы iptables

```
iptables - auto mode
  link best version is /usr/sbin/iptables-nft
  link currently points to /usr/sbin/iptables-nft
  link iptables is /usr/sbin/iptables
  slave iptables-restore is /usr/sbin/iptables-restore
```


### Репозитории

```
нет apt-cache
```


## 4. Сеть

```
5.175.236.47```

```
нет IPv6
```

```
127.0.0.1/8 lo
5.175.236.47/24 eth0
198.18.0.0/30 tun-mihomo
172.16.0.2/32 wg0
172.17.0.1/16 docker0
172.29.172.1/24 amn0
```

```
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
eth0             UP             00:f3:fe:d1:58:7b <BROADCAST,MULTICAST,UP,LOWER_UP> 
tun-mihomo       UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> 
wg0              UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> 
docker0          UP             b6:ac:86:65:a8:21 <BROADCAST,MULTICAST,UP,LOWER_UP> 
amn0             UP             ce:04:e6:10:6c:cc <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth3a20083@if2  UP             e2:bc:32:50:a8:1c <BROADCAST,MULTICAST,UP,LOWER_UP> 
vethbbc2d83@if3  UP             8e:21:44:c8:9d:5d <BROADCAST,MULTICAST,UP,LOWER_UP> 
```


### Детали интерфейсов

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0  allmulti 0 minmtu 0 maxmtu 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT group default qlen 1000
    link/ether 00:f3:fe:d1:58:7b brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 parentbus virtio parentdev virtio0 
    altname enp0s3
    altname ens3
3: tun-mihomo: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 500
    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    tun type tun pi off vnet_hdr on persist off addrgenmode random numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 
4: wg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 500
    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    tun type tun pi off vnet_hdr on persist off addrgenmode random numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 
5: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether b6:ac:86:65:a8:21 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.b6:ac:86:65:a8:21 designated_root 8000.b6:ac:86:65:a8:21 root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer  115.67 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3124 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
6: amn0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether ce:04:e6:10:6c:cc brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.ce:4:e6:10:6c:cc designated_root 8000.ce:4:e6:10:6c:cc root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer  115.58 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3124 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
7: veth3a20083@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master amn0 state UP mode DEFAULT group default 
    link/ether e2:bc:32:50:a8:1c brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 
    veth 
    bridge_slave state forwarding priority 32 cost 2 hairpin off guard off root_block off fastleave off learning on flood on port_id 0x8001 port_no 0x1 designated_port 32769 designated_cost 0 designated_bridge 8000.ce:4:e6:10:6c:cc designated_root 8000.ce:4:e6:10:6c:cc hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on bcast_flood on mcast_to_unicast off neigh_suppress off group_fwd_mask 0 group_fwd_mask_str 0x0 vlan_tunnel off isolated off locked off addrgenmode eui64 numtxqueues 128 numrxqueues 128 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
8: vethbbc2d83@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default 
    link/ether 8e:21:44:c8:9d:5d brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 
    veth 
    bridge_slave state forwarding priority 32 cost 2 hairpin off guard off root_block off fastleave off learning on flood on port_id 0x8001 port_no 0x1 designated_port 32769 designated_cost 0 designated_bridge 8000.b6:ac:86:65:a8:21 designated_root 8000.b6:ac:86:65:a8:21 hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on bcast_flood on mcast_to_unicast off neigh_suppress off group_fwd_mask 0 group_fwd_mask_str 0x0 vlan_tunnel off isolated off locked off addrgenmode eui64 numtxqueues 128 numrxqueues 128 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
```


### Интерфейсы WG/TUN

```
```

```
3: tun-mihomo: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 500
    link/none 
4: wg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 500
    link/none 
```


## 5. MTU

```
amn0: 1500
docker0: 1500
eth0: 1500
lo: 65536
tun-mihomo: 1420
veth3a20083: 1500
vethbbc2d83: 1500
wg0: 1420
```

```
нет mtu
```


## 6. Routing / Policy Routing

```
0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default
```

```
default via 5.175.236.1 dev eth0 onlink 
5.175.236.0/24 dev eth0 proto kernel scope link src 5.175.236.47 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.29.172.0/24 dev amn0 proto kernel scope link src 172.29.172.1 
198.18.0.0/30 dev tun-mihomo proto kernel scope link src 198.18.0.0 
```

```
default via 5.175.236.1 dev eth0 onlink 
5.175.236.0/24 dev eth0 proto kernel scope link src 5.175.236.47 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.29.172.0/24 dev amn0 proto kernel scope link src 172.29.172.1 
198.18.0.0/30 dev tun-mihomo proto kernel scope link src 198.18.0.0 
local 5.175.236.47 dev eth0 table local proto kernel scope host src 5.175.236.47 
broadcast 5.175.236.255 dev eth0 table local proto kernel scope link src 5.175.236.47 
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
2606:4700:110:8166:306a:e2be:89ce:5a53 dev wg0 proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 256 pref medium
fe80::/64 dev tun-mihomo proto kernel metric 256 pref medium
fe80::/64 dev wg0 proto kernel metric 256 pref medium
fe80::/64 dev amn0 proto kernel metric 256 pref medium
fe80::/64 dev veth3a20083 proto kernel metric 256 pref medium
fe80::/64 dev vethbbc2d83 proto kernel metric 256 pref medium
fe80::/64 dev docker0 proto kernel metric 256 pref medium
local ::1 dev lo table local proto kernel metric 0 pref medium
local 2606:4700:110:8166:306a:e2be:89ce:5a53 dev wg0 table local proto kernel metric 0 pref medium
local fe80::2f3:feff:fed1:587b dev eth0 table local proto kernel metric 0 pref medium
local fe80::6654:4e40:dec1:a00e dev wg0 table local proto kernel metric 0 pref medium
```

```
1.1.1.1 via 5.175.236.1 dev eth0 src 5.175.236.47 uid 0 
    cache 
```

```
нет IPv6 route
```


## 7. iptables / nftables

```
iptables v1.8.9 (nf_tables)
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
-A INPUT -j ufw-before-logging-input
-A INPUT -j ufw-before-input
-A INPUT -j ufw-after-input
-A INPUT -j ufw-after-logging-input
-A INPUT -j ufw-reject-input
-A INPUT -j ufw-track-input
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A FORWARD -j ufw-before-logging-forward
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
-A DOCKER ! -i amn0 -p udp -m udp --dport 32926 -j DNAT --to-destination 172.29.172.2:32926
```

```
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
```

```
nftables v1.0.6 (Lester Gooch #5)
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
		iifname "lo" counter packets 42536523 bytes 51289480949 accept
		ct state related,established counter packets 95575414 bytes 81286662098 accept
		ct state invalid counter packets 6217 bytes 347790 jump ufw-logging-deny
		ct state invalid counter packets 6217 bytes 347790 drop
		meta l4proto icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		meta l4proto icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		meta l4proto icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		meta l4proto icmp icmp type echo-request counter packets 974 bytes 55505 accept
		udp sport 67 udp dport 68 counter packets 0 bytes 0 accept
		counter packets 295102 bytes 29876497 jump ufw-not-local
		ip daddr 224.0.0.251 udp dport 5353 counter packets 0 bytes 0 accept
		ip daddr 239.255.255.250 udp dport 1900 counter packets 0 bytes 0 accept
		counter packets 295102 bytes 29876497 jump ufw-user-input
	}

	chain ufw-before-output {
		oifname "lo" counter packets 42536523 bytes 51289480949 accept
		ct state related,established counter packets 86576949 bytes 80243382086 accept
		counter packets 691394 bytes 45232049 jump ufw-user-output
	}

	chain ufw-before-forward {
		ct state related,established counter packets 0 bytes 0 accept
		meta l4proto icmp icmp type destination-unreachable counter packets 0 bytes 0 accept
		meta l4proto icmp icmp type time-exceeded counter packets 0 bytes 0 accept
		meta l4proto icmp icmp type parameter-problem counter packets 0 bytes 0 accept
		meta l4proto icmp icmp type echo-request counter packets 0 bytes 0 accept
		counter packets 0 bytes 0 jump ufw-user-forward
	}

	chain ufw-after-input {
		udp dport 137 counter packets 14 bytes 1090 jump ufw-skip-to-policy-input
		udp dport 138 counter packets 0 bytes 0 jump ufw-skip-to-policy-input
		tcp dport 139 counter packets 23 bytes 1060 jump ufw-skip-to-policy-input
		tcp dport 445 counter packets 108 bytes 5200 jump ufw-skip-to-policy-input
		udp dport 67 counter packets 42494 bytes 13937732 jump ufw-skip-to-policy-input
		udp dport 68 counter packets 2 bytes 56 jump ufw-skip-to-policy-input
		fib daddr type broadcast counter packets 48 bytes 33728 jump ufw-skip-to-policy-input
	}

	chain ufw-after-output {
	}

	chain ufw-after-forward {
	}

	chain ufw-after-logging-input {
		limit rate 3/minute burst 10 packets counter packets 77 bytes 4502 log prefix "[UFW BLOCK] "
	}

	chain ufw-after-logging-output {
	}

	chain ufw-after-logging-forward {
		limit rate 3/minute burst 10 packets counter packets 0 bytes 0 log prefix "[UFW BLOCK] "
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
net.core.rmem_max                             = 16777216
net.core.wmem_max                             = 16777216
net.ipv4.tcp_rmem                             = 4096	131072	6291456
net.ipv4.tcp_wmem                             = 4096	16384	4194304
net.core.somaxconn                            = 4096
net.ipv4.ip_local_port_range                  = 32768	60999
net.ipv4.ip_local_reserved_ports              = 
vm.swappiness                                 = 10
vm.overcommit_memory                          = 1
net.ipv4.conf.all.rp_filter                   = 0
net.ipv4.tcp_max_syn_backlog                  = 128
net.netfilter.nf_conntrack_max                = 7680
net.netfilter.nf_conntrack_count              = 2746
```

### Кастомные sysctl.d

- `/etc/sysctl.d/99-amnezia.conf` (3 строк)
- `/etc/sysctl.d/99-sysctl.conf` (95 строк)

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
нет resolved
```

```
UNCONN 0      0                  *:53               *:*    users:(("mihomo",pid=725,fd=8))           
```


## 10. Безопасность


### SSH

```
Port 2222
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
```

```
LISTEN 0      128          0.0.0.0:2222       0.0.0.0:*    users:(("sshd",pid=767,fd=3))            
LISTEN 0      128             [::]:2222          [::]:*    users:(("sshd",pid=767,fd=4))            
```


### UFW

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
Anywhere                   REJECT IN   187.212.24.151             # by Fail2Ban after 3 attempts against sshd
Anywhere                   REJECT IN   188.69.225.188             # by Fail2Ban after 3 attempts against sshd
2222/tcp                   ALLOW IN    Anywhere                   # SSH
443/tcp                    ALLOW IN    Anywhere                   # TeleMT
32926/udp                  ALLOW IN    Anywhere                   # AmneziaWG
8443/tcp                   ALLOW IN    Anywhere                   # 3X-UI Panel
2053/tcp                   ALLOW IN    Anywhere                   # VLESS Reality
2096/tcp                   ALLOW IN    Anywhere                   # VLESS gRPC
2083/udp                   ALLOW IN    Anywhere                   # Hysteria2 QUIC
20000:22000/tcp            ALLOW IN    Anywhere                   # Mieru/Mita TCP
20000:22000/tcp (v6)       ALLOW IN    Anywhere (v6)              # Mieru/Mita TCP

```


### Fail2ban

```
active
Status
|- Number of jail:	3
`- Jail list:	3x-ipl, recidive, sshd
```


### AppArmor / SELinux

```
apparmor module is loaded.
9 profiles are loaded.
9 profiles are in enforce mode.
   /usr/lib/NetworkManager/nm-dhcp-client.action
   /usr/lib/NetworkManager/nm-dhcp-helper
   /usr/lib/connman/scripts/dhclient-script
   /usr/sbin/chronyd
   /{,usr/}sbin/dhclient
   docker-default
   lsb_release
```

```
нет SELinux
```


### Limits (ulimit)

```
32768
```

```
real-time non-blocking time  (microseconds, -R) unlimited
core file size              (blocks, -c) 0
data seg size               (kbytes, -d) unlimited
scheduling priority                 (-e) 0
file size                   (blocks, -f) unlimited
pending signals                     (-i) 3491
max locked memory           (kbytes, -l) 118444
max memory size             (kbytes, -m) unlimited
open files                          (-n) 32768
pipe size                (512 bytes, -p) 8
POSIX message queues         (bytes, -q) 819200
real-time priority                  (-r) 0
stack size                  (kbytes, -s) 8192
cpu time                   (seconds, -t) unlimited
max user processes                  (-u) 3491
```


## 10.5 Cron jobs

```
16 23 * * * "/.acme.sh"/acme.sh --cron --home "/.acme.sh" > /dev/null
```

```
total 20
drwxr-xr-x  2 root root   45 May 26 19:52 .
drwxr-xr-x 92 root root 8192 Sep  2 20:24 ..
-rw-r--r--  1 root root  201 Mar  5  2023 e2scrub_all
-rw-r--r--  1 root root  102 Mar  2  2023 .placeholder
```

```
=== /etc/cron.d/e2scrub_all ===
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
```


## 11. Systemd

```
apparmor.service
chrony.service
cloud-config.service
cloud-final.service
cloud-init-local.service
cloud-init.service
console-setup.service
containerd.service
cron.service
docker.service
e2scrub_reap.service
fail2ban.service
getty@.service
glances.service
keyboard-setup.service
lm-sensors.service
mihomo.service
mita.service
networking.service
rsyslog.service
ssh.service
systemd-pstore.service
telemt-panel.service
telemt.service
ufw.service
unattended-upgrades.service
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
ExecStart={ path=/usr/local/bin/mihomo ; argv[]=/usr/local/bin/mihomo -d /etc/mihomo ; ignore_errors=no ; start_time=[Wed 2026-09-02 20:25:00 MSK] ; stop_time=[n/a] ; pid=725 ; code=(null) ; status=0/0 }
Environment=
LimitNOFILE=524288
User=root
Group=
```

#### telemt
```
Restart=on-failure
ExecStart={ path=/usr/bin/telemt ; argv[]=/usr/bin/telemt /etc/telemt/telemt.toml ; ignore_errors=no ; start_time=[Wed 2026-09-02 20:25:00 MSK] ; stop_time=[n/a] ; pid=736 ; code=(null) ; status=0/0 }
Environment=
LimitNOFILE=65536
User=telemt
Group=telemt
```

#### mita
```
Restart=on-failure
ExecStart={ path=/usr/bin/mita ; argv[]=/usr/bin/mita run ; ignore_errors=no ; start_time=[Wed 2026-09-02 20:25:00 MSK] ; stop_time=[n/a] ; pid=764 ; code=(null) ; status=0/0 }
Environment=MITA_LOG_NO_TIMESTAMP=true
LimitNOFILE=524288
User=mita
Group=mita
```

#### x-ui
```
Restart=on-failure
ExecStart={ path=/usr/local/x-ui/x-ui ; argv[]=/usr/local/x-ui/x-ui ; ignore_errors=no ; start_time=[Wed 2026-09-02 20:25:00 MSK] ; stop_time=[n/a] ; pid=737 ; code=(null) ; status=0/0 }
Environment=XRAY_VMESS_AEAD_FORCED=false
LimitNOFILE=524288
User=
Group=
```


## 12. Docker

```
Docker version 29.7.2, build a7dcaa6
```

```
 Server Version: 29.7.2
 Storage Driver: overlayfs
 Cgroup Driver: systemd
 Cgroup Version: 2
 Kernel Version: 6.1.0-52-amd64
 Operating System: Debian GNU/Linux 12 (bookworm)
 Total Memory: 925.4MiB
```

```
NAMES          IMAGE          STATUS        PORTS
amnezia-awg2   amnezia-awg2   Up 43 hours   0.0.0.0:32926->32926/udp, [::]:32926->32926/udp
```

```
NETWORK ID     NAME              DRIVER    SCOPE
173980332d5c   amnezia-dns-net   bridge    local
e2e512e9f35c   bridge            bridge    local
4bcd98ea5602   host              host      local
f00a8903fab5   none              null      local
```

```
DRIVER    VOLUME NAME
```


### Docker compose файлы

```
```


## 13. Kernel modules

```
veth                   36864  0
tun                    61440  6
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
● mihomo.service - Mihomo Meta Service
     Loaded: loaded (/etc/systemd/system/mihomo.service; enabled; preset: enabled)
    Drop-In: /etc/systemd/system/mihomo.service.d
             └─override.conf
     Active: active (running) since Wed 2026-09-02 20:25:00 MSK; 1 day 18h ago
   Main PID: 725 (mihomo)
      Tasks: 13 (limit: 1047)
     Memory: 118.0M
        CPU: 2h 9min 24.506s
     CGroup: /system.slice/mihomo.service
             └─725 /usr/local/bin/mihomo -d /etc/mihomo

Sep 04 14:55:31 Saymer2 mihomo[725]: time="2026-09-04T14:55:31.338234746+03:00" level=info msg="[TCP] 127.0.0.1:49948 --> 91.105.192.100:443 match Match using GLOBAL[WARP-MASQUE-H2-443]"
Sep 04 14:55:31 Saymer2 mihomo[725]: time="2026-09-04T14:55:31.340073249+03:00" level=info msg="[TCP] 127.0.0.1:49954 --> 91.105.192.100:443 match Match using GLOBAL[WARP-MASQUE-H2-443]"
Sep 04 14:55:31 Saymer2 mihomo[725]: time="2026-09-04T14:55:31.350701348+03:00" level=info msg="[TCP] 127.0.0.1:49958 --> 91.105.192.100:443 match Match using GLOBAL[WARP-MASQUE-H2-443]"
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
  gist_se2_vps:
    type: http
    header:
      Cache-Control:
        - "no-cache"
      x-hwid:
        - "8db4db1e1f8c1a13ad1104cc349c48fd"
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
        - "8db4db1e1f8c1a13ad1104cc349c48fd"
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
  - name: "🚀 SE2_EXIT_STRATEGY"
    type: fallback
    proxies:
      - "⚡ Fastest_MASQUE"           # 1 эшелон
      - "WARP SE2"                   # 2 эшелон
      - "🛡️ GEODEMA_SUBSCRIPTION"    # 3 эшелон (Новая)
      - "🗲 MY_GIST_SUBSCRIPTION"    # 4 эшелон (Резервное дно)

  # Первый эшелон: Автоматический выбор между QUIC и H2 для MASQUE
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

  # Четвертый эшелон: Автоматический выбор лучшего сервера из подписки
  - name: "🗲 MY_GIST_SUBSCRIPTION"
    type: url-test
    use:
      - gist_se2_vps
    url: "https://google.com/generate_204"
    interval: 300
    expected-status: 204
    tolerance: 50

  # Главный ручной селектор для панели управления
  - name: "GLOBAL"
    type: select
    proxies:
      - "🚀 SE2_EXIT_STRATEGY"
      - "⚡ Fastest_MASQUE"
      - WARP-MASQUE-QUIC
      - WARP-MASQUE-H2-443
      - "WARP SE2"
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

  # Локальный WireGuard Cloudflare для Швеции 2
  - name: "WARP SE2"
    type: wireguard
    server: engage.cloudflareclient.com
    port: 2408
    private-key: "8F+sYJdeRrenJihHX6lod4ljFOQ2Xkt4zO94Y7RtZGI="
    udp: true
    ip: 172.16.0.2
    ipv6: 2606:4700:110:8b6f:ad81:1fcc:9ca1:c84b
    public-key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    allowed-ips:
      - "0.0.0.0/0"
      - "::/0"
    mtu: 1280

# --- ПРАВИЛА ---
rules:
  - "MATCH,GLOBAL"```


## 16. Cloudflare WARP

_WARP не установлен_

## 17. TeleMT

```
● telemt.service - Telemt
     Loaded: loaded (/etc/systemd/system/telemt.service; enabled; preset: enabled)
     Active: active (running) since Wed 2026-09-02 20:25:00 MSK; 1 day 18h ago
   Main PID: 736 (telemt)
      Tasks: 53 (limit: 1047)
     Memory: 58.4M
        CPU: 28min 58.480s
     CGroup: /system.slice/telemt.service
             └─736 /usr/bin/telemt /etc/telemt/telemt.toml

Sep 04 14:55:27 Saymer2 telemt[736]: 2026-09-04T11:55:27.940659Z  INFO telemt::transport::middle_proxy::handshake: ME key derivation parameters local_addr=5.175.236.47:45404 local_addr_nat=5.175.236.47:45404 client_addr_for_kdf=5.175.236.47:45404 reflected_ip="5.175.236.47" peer_addr=149.154.175.50:8888 transport_peer_addr=149.154.175.50:8888 peer_addr_nat=149.154.175.50:8888 key_selector=0xcafaf9c4 crypto_schema=0x00000001 skew_secs=0 socks_kdf_policy=Strict
Sep 04 14:55:28 Saymer2 telemt[736]: 2026-09-04T11:55:28.066567Z  INFO telemt::transport::middle_proxy::handshake: RPC handshake OK addr=149.154.175.50:8888
Sep 04 14:55:28 Saymer2 telemt[736]: 2026-09-04T11:55:28.066870Z  INFO telemt::transport::middle_proxy::pool_reinit: ME hardswap warmup floor reached for DC dc=1 pass=1 total_passes=4 fresh_count=3 required=3
Sep 04 14:55:29 Saymer2 telemt[736]: 2026-09-04T11:55:29.774123Z  INFO telemt::transport::middle_proxy::handshake: ME key derivation parameters local_addr=5.175.236.47:45420 local_addr_nat=5.175.236.47:45420 client_addr_for_kdf=5.175.236.47:45420 reflected_ip="5.175.236.47" peer_addr=149.154.175.50:8888 transport_peer_addr=149.154.175.50:8888 peer_addr_nat=149.154.175.50:8888 key_selector=0xcafaf9c4 crypto_schema=0x00000001 skew_secs=0 socks_kdf_policy=Strict
Sep 04 14:55:29 Saymer2 telemt[736]: 2026-09-04T11:55:29.900217Z  INFO telemt::transport::middle_proxy::handshake: RPC handshake OK addr=149.154.175.50:8888
```

```
# Файл: /etc/telemt/telemt.toml
[general]
ad_tag = "88ee78c8cd6bf5c4c6d93a3b701e3467"
log_level = "normal"
use_middle_proxy = true
middle_proxy_nat_probe = true
prefer_ipv6 = false

  [general.modes]
  classic = false
  secure = false
  tls = true

[server]
port = 443
max_connections = 1500

  [server.api]
  enabled = true
  listen = "127.0.0.1:9091"
  whitelist = [ "127.0.0.1/32" ]

[censorship]
tls_domain = "ica.se"
mask = true
tls_emulation = true

[access.users]
Terpilka = "2196596470f56b44e0c8494c5ee282c4"
TullTroll = "4ae6ce1cd289e1b76498bce80003a500"
Tullkriminalare = "8df7d7865a41070d60416350344c355a"
Gransvakt = "f185537c767bd0c54030e33aa8a1cd11"
Systembolaget = "ae4aee7545e882ed6bbf2b48c27a751e"
VabbaForare = "f2a57f95949c31a009ce14445a616cde"
LagomTrafik = "753f91263fdc6998be1619a5a8c28338"```


## 17.5 Mieru (mita)

```
● mita.service - Mieru proxy server
     Loaded: loaded (/lib/systemd/system/mita.service; enabled; preset: enabled)
     Active: active (running) since Wed 2026-09-02 20:25:00 MSK; 1 day 18h ago
    Process: 716 ExecStartPre=/usr/bin/mkdir -p /var/run/mita (code=exited, status=0/SUCCESS)
    Process: 742 ExecStartPre=/usr/bin/chown -R mita:mita /var/run/mita (code=exited, status=0/SUCCESS)
    Process: 748 ExecStartPre=/usr/bin/chmod 775 /var/run/mita (code=exited, status=0/SUCCESS)
   Main PID: 764 (mita)
      Tasks: 6 (limit: 1047)
     Memory: 37.8M
        CPU: 3min 1.629s
     CGroup: /system.slice/mita.service
             └─764 /usr/bin/mita run

Sep 04 14:55:01 Saymer2 mita[764]: INFO [metrics]
Sep 04 14:55:01 Saymer2 mita[764]: INFO [metrics - cipher - server] DirectDecrypt=31406468 FailedDirectDecrypt=0 FailedHintMatchDecrypt=100 FailedIterateDecrypt=50349 HintMatchDecrypt=211428 IterateDecrypt=261677
```

```
2001
```

```
LISTEN 0      4096               *:20484            *:*    users:(("mita",pid=764,fd=680))          
LISTEN 0      4096               *:20996            *:*    users:(("mita",pid=764,fd=852))          
LISTEN 0      4096               *:21508            *:*    users:(("mita",pid=764,fd=1647))         
LISTEN 0      4096               *:20485            *:*    users:(("mita",pid=764,fd=681))          
LISTEN 0      4096               *:20997            *:*    users:(("mita",pid=764,fd=853))          
LISTEN 0      4096               *:21509            *:*    users:(("mita",pid=764,fd=1648))         
LISTEN 0      4096               *:20486            *:*    users:(("mita",pid=764,fd=682))          
LISTEN 0      4096               *:20998            *:*    users:(("mita",pid=764,fd=854))          
LISTEN 0      4096               *:21510            *:*    users:(("mita",pid=764,fd=1649))         
LISTEN 0      4096               *:20487            *:*    users:(("mita",pid=764,fd=695))          
