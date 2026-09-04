# VPS Snapshot v2: Saymer
_Дата: 2026-09-04 14:54:49 MSK_
_Скрипт: vps-snapshot-v2.sh v2.0_

## 1. Система


### OS

```
NAME="Ubuntu"
VERSION="24.04.4 LTS (Noble Numbat)"
ID=ubuntu
```

```
Linux Saymer 6.8.0-111-generic #111-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 11 23:16:02 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

```
Saymer
```

```
 14:54:50 up 1 day, 18:37,  1 user,  load average: 0.25, 0.20, 0.18
```

```
                Time zone: Europe/Moscow (MSK, +0300)
```

```
LANG=C.UTF-8
LANGUAGE=
LC_CTYPE="C.UTF-8"
LC_NUMERIC="C.UTF-8"
LC_TIME="C.UTF-8"
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
Mem:           913Mi       727Mi        72Mi        44Ki       250Mi       186Mi
Swap:          1.0Gi       186Mi       837Mi
```

```
NAME      TYPE  SIZE   USED PRIO
/swap.img file 1024M 186.2M   -2
```

```
Filesystem      Size  Used Avail Use% Mounted on
/dev/vda1       8.7G  5.6G  3.1G  65% /
/dev/vda16      881M   64M  756M   8% /boot
/dev/vda15      105M  6.2M   99M   6% /boot/efi
```


## 3. Пакеты и версии


### Ключевые пакеты

```
ca-certificates 20260601~24.04.1
curl 8.5.0-2ubuntu10.13
docker-compose 1.29.2-6ubuntu1
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
```


### Репозитории

```
нет apt-cache
```


## 4. Сеть

```
5.175.236.6```

```
нет IPv6
```

```
127.0.0.1/8 lo
5.175.236.6/24 ens3
198.18.0.0/30 tun-mihomo
172.16.0.2/32 wg0
172.17.0.1/16 docker0
172.29.172.1/24 amn0
```

```
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
ens3             UP             00:9a:95:67:1c:2d <BROADCAST,MULTICAST,UP,LOWER_UP> 
tun-mihomo       UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> 
wg0              UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> 
docker0          UP             76:c7:f4:90:c9:e4 <BROADCAST,MULTICAST,UP,LOWER_UP> 
amn0             UP             3a:96:ae:c8:34:09 <BROADCAST,MULTICAST,UP,LOWER_UP> 
vethd711776@if2  UP             f6:67:49:29:12:15 <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth3ab5fe4@if3  UP             06:20:59:15:a2:26 <BROADCAST,MULTICAST,UP,LOWER_UP> 
```


### Детали интерфейсов

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0  allmulti 0 minmtu 0 maxmtu 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT group default qlen 1000
    link/ether 00:9a:95:67:1c:2d brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 parentbus virtio parentdev virtio0 
    altname enp0s3
3: tun-mihomo: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 5000
    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    tun type tun pi off vnet_hdr on persist off addrgenmode random numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 
4: wg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq state UNKNOWN mode DEFAULT group default qlen 500
    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    tun type tun pi off vnet_hdr on persist off addrgenmode random numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 
5: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether 76:c7:f4:90:c9:e4 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.76:c7:f4:90:c9:e4 designated_root 8000.76:c7:f4:90:c9:e4 root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer  178.68 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
6: amn0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether 3a:96:ae:c8:34:09 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.3a:96:ae:c8:34:9 designated_root 8000.3a:96:ae:c8:34:9 root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer   46.13 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
7: vethd711776@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master amn0 state UP mode DEFAULT group default 
    link/ether f6:67:49:29:12:15 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 
    veth 
    bridge_slave state forwarding priority 32 cost 2 hairpin off guard off root_block off fastleave off learning on flood on port_id 0x8001 port_no 0x1 designated_port 32769 designated_cost 0 designated_bridge 8000.3a:96:ae:c8:34:9 designated_root 8000.3a:96:ae:c8:34:9 hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on bcast_flood on mcast_to_unicast off neigh_suppress off group_fwd_mask 0 group_fwd_mask_str 0x0 vlan_tunnel off isolated off locked off addrgenmode eui64 numtxqueues 128 numrxqueues 128 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
8: veth3ab5fe4@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default 
    link/ether 06:20:59:15:a2:26 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 
    veth 
    bridge_slave state forwarding priority 32 cost 2 hairpin off guard off root_block off fastleave off learning on flood on port_id 0x8001 port_no 0x1 designated_port 32769 designated_cost 0 designated_bridge 8000.76:c7:f4:90:c9:e4 designated_root 8000.76:c7:f4:90:c9:e4 hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on bcast_flood on mcast_to_unicast off neigh_suppress off group_fwd_mask 0 group_fwd_mask_str 0x0 vlan_tunnel off isolated off locked off addrgenmode eui64 numtxqueues 128 numrxqueues 128 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
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
veth3ab5fe4: 1500
vethd711776: 1500
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
default via 5.175.236.1 dev ens3 proto static 
5.175.236.0/24 dev ens3 proto kernel scope link src 5.175.236.6 
5.175.236.1 dev ens3 proto static scope link 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.29.172.0/24 dev amn0 proto kernel scope link src 172.29.172.1 
198.18.0.0/30 dev tun-mihomo proto kernel scope link src 198.18.0.0 
198.18.0.0/16 dev tun-mihomo scope link 
```

```
default dev tun-mihomo table mihomo scope link 
default via 5.175.236.1 dev ens3 proto static 
5.175.236.0/24 dev ens3 proto kernel scope link src 5.175.236.6 
5.175.236.1 dev ens3 proto static scope link 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.29.172.0/24 dev amn0 proto kernel scope link src 172.29.172.1 
198.18.0.0/30 dev tun-mihomo proto kernel scope link src 198.18.0.0 
198.18.0.0/16 dev tun-mihomo scope link 
local 5.175.236.6 dev ens3 table local proto kernel scope host src 5.175.236.6 
broadcast 5.175.236.255 dev ens3 table local proto kernel scope link src 5.175.236.6 
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
2606:4700:110:88b0:c273:ea0b:bbb:da9 dev wg0 proto kernel metric 256 pref medium
fe80::/64 dev ens3 proto kernel metric 256 pref medium
fe80::/64 dev tun-mihomo proto kernel metric 256 pref medium
fe80::/64 dev wg0 proto kernel metric 256 pref medium
fe80::/64 dev vethd711776 proto kernel metric 256 pref medium
fe80::/64 dev amn0 proto kernel metric 256 pref medium
fe80::/64 dev veth3ab5fe4 proto kernel metric 256 pref medium
fe80::/64 dev docker0 proto kernel metric 256 pref medium
local ::1 dev lo table local proto kernel metric 0 pref medium
