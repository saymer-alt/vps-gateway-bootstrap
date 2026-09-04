# VPS Snapshot v2: Saymer3
_Дата: 2026-09-04 15:01:58 MSK_
_Скрипт: vps-snapshot-v2.sh v2.0_

## 1. Система


### OS

```
NAME="Ubuntu"
VERSION="24.04.4 LTS (Noble Numbat)"
ID=ubuntu
```

```
Linux Saymer3 6.8.0-111-generic #111-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 11 23:16:02 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

```
Saymer3
```

```
 15:01:59 up 1 day, 18:36,  1 user,  load average: 0.02, 0.05, 0.02
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
Model name:                              Intel Xeon Processor (Skylake, IBRS)
Thread(s) per core:                      1
Core(s) per socket:                      1
Virtualization type:                     full
```

```
               total        used        free      shared  buff/cache   available
Mem:           913Mi       602Mi       150Mi       288Ki       361Mi       311Mi
Swap:          1.5Gi       171Mi       1.3Gi
```

```
NAME      TYPE SIZE   USED PRIO
/swap.img file 1.5G 171.9M   -2
```

```
Filesystem      Size  Used Avail Use% Mounted on
/dev/vda1       8.7G  5.8G  3.0G  67% /
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
wireguard-tools 1.0.20210914-1ubuntu4
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
5.175.134.49```

```
нет IPv6
```

```
127.0.0.1/8 lo
5.175.134.49/24 ens3
198.18.0.0/30 tun-mihomo
172.16.0.2/32 wg0
172.29.172.1/24 amn0
172.17.0.1/16 docker0
```

```
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
ens3             UP             00:f2:34:07:a0:fd <BROADCAST,MULTICAST,UP,LOWER_UP> 
tun-mihomo       UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> 
wg0              UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> 
amn0             UP             b6:29:b3:5c:54:8c <BROADCAST,MULTICAST,UP,LOWER_UP> 
docker0          UP             32:74:c4:21:19:b8 <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth0fbd50e@if2  UP             46:2e:18:21:83:ca <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth131d347@if3  UP             86:d4:69:75:99:4f <BROADCAST,MULTICAST,UP,LOWER_UP> 
```


### Детали интерфейсов

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0  allmulti 0 minmtu 0 maxmtu 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc cake state UP mode DEFAULT group default qlen 1000
    link/ether 00:f2:34:07:a0:fd brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 parentbus virtio parentdev virtio0 
    altname enp0s3
3: tun-mihomo: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc cake state UNKNOWN mode DEFAULT group default qlen 5000
    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    tun type tun pi off vnet_hdr on persist off addrgenmode random numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 
4: wg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc cake state UNKNOWN mode DEFAULT group default qlen 500
    link/none  promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    tun type tun pi off vnet_hdr on persist off addrgenmode random numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 
5: amn0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether b6:29:b3:5c:54:8c brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.b6:29:b3:5c:54:8c designated_root 8000.b6:29:b3:5c:54:8c root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer  284.66 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
6: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether 32:74:c4:21:19:b8 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.32:74:c4:21:19:b8 designated_root 8000.32:74:c4:21:19:b8 root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer  284.66 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
7: veth0fbd50e@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default 
    link/ether 46:2e:18:21:83:ca brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 
    veth 
    bridge_slave state forwarding priority 32 cost 2 hairpin off guard off root_block off fastleave off learning on flood on port_id 0x8001 port_no 0x1 designated_port 32769 designated_cost 0 designated_bridge 8000.32:74:c4:21:19:b8 designated_root 8000.32:74:c4:21:19:b8 hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on bcast_flood on mcast_to_unicast off neigh_suppress off group_fwd_mask 0 group_fwd_mask_str 0x0 vlan_tunnel off isolated off locked off addrgenmode eui64 numtxqueues 128 numrxqueues 128 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
8: veth131d347@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master amn0 state UP mode DEFAULT group default 
    link/ether 86:d4:69:75:99:4f brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1  allmulti 1 minmtu 68 maxmtu 65535 
    veth 
    bridge_slave state forwarding priority 32 cost 2 hairpin off guard off root_block off fastleave off learning on flood on port_id 0x8001 port_no 0x1 designated_port 32769 designated_cost 0 designated_bridge 8000.b6:29:b3:5c:54:8c designated_root 8000.b6:29:b3:5c:54:8c hold_timer    0.00 message_age_timer    0.00 forward_delay_timer    0.00 topology_change_ack 0 config_pending 0 proxy_arp off proxy_arp_wifi off mcast_router 1 mcast_fast_leave off mcast_flood on bcast_flood on mcast_to_unicast off neigh_suppress off group_fwd_mask 0 group_fwd_mask_str 0x0 vlan_tunnel off isolated off locked off addrgenmode eui64 numtxqueues 128 numrxqueues 128 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
```


### Интерфейсы WG/TUN

```
```

```
3: tun-mihomo: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc cake state UNKNOWN mode DEFAULT group default qlen 5000
    link/none 
4: wg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc cake state UNKNOWN mode DEFAULT group default qlen 500
    link/none 
```


## 5. MTU

```
amn0: 1500
docker0: 1500
ens3: 1500
lo: 65536
tun-mihomo: 1420
veth0fbd50e: 1500
veth131d347: 1500
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
default via 5.175.134.1 dev ens3 proto static 
5.175.134.0/24 dev ens3 proto kernel scope link src 5.175.134.49 
5.175.134.1 dev ens3 proto static scope link 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.29.172.0/24 dev amn0 proto kernel scope link src 172.29.172.1 
198.18.0.0/30 dev tun-mihomo proto kernel scope link src 198.18.0.0 
198.18.0.0/16 dev tun-mihomo scope link 
```

```
default dev tun-mihomo table mihomo scope link 
default via 5.175.134.1 dev ens3 proto static 
5.175.134.0/24 dev ens3 proto kernel scope link src 5.175.134.49 
5.175.134.1 dev ens3 proto static scope link 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.29.172.0/24 dev amn0 proto kernel scope link src 172.29.172.1 
198.18.0.0/30 dev tun-mihomo proto kernel scope link src 198.18.0.0 
198.18.0.0/16 dev tun-mihomo scope link 
local 5.175.134.49 dev ens3 table local proto kernel scope host src 5.175.134.49 
broadcast 5.175.134.255 dev ens3 table local proto kernel scope link src 5.175.134.49 
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
2606:4700:110:8c6f:a3d2:26b1:ff59:7712 dev wg0 proto kernel metric 256 pref medium
2a10:ccc1:1333::1 dev ens3 proto static metric 1024 pref medium
2a10:ccc1:1333::/64 dev ens3 proto ra metric 1024 mtu 1500 hoplimit 64 pref medium
2a10:ccc1:1333:38::/64 dev ens3 proto kernel metric 256 pref medium
fe80::/64 dev ens3 proto kernel metric 256 pref medium
fe80::/64 dev tun-mihomo proto kernel metric 256 pref medium
fe80::/64 dev wg0 proto kernel metric 256 pref medium
fe80::/64 dev veth0fbd50e proto kernel metric 256 pref medium
fe80::/64 dev docker0 proto kernel metric 256 pref medium
