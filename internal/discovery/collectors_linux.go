package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (c *Collector) collectSystem(ctx context.Context, r *Result) {
	b, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			p := strings.SplitN(line, "=", 2); if len(p) != 2 { continue }
			v := strings.Trim(p[1], "\"")
			switch p[0] { case "ID": r.System.OS.ID=v; case "NAME": r.System.OS.Name=v; case "VERSION_ID": r.System.OS.VersionID=v; case "VERSION": r.System.OS.Version=v; case "VERSION_CODENAME": r.System.OS.Codename=v }
		}
	} else { addObservation(&r.Unknowns, "OS_UNKNOWN", "system", err.Error()) }
	r.System.Kernel.Release = text(c, ctx, "uname", "-r")
	r.System.Kernel.Architecture = text(c, ctx, "uname", "-m")
	r.System.CPU.Count = countCPU()
	r.System.CPU.Model = cpuModel()
	r.System.CPU.Virtualization = text(c, ctx, "systemd-detect-virt")
	r.System.Memory.TotalMB, r.System.Memory.AvailableMB = memInfo()
	r.System.Swap.TotalMB, r.System.Swap.UsedMB = swapInfo()
	if st, err := os.Stat("/"); err == nil { _ = st }
	if out, err := output(c, ctx, "df", "-B1", "/"); err == nil { r.System.RootFS = parseDF(string(out)) } else { addObservation(&r.Unknowns, "ROOTFS_UNKNOWN", "system", err.Error()) }
}

func countCPU() int { b, err := os.ReadFile("/proc/cpuinfo"); if err != nil { return 0 }; n:=0; for _, l := range strings.Split(string(b), "\n") { if strings.HasPrefix(l,"processor") { n++ } }; return n }
func cpuModel() string { b, err:=os.ReadFile("/proc/cpuinfo"); if err!=nil{return ""}; for _,l:=range strings.Split(string(b),"\n") { if strings.HasPrefix(l,"model name") || strings.HasPrefix(l,"Hardware") { p:=strings.SplitN(l,":",2); if len(p)==2{return strings.TrimSpace(p[1])} } }; return "" }
func memInfo() (uint64,uint64) { b,err:=os.ReadFile("/proc/meminfo"); if err!=nil{return 0,0}; var t,a uint64; for _,l:=range strings.Split(string(b),"\n") { f:=strings.Fields(l); if len(f)<2{continue}; v,_:=strconv.ParseUint(f[1],10,64); switch f[0]{case "MemTotal:":t=v;case "MemAvailable:":a=v} }; return t/1024,a/1024 }
func swapInfo() (uint64,uint64) { b,err:=os.ReadFile("/proc/meminfo"); if err!=nil{return 0,0}; var t,u uint64; for _,l:=range strings.Split(string(b),"\n") { f:=strings.Fields(l); if len(f)<2{continue}; v,_:=strconv.ParseUint(f[1],10,64); switch f[0]{case "SwapTotal:":t=v;case "SwapFree:": if t>=v {u=t-v}} }; return t/1024,u/1024 }
func parseDF(s string) Filesystem { var f Filesystem; lines:=strings.Split(strings.TrimSpace(s),"\n"); if len(lines)<2{return f}; x:=strings.Fields(lines[len(lines)-1]); if len(x)>=6 { f.Filesystem=x[0]; f.SizeBytes,_=strconv.ParseUint(x[1],10,64); f.UsedBytes,_=strconv.ParseUint(x[2],10,64); f.AvailableBytes,_=strconv.ParseUint(x[3],10,64); f.Mountpoint=x[5] }; return f }

func (c *Collector) collectNetwork(ctx context.Context, r *Result) {
	var links []struct { Ifindex int `json:"ifindex"`; Ifname string `json:"ifname"`; MTU int `json:"mtu"`; OperState string `json:"operstate"`; Address string `json:"address"`; LinkType string `json:"link_type"`; Altnames []string `json:"altnames"` }
	if err:=jsonOut(c,ctx,&links,"ip","-j","link"); err==nil { for _,l:=range links { r.Network.Interfaces=append(r.Network.Interfaces,Interface{Name:l.Ifname,MTU:l.MTU,State:l.OperState,MAC:l.Address,Kind:l.LinkType,AltNames:l.Altnames}) } } else { addObservation(&r.Unknowns,"NETWORK_LINKS_UNKNOWN","network",err.Error()) }
	var addrs []struct { Ifname string `json:"ifname"`; AddrInfo []struct { Family string `json:"family"`; Local string `json:"local"`; Prefix int `json:"prefixlen"` } `json:"addr_info"` }
	if err:=jsonOut(c,ctx,&addrs,"ip","-j","addr"); err==nil { for _,a:=range addrs { for _,x:=range a.AddrInfo { for i:=range r.Network.Interfaces { if r.Network.Interfaces[i].Name==a.Ifname { r.Network.Interfaces[i].Addresses=append(r.Network.Interfaces[i].Addresses,Address{Address:x.Local,PrefixLength:x.Prefix,Family:x.Family}) } } } } } else { addObservation(&r.Unknowns,"NETWORK_ADDRS_UNKNOWN","network",err.Error()) }
	var routes []struct { Dst string `json:"dst"`; Gateway string `json:"gateway"`; Dev string `json:"dev"`; Protocol string `json:"protocol"`; Metric int `json:"metric"` }
	if err:=jsonOut(c,ctx,&routes,"ip","-j","route","show","default"); err==nil && len(routes)>0 { r.Network.DefaultGateway=routes[0].Gateway; r.Network.ExternalInterface=routes[0].Dev; r.Network.IPv4=true } else if err!=nil { addObservation(&r.Unknowns,"DEFAULT_ROUTE_UNKNOWN","network",err.Error()) }
	var has4,has6 bool; for _,i:=range r.Network.Interfaces { for _,a:=range i.Addresses { if a.Family=="inet" {has4=true}; if a.Family=="inet6" {has6=true} } }; r.Network.IPv4=has4 || r.Network.DefaultGateway!=""; r.Network.IPv6=has6
	if b,err:=os.ReadFile("/etc/resolv.conf"); err==nil { for _,l:=range strings.Split(string(b),"\n") { f:=strings.Fields(l); if len(f)>=2 && f[0]=="nameserver" { r.Network.DNS.Resolvers=append(r.Network.DNS.Resolvers,f[1]) } }; r.Network.DNS.Source="/etc/resolv.conf"; r.Network.DNS.Active=len(r.Network.DNS.Resolvers)>0 } else { addObservation(&r.Unknowns,"DNS_UNKNOWN","network",err.Error()) }
}

func (c *Collector) collectRouting(ctx context.Context, r *Result) {
	var rules []struct { Priority int `json:"priority"`; From string `json:"from"`; To string `json:"to"`; FirewallMark any `json:"fwmark"`; Table any `json:"table"` }
	if err:=jsonOut(c,ctx,&rules,"ip","-j","rule"); err==nil { for _,x:=range rules { r.Routing.Rules=append(r.Routing.Rules,Rule{Priority:x.Priority,Selector:strings.TrimSpace(x.From+" "+x.To),Table:fmtAny(x.Table)}) } } else { addObservation(&r.Unknowns,"ROUTING_RULES_UNKNOWN","routing",err.Error()) }
	if out,err:=output(c,ctx,"ip","-j","route","show","table","all"); err==nil { var raw []map[string]any; if json.Unmarshal(out,&raw)==nil { for _,x:=range raw { dst,_:=x["dst"].(string); dev,_:=x["dev"].(string); gw,_:=x["gateway"].(string); table:=fmtAny(x["table"]); if dst=="default" && table!="" { r.Routing.DefaultRoutes=append(r.Routing.DefaultRoutes,Route{Destination:"0.0.0.0/0",Gateway:gw,Device:dev,Table:table}) } } } } else { addObservation(&r.Unknowns,"ROUTING_TABLES_UNKNOWN","routing",err.Error()) }
}
func fmtAny(v any) string { switch x:=v.(type){case string:return x;case float64:return strconv.Itoa(int(x));default:return ""} }

func (c *Collector) collectFirewall(ctx context.Context, r *Result) {
	if p,err:=execLookPath("ufw"); err==nil { r.Firewall.UFW.Installed=true; if s:=text(c,ctx,p,"status"); strings.Contains(s,"Status: active") {r.Firewall.UFW.Active=true}; r.Firewall.Layers=append(r.Firewall.Layers,"ufw") }
	if p,err:=execLookPath("nft"); err==nil { r.Firewall.NFTables.Installed=true; if _,e:=output(c,ctx,p,"list","ruleset"); e==nil {r.Firewall.NFTables.Active=true}; r.Firewall.Layers=append(r.Firewall.Layers,"nftables") }
	if p,err:=execLookPath("iptables"); err==nil { r.Firewall.IPTables.Installed=true; if _,e:=output(c,ctx,p,"-S"); e==nil {r.Firewall.IPTables.Active=true}; r.Firewall.Layers=append(r.Firewall.Layers,"iptables") }
	if len(r.Firewall.Layers)==0 { addObservation(&r.Unknowns,"FIREWALL_UNKNOWN","firewall","no supported firewall frontend detected") }
}

func (c *Collector) collectSSH(ctx context.Context, r *Result) {
	if p,err:=execLookPath("sshd"); err==nil { r.SSH.Installed=true; if out,e:=output(c,ctx,p,"-T"); e==nil { parseSSH(string(out),&r.SSH) } }
	if socketState:=text(c,ctx,"systemctl","is-active","ssh.socket"); socketState=="active" { r.SSH.Architecture="socket-activated"; addObservation(&r.Observations,"SSH_SOCKET_ACTIVATION","ssh","ssh.socket is active") } else { r.SSH.Architecture="service" }
	for _,l:=range listeners(c,ctx) { if l.Protocol=="tcp" && l.Service=="sshd" { r.SSH.Listeners=append(r.SSH.Listeners,l); r.SSH.EffectivePorts=appendUnique(r.SSH.EffectivePorts,l.Port) } }
}
func parseSSH(s string,r *SSH){ for _,l:=range strings.Split(s,"\n"){f:=strings.Fields(l);if len(f)<2{continue}; switch strings.ToLower(f[0]){case "port":if n,e:=strconv.Atoi(f[1]);e==nil{r.EffectivePorts=appendUnique(r.EffectivePorts,n)};case "passwordauthentication":v:=strings.EqualFold(f[1],"yes");r.PasswordAuthentication=&v;case "pubkeyauthentication":v:=strings.EqualFold(f[1],"yes");r.PubkeyAuthentication=&v;case "permitrootlogin":r.PermitRootLogin=f[1]}} }
func appendUnique(a []int,v int)[]int{for _,x:=range a{if x==v{return a}};return append(a,v)}

func (c *Collector) collectServices(ctx context.Context,r *Result){ names:=[]string{"ssh.service","ssh.socket","docker.service","mihomo.service","mita.service","fail2ban.service"}; for _,n:=range names { if s:=text(c,ctx,"systemctl","show","-p","LoadState","-p","ActiveState","-p","SubState","-p","UnitFileState",n); s!="" { sv:=Service{Name:n,Exists:true}; for _,l:=range strings.Split(s,"\n"){p:=strings.SplitN(l,"=",2);if len(p)!=2{continue};switch p[0]{case "LoadState":sv.Exists=p[1]=="loaded";case "ActiveState":sv.Active=p[1]=="active";case "SubState":sv.SubState=p[1];case "UnitFileState":sv.Enabled=p[1]=="enabled"}}; if sv.Exists{r.Services=append(r.Services,sv)} } } }

func (c *Collector) collectPorts(ctx context.Context,r *Result){ r.Ports=listeners(c,ctx) }
func listeners(c *Collector,ctx context.Context)[]Listener{ out,err:=output(c,ctx,"ss","-H","-lntp");if err!=nil{return nil};var result []Listener;for _,line:=range strings.Split(string(out),"\n"){f:=strings.Fields(line);if len(f)<4{continue}; addr,port:=splitEndpoint(f[3]); p:=Listener{Address:addr,Port:port,Protocol:"tcp"};if len(f)>=6{p.Process=f[5];if strings.Contains(p.Process,"sshd"){p.Service="sshd"}};result=append(result,p)};return result }
func splitEndpoint(s string)(string,int){ if h,p,e:=net.SplitHostPort(s);e==nil{n,_:=strconv.Atoi(p);return h,n};i:=strings.LastIndex(s,":");if i<0{return s,0};n,_:=strconv.Atoi(s[i+1:]);return strings.Trim(s[:i],"[]"),n }

func (c *Collector) collectCapabilities(ctx context.Context,r *Result){ _,e:=exec.LookPath("systemctl");r.Capabilities.Systemd=e==nil;_,e=exec.LookPath("docker");r.Capabilities.Docker=e==nil;_,e=exec.LookPath("nft");r.Capabilities.NFTables=e==nil;_,e=exec.LookPath("iptables");r.Capabilities.IPTables=e==nil;_,e=exec.LookPath("ufw");r.Capabilities.UFW=e==nil;_,e=exec.LookPath("wg");r.Capabilities.WireGuard=e==nil }

func execLookPath(name string)(string,error){return exec.LookPath(name)}
var _ = bufio.NewScanner
var _ = filepath.Separator
