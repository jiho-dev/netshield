#include <include_os.h>
#include <net/addrconf.h>

#include <typedefs.h>
#include <timer.h>
#include <ns_task.h>
#include <session.h>
#include <options.h>
#include <ns_macro.h>
#include <misc.h>


DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

extern struct timezone sys_tz;
extern struct net_device *dev_base;
extern rwlock_t dev_base_lock;

//////////////////////////////////////////////////////

desc_proto_t* ns_get_protocol_desc(uint8_t p);
char* ns_get_nic_name_by_idx(int32_t ifidx, char* buf);


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

uint8_t icmp_type_invmap[] __read_mostly = {
	[ICMP_ECHO] = ICMP_ECHOREPLY + 1,
	[ICMP_ECHOREPLY] = ICMP_ECHO + 1,
	[ICMP_TIMESTAMP] = ICMP_TIMESTAMPREPLY + 1,
	[ICMP_TIMESTAMPREPLY] = ICMP_TIMESTAMP + 1,
	[ICMP_INFO_REQUEST] = ICMP_INFO_REPLY + 1,
	[ICMP_INFO_REPLY] = ICMP_INFO_REQUEST + 1,
	[ICMP_ADDRESS] = ICMP_ADDRESSREPLY + 1,
	[ICMP_ADDRESSREPLY] = ICMP_ADDRESS + 1
};

uint8_t icmp6_type_invmap[] __read_mostly= {
	[ICMPV6_ECHO_REQUEST - 128]	= ICMPV6_ECHO_REPLY + 1,
	[ICMPV6_ECHO_REPLY - 128]	= ICMPV6_ECHO_REQUEST + 1,
	[NDISC_NEIGHBOUR_SOLICITATION - 128] = NDISC_NEIGHBOUR_ADVERTISEMENT + 1,
	[NDISC_NEIGHBOUR_ADVERTISEMENT - 128] = NDISC_NEIGHBOUR_SOLICITATION + 1,
	[ICMPV6_NI_QUERY - 128]		= ICMPV6_NI_REPLY + 1,
	[ICMPV6_NI_REPLY - 128]		= ICMPV6_NI_QUERY +1

};


desc_proto_t desc_p [] __read_mostly = {
//{	  0,     "HOPOPT",		"IPv6 Hop-by-Hop Option "},
{	  0,     "IP",			"Internet Protocol"},
{     1,     "ICMP",		"Internet Control Message"},
{     2,     "IGMP",		"Internet Group Management"},
{     3,     "GGP",			"Gateway-to-Gateway"},
{     4,     "IP",			"IP in IP (encapsulation)"},
{     5,     "ST",			"Stream"},
{     6,     "TCP",			"Transmission Control"},
{     7,     "CBT",			"CBT"},
{     8,     "EGP",			"Exterior Gateway Protocol"},
{     9,     "IGP",			"any private interior gateway (used by Cisco for their IGRP)"},
{    10,     "BBN-RCC-MON",	" BBN RCC Monitoring"},
{    11,     "NVP-II",		"Network Voice Protocol"},
{    12,     "PUP",			"PUP"},
{    13,     "ARGUS",		"ARGUS"},
{    14,     "EMCON",		"EMCON"},
{    15,     "XNET",		"Cross Net Debugger"},
{    16,     "CHAOS",		"Chaos"},
{    17,     "UDP",			"User Datagram"},
{    18,     "MUX",			"Multiplexing"},
{    19,     "DCN-MEAS",	"DCN Measurement Subsystems"},
{    20,     "HMP",			"Host Monitoring"},
{    21,     "PRM ",		"Packet Radio Measurement"},
{    22,     "XNS-IDP",		"XEROX NS IDP"},
{    23,     "TRUNK-1",		"Trunk-1"},
{    24,     "TRUNK-2",		"Trunk-2"},
{    25,     "LEAF-1",		"Leaf-1"},
{    26,     "LEAF-2",		"Leaf-2"},
{    27,     "RDP",			"Reliable Data Protocol"},
{    28,     "IRTP",		"Internet Reliable Transaction"},
{    29,     "ISO-TP4",		"ISO Transport Protocol Class 4"},
{    30,     "NETBLT",		"Bulk Data Transfer Protocol"},
{    31,     "MFE-NSP",		"MFE Network Services Protocol"},
{    32,     "MERIT-INP",	"MERIT Internodal Protocol"},
{    33,     "SEP",			"Sequential Exchange Protocol"},
{    34,     "3PC",			"Third Party Connect Protocol"},
{    35,     "IDPR",		"Inter-Domain Policy Routing Protocol"},
{    36,     "XTP",			"XTP"},
{    37,     "DDP",			"Datagram Delivery Protocol"},
{    38,     "IDPR-CMTP",	"IDPR Control Message Transport Protocol"},
{    39,     "TP++",		"TP++ Transport Protocol"},
{    40,     "IL",			"IL Transport Protocol"},
{    41,     "ISATAP",		"ISATAP"},
{    42,     "SDRP",		"Source Demand Routing Protocol"},
{    43,     "IPv6-Route",	"Routing Header for IPv6"},
{    44,     "IPv6-Frag",	"Fragment Header for IPv6"},
{    45,     "IDRP",		"Inter-Domain Routing Protocol"},
{    46,     "RSVP",		"Reservation Protocol"},
{    47,     "GRE",			"General Routing Encapsulation"},
{    48,     "MHRP",		"Mobile Host Routing Protocol"},
{    49,     "BNA",			"BNA"},
{    50,     "ESP",			"Encap Security Payload for IPv6"},
{    51,     "AH",			"Authentication Header for IPv6"},
{    52,     "I-NLSP",		"Integrated Net Layer Security  TUBA"},
{    53,     "SWIPE",		"IP with Encryption"},
{    54,     "NARP",		"NBMA Address Resolution Protocol"},
{    55,     "MOBILE",		"IP Mobility"},
{    56,     "TLSP",		"Transport Layer Security Protocol using Kryptonet key management"},
{    57,     "SKIP",		"SKIP"},
{    58,     "IPv6-ICMP",	"ICMP for IPv6"},
{    59,     "IPv6-NoNxt",	"No Next Header for IPv6"},
{    60,     "IPv6-Opts",	"Destination Options for IPv6"},
{    61,     "Unknown",		"any host internal protocol"},
{    62,     "CFTP",		"CFTP"},
{    63,     "Unknown",		"any local network"},
{    64,     "SAT-EXPAK",	"SATNET and Backroom EXPAK"},
{    65,     "KRYPTOLAN",	"Kryptolan"},
{    66,     "RVD",			"MIT Remote Virtual Disk Protocol"},
{    67,     "IPPC ",		"Internet Pluribus Packet Core"},
{    68,     "Unknown",		"any distributed file system"},
{    69,     "SAT-MON",		"SATNET Monitoring"},
{    70,     "VISA",		"VISA Protocol"},
{    71,     "IPCV",		"Internet Packet Core Utility"},
{    72,     "CPNX",		"Computer Protocol Network Executive"},
{    73,     "CPHB",		"Computer Protocol Heart Beat"},
{    74,     "WSN",			"Wang Span Network"},
{    75,     "PVP",			"Packet Video Protocol"},
{    76,     "BR-SAT-MON",	"Backroom SATNET Monitoring"},
{    77,     "SUN-ND",		"SUN ND PROTOCOL-Temporary"},
{    78,     "WB-MON",		"WIDEBAND Monitoring"},
{    79,     "WB-EXPAK",	"WIDEBAND EXPAK"},
{    80,     "ISO-IP",		"ISO Internet Protocol"},
{    81,     "VMTP",		"VMTP"},
{    82,     "SECURE-VMTP",	"SECURE-VMTP"},
{    83,     "VINES",		"VINES"},
{    84,     "TTP",			"TTP"},
{    85,     "NSFNET-IGP",	"NSFNET-IGP"},
{    86,     "DGP",			"Dissimilar Gateway Protocol"},
{    87,     "TCF",			"TCF"},
{    88,     "EIGRP",		"EIGRP"},
{    89,     "OSPFIGP",		"OSPFIGP"},
{    90,     "Sprite-RPC",	"Sprite RPC Protocol"},
{    91,     "LARP",		"Locus Address Resolution Protocol"},
{    92,     "MTP",			"Multicast Transport Protocol"},
{    93,     "AX.25",		"AX.25 Frames"},
{    94,     "IPIP",		"IP-within-IP Encapsulation Protocol"},
{    95,     "MICP",		"Mobile Internetworking Control Protocol"},
{    96,     "SCC-SP",		"Semaphore Communications Sec. Protocol"},
{    97,     "ETHERIP",		"Ethernet-within-IP Encapsulation"},
{    98,     "ENCAP",		"Encapsulation Header"},
{    99,     "Unknown",		"any private encryption scheme"},
{   100,     "GMTP",		"GMTP"},
{   101,     "IFMP",		"Ipsilon Flow Management Protocol"},
{   102,     "PNNI",		"PNNI over IP"},
{   103,     "PIM",			"Protocol Independent Multicast"},
{   104,     "ARIS",		"ARIS"},
{   105,     "SCPS",		"SCPS"},
{   106,     "QNX",			"QNX"},
{   107,     "A/N",			"Active Networks"},
{   108,     "IPComp",		"IP Payload Compression Protocol"},
{   109,     "SNP",			"Sitara Networks Protocol"},
{   110,     "Compaq-Peer",	"Compaq Peer Protocol"},
{   111,     "IPX-in-IP",	"IPX in IP"},
{   112,     "VRRP",		"Virtual Router Redundancy Protocol"},
{   113,     "PGM ",		"PGM Reliable Transport Protocol"},
{   114,     "Unknown",		"any 0-hop protocol"},
{   115,     "L2TP",		"Layer Two Tunneling Protocol"},
{   116,     "DDX",			"D-II Data Exchange (DDX)"},
{   117,     "IATP",		"Interactive Agent Transfer Protocol"},
{   118,     "STP",			"Schedule Transfer Protocol"},
{   119,     "SRP",			"SpectraLink Radio Protocol"},
{   120,     "UTI",			"UTI"},
{   121,     "SMP",			"Simple Message Protocol"},
{   122,     "SM",			"SM"},
{   123,     "PTP",			"Performance Transparency Protocol"},
{   124,     "ISIS",		"over IPv4"},
{   125,     "FIRE",		"Fire"},
{   126,     "CRTP",		"Combat Radio Transport Protocol"},
{   127,     "CRUDP",		"Combat Radio User Datagram"},
{   128,     "SSCOPMCE",	" "},
{   129,     "IPLT",		" "},
{   130,     "SPS",			"Secure Packet Shield"},
{   131,     "PIPE",		"Private IP Encapsulation within IP"},
{   132,     "SCTP",		"Stream Control Transmission Protocol"},
{   133,     "FC",			"Fibre Channel"},
{   255,     "Unknown",		"Reserved"},
};

desc_proto_t unassigned_p __read_mostly = {
	134, 	"Unknown", "Unassigned"
};

uint32_t ns_inet_aton(char *cp, struct in_addr *addr)
{
	int32_t dots = 0;
	u_long acc = 0, tmp_addr = 0;

	do {
		char cc = *cp;

		switch (cc) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				acc = acc * 10 + (cc - '0');
				break;

			case '.':
				if (++dots > 3) {
					return 0;
				}
				/* Fall through */

			case '\0':
				if (acc > 255) {
						return 0;
				}
				tmp_addr = tmp_addr << 8 | acc;
				acc = 0;
				break;

			default:
				return 0;
		}
	} while (*cp++) ;

	/* Normalize the address */
	if (dots < 3) {
		tmp_addr <<= 8 * (3 - dots) ;
	}

	tmp_addr = htonl(tmp_addr);

	/* Store it if requested */
	if (addr) {
		addr->s_addr = tmp_addr;
	}

	return tmp_addr;
}

#if 1

int32_t ns_atoi(const char *data)
{
	/* 64bit에서 어떻게 될까 ?  octeon할때 디버깅 하자 */
	return (int)simple_strtoul(data, NULL, 10);
}

#else
int32_t ns_atoi(const char *data)
{
	int32_t val = 0;

	for (;; data++) {
		switch (*data) {
			case '0'...'9':
				val = 10*val+(*data-'0');
				break;
			default:
				return val;
		}
	}
}
#endif

int32_t ns_atohex(char *dst, const char * src, int32_t len)
{	
	char *ret = dst;
	int32_t lsb,msb,idx;
	int32_t start = 0;

	for (idx=0; idx < len; idx ++) {	
		if (src[idx] == '|') {
			start = !start;
			continue;
		}

		if (start) {
			if (!isxdigit(src[idx]))
				continue;

			msb = tolower(src[idx++]);
			lsb = tolower(src[idx]);
			msb -= isdigit(msb) ? 0x30 : 0x57;
			lsb -= isdigit(lsb) ? 0x30 : 0x57;

#ifdef __LITTLE_ENDIAN
			*dst = (char)(lsb | (msb << 4));  
#else
#error 	check this for BIG_ENDIAN !!!
#endif
		}
		else {
			*dst = src[idx];
		}

		dst++;
	}

	*dst = 0;
	return dst-ret;
}

void dump_pkt(char* func, int32_t line, iph_t *iph, uint8_t inic)
{
	uint8_t* data;
	tph_t* t = NULL;
	uph_t* u = NULL;
	struct icmphdr* ic = NULL;
	uint16_t sp, dp;
	desc_proto_t *p_desc;
	char buf[256];
	char nic_name[IFNAMSIZ+1];
	char *p;

	data = (uint8_t *)iph + (iph->ihl << 2);
	p_desc = ns_get_protocol_desc(iph->protocol);

	switch (iph->protocol) {
	case IPPROTO_UDP:
		u = (uph_t*)data;
		sp = ntohs(u->source);
		dp = ntohs(u->dest);

		break;

	case IPPROTO_TCP:
		t = (tph_t*)data;
		sp = ntohs(t->source);
		dp = ntohs(t->dest);

		break;

	case IPPROTO_ICMP:
		ic = (struct icmphdr*)data;
		sp = ic->type;
		dp =  ntohs(ic->un.echo.id);
		break;

	default:
		dp = sp = 0;
	};

	if (inic > 0 ) {
		p = ns_get_nic_name_by_idx(inic, nic_name);
	}
	else {
		p = NULL;
	}

	//snprintf(buf, 256, "NetShield: " NS_FUNC_FMT "Packet Dump:iph=0x%p NIC=%s(%u):", func, line, iph, p?p:"NULL", inic);
	snprintf(buf, 256, "NetShield: " NS_FUNC_FMT "Packet Dump:NIC=%s(%u):", func, line, p?p:"NULL", inic);

	if (iph->protocol == IPPROTO_ICMP) {
		printk("%s"IP_FMT "->" IP_FMT ":%s(%d)-type:%d id:%d code:%d seq:%d \n",
			   buf,
			   IPN(iph->saddr),
			   IPN(iph->daddr),
			   p_desc->name,
			   iph->protocol, sp, dp, ic->code, ic->un.echo.sequence);
	}
	else {
		printk("%s"IP_FMT ":%d->" IP_FMT ":%d: %s(%d) \n",
			   buf,
			   IPN(iph->saddr),
			   sp,
			   IPN(iph->daddr),
			   dp,
			   p_desc->name,
			   iph->protocol);
	}
}

void dump_eth_pkt(char* data, int32_t len, char *msg)
{
	int32_t i;
	uint32_t c;

	printk("===== %s =====\n", msg);

	for (i=0; i<len; i++) {

		if (i>0 && (i%8) == 0)
			printk("\n");

		c = (uint32_t)(data[i] & 0x000000ff);
		printk("0x%02x(%c) ", c, c<128?isalnum(c)?c:' ':' ');

	}

	printk("\n");

}

#if defined(__LITTLE_ENDIAN)
void ns_dec_ip(ip4_t *ip)
{
	char* str_ip = (char*)ip;

	if (ip == NULL)
		return;

	str_ip[0] --;
}

void ns_inc_ip(ip4_t* ip)
{
	char* str_ip = (char*)ip;

	if (ip == NULL)
		return;

	str_ip[0] ++;
}
#elif defined(__BIG_ENDIAN)

void ns_dec_ip(ip4_t *ip)
{
	char* str_ip = (char*)ip;

	if (ip == NULL)
		return;

#error "We'll need to get a test on BIG endian mode, Please call patrick !!"
//	str_ip[3] --;
}

void ns_inc_ip(ip4_t* ip)
{
	char* str_ip = (char*)ip;

	if (ip == NULL)
		return;

#error "We'll need to get a test on BIG endian mode, Please call patrick !!"
//	str_ip[3] ++;
}
#else
#error Not defined Endian Mode
#endif

int32_t ns_is_local_address(ip4_t ip)
{
	struct net_device *dev = NULL;

	ENT_FUNC(3);

	dev = ip_dev_find(&init_net, ip);

	if (dev)
		dev_put(dev);

	return dev != NULL;

#if 0
	if (inet_addr_type(net, fl.fl4_src) == RTN_LOCAL) {
	}
#endif

}

int32_t ns_is_zeronet(ip4_t ip)
{
	return (ipv4_is_zeronet(ip));
}

#define ADDR_LOOPBACK 	0x0100007f
int32_t ns_is_loopback(ip4_t ip)
{
	ENT_FUNC(3);

	return (ip == ADDR_LOOPBACK);
}

int32_t ns_is_loopback6(ip_t* ip)
{
	return ipv6_addr_loopback((const struct in6_addr *)ip);
}

int32_t ns_is_local_broadcast(ip4_t addr)
{

	if ((addr & htonl(0x000000FF)) == htonl(0x000000FF))
		return 1;

	if ((addr & htonl(0x0000FFFF)) == htonl(0x0000FFFF))
		return 1;

	if ((addr & htonl(0x00FFFFFF)) == htonl(0x00FFFFFF))
		return 1;

	return 0;
}

int32_t ns_copy_from_user(void *_to, void *_from, int32_t nbytes)
{
	int32_t i, len, n;
	char* to = (char*)_to;
	char* from = (char*)_from;

	len = 0;

	for (i=0; i<10; i++) {
		n = copy_from_user(to+len, from+len, nbytes-len);

		len += n;

		if (n == 0)
			break;
	}

	if (i == 10 && n != 0) {
		dbg(0, "Can't copy data from user: %d", nbytes - len);
	}

	return n;
}

desc_proto_t* ns_get_protocol_desc(uint8_t p)
{
	int32_t i,asize;
	desc_proto_t *dp=&unassigned_p;

	// init
	dp->p = p;

	asize = sizeofa(desc_p);

	for (i=0; i<asize; i++) {
		if (desc_p[i].p == p) {
			dp = &desc_p[i];
			break;
		}
	}
	
	return dp;
}
EXPORT_SYMBOL(ns_get_protocol_desc);

char* ns_get_protocol_name(uint8_t p)
{
	desc_proto_t* pd = ns_get_protocol_desc(p);

	if (pd)
		return pd->name;

	return "Unknown";
}

dstent_t* ns_get_dst_entry(skb_t *skb)
{
	return skb_dst(skb);
}

void ns_set_dst_entry(skb_t *skb, dstent_t *dst)
{
	skb_dst_set(skb, dst);
}

uint16_t ns_csum(uint32_t oldvalinv, uint32_t newval, uint16_t oldcheck)
{
	uint32_t diffs[] = { oldvalinv, newval };

	return csum_fold(csum_partial((char *)diffs, sizeof(diffs), oldcheck ^ 0xffff));
}

uint32_t ns_get_nic_ip(int32_t if_idx)
{
	struct in_device *in_dev = NULL;
	netdev_t* dev=NULL;
	ip4_t ip=0;

	ENT_FUNC(5);

	dev = dev_get_by_index(&init_net, if_idx);
	if (dev == NULL /* || !(dev->flags & IFF_UP) */) {
		return 0;
	}

	ns_rd_lock();

	if ((in_dev = __in_dev_get_rcu(dev)) == NULL) {
		goto END;
	}

	for_primary_ifa(in_dev) {
		if (ifa->ifa_address == 0 || IN_LOOPBACK(ntohl(ifa->ifa_address)))
			continue;

		if (ifa->ifa_address != ifa->ifa_local) {
			ip = ifa->ifa_local;
			break;
		}
		ip = ifa->ifa_address;
		break;

	} endfor_ifa(in_dev);

END:
	ns_rd_unlock();

	if (dev)
		dev_put(dev);

	return ntohl(ip);
}

char *ns_strpbrk(const char *cs, const char *ct, const char *end)
{
	const char *sc1, *sc2;

	for (sc1 = cs; *sc1 != '\0' && sc1 <= end; ++sc1) {
		for (sc2 = ct; *sc2 != '\0'; ++sc2) {
			if (*sc1 == *sc2)
				return (char *)sc1;
		}
	}
	return NULL;
}

netdev_t* ns_get_nic_by_name(char* name)
{

	// INFO: 사용 완료후 dev_put()을 호출 해야 한다.
	return dev_get_by_name(&init_net, name);
}

int32_t  ns_get_nic_idx_by_name(char* name)
{
	netdev_t* dev;
	int32_t ret = -1;

	dev = ns_get_nic_by_name(name);
	if (dev != NULL) {
		ret = dev->ifindex;
		dev_put(dev);
	}

	return ret;
}

uint8_t ns_get_inv_icmp_type(uint8_t icmp_type, uint32_t fflag)
{
	if (fflag & FUNC_FLAG_IPV6)
		return (icmp6_type_invmap[icmp_type-128]-1);
	else
		return (icmp_type_invmap[icmp_type]-1);
}

netdev_t* ns_get_nic_by_idx(int32_t ifidx)
{
	// INFO: 사용후 dev_put()을 반드시 호출 해야 한다.
	netdev_t* dev=NULL;

	dev = dev_get_by_index(&init_net, ifidx);

	return dev;
}

char* ns_get_nic_name_by_idx(int32_t ifidx, char* buf)
{
	netdev_t* dev;

	dev = ns_get_nic_by_idx(ifidx);
	if (dev == NULL)
		return NULL;

	bzero(buf, IFNAMSIZ);
	strlcpy(buf, dev->name, IFNAMSIZ);
	
	dev_put(dev);

	return buf;
}

netdev_t* ns_get_nic_by_ip(ip4_t ip)
{
	netdev_t *dev;
	struct in_device *in_dev = NULL;
	int find = 0;

	read_lock(&dev_base_lock);

	ns_for_each_netdev(dev) {
		if ((in_dev = __in_dev_get_rcu(dev)) == NULL) {
			continue;
		}

		for_primary_ifa(in_dev) {
			if (ifa->ifa_address == 0 || IN_LOOPBACK(ntohl(ifa->ifa_address)))
				continue;

#if 0
			DBG(9, "ip=" IP_FMT " mask=" IP_FMT " in=" IP_FMT, 
				IPN(ifa->ifa_address), IPN(ifa->ifa_mask), IPN(ip));
#endif

			if (IS_INCLUDE_IP(ifa->ifa_address,ifa->ifa_mask,ip)) {
				dev_hold(dev);
				find = 1;
				goto END;
			}

			if (ifa->ifa_address != ifa->ifa_local) {
				if (IS_INCLUDE_IP(ifa->ifa_local,ifa->ifa_mask,ip)) {
					dev_hold(dev);
					find = 1;
					goto END;
				}
			}

		} endfor_ifa(in_dev);
	}

END:
	read_unlock(&dev_base_lock);

	return (find ? dev : NULL);
}

int32_t ns_get_nic_idx_by_ip(ip4_t ip)
{
	netdev_t *dev;
	int32_t nic=0;

	dev = ns_get_nic_by_ip(ip);
	if (dev) {
		nic = dev->ifindex;
		dev_put(dev);
	}

	return nic;
}

void ns_set_transport_header(skb_t* skb, uint8_t* iph, int32_t ip_hlen)
{
	// set ip payload pointer
	skb_set_transport_header(skb, ip_hlen);
}

