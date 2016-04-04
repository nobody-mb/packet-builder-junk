#include "main.h"

static uint16_t checksum_comp(uint16_t * addr, int len)
{
	register long   sum = 0;
	int             count = len;
	uint16_t        temp;

	while (count > 1) {
		temp = *addr++;
		sum += temp;
		count -= 2;
	}
	if (count > 0)
		sum += *(char *)addr;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

long get_tcp_checksum_2(struct iovec *pio, struct ip ip, struct tcphdr tcp,
			char *opts, char *data, int opt_len, int data_len)
{

	int             slen = (int)pio->iov_len - (int)(ip.ip_hl * 4) - s_eth;
	int             hlen = (int)s_psh + slen;
	unsigned char  *sumblock = malloc(hlen);

	struct pseudo_hdr phdr;

	memset(&phdr, 0x00, s_psh);

	phdr.src = ip.ip_src.s_addr;
	phdr.dst = ip.ip_dst.s_addr;
	phdr.zero = 0;
	phdr.protocol = IPPROTO_TCP;
	phdr.tcplen = htons(slen);

	memcpy(sumblock, &phdr, s_psh);

	memcpy(sumblock + s_psh, &tcp, s_tcp);

	memcpy(sumblock + s_psh + s_tcp, opts, opt_len);

	memcpy(sumblock + s_psh + s_tcp + opt_len, data, data_len);

	return checksum_comp((unsigned short *)sumblock, hlen);
}

void build_eth_hdr(struct iovec *pio, uint8_t * src, uint8_t * dst)
{

	struct ether_header eth;

	memset(&eth, 0x00, s_eth);

	eth.ether_type = 8;
	memcpy(eth.ether_shost, src, ETH_ALEN);
	memcpy(eth.ether_dhost, dst, ETH_ALEN);

	memcpy(pio->iov_base, &eth, s_eth);

}

void build_ip_hdr(struct iovec *pio, uint32_t len, char *src,
		  struct ip_pair **dst)
{

	struct ip       ip;

	memset(&ip, 0x00, s_iph);

	ip.ip_v = 0x4;
	ip.ip_hl = 0x5;
	ip.ip_tos = 0x0;
	ip.ip_id = (arc4random() % 65535);
	ip.ip_off = htons(IP_DF);

	ip.ip_len = ntohl(len);

	ip.ip_ttl = 64;
	ip.ip_p = 0x6;
	inet_aton(src, &ip.ip_src);

	pthread_key_t   i = index_ips(dst);
	char           *ipd = pthread_getspecific(i);

	inet_aton(ipd, &ip.ip_dst);

	ip.ip_sum = checksum_comp((unsigned short *)&ip, s_iph);

	memcpy(pio->iov_base + s_eth, &ip, s_iph);
}

char           *build_tcp_hdr(struct iovec *pio, uint16_t sport, uint16_t dport,
			      uint32_t seq, uint32_t ack, uint32_t optlen,
			      uint32_t flags, char *opts, char *data,
			      int opt_len, int data_len)
{
	char           *ret = malloc(s_tcp + 1);

	struct tcphdr   tcp;

	memset(&tcp, 0x00, s_tcp);

	tcp.th_sport = htons(sport);
	tcp.th_dport = htons(dport);
	tcp.th_seq = htonl(seq);
	tcp.th_ack = htonl(ack);
	tcp.th_off = 5 + (optlen / 4);
	tcp.th_x2 = 0x0;
	tcp.th_flags = flags;
	tcp.th_win = htons(14600);
	tcp.th_urp = 0x0;

	struct ip      *ip = (struct ip *)(pio->iov_base + s_eth);

	tcp.th_sum =
		(int)get_tcp_checksum_2(pio, *ip, tcp, opts, data, opt_len,
					data_len);

	memcpy(pio->iov_base + s_eth + s_iph, &tcp, s_tcp);

	return ret;
}

struct iovec   *build_raw(struct pkt_info_t *syn)
{

	if (syn->p_flags & TH_SYN) {
		syn->opts = build_syn_ops(0, 0);
		syn->opt_len = 20;

	} else if (syn->p_flags & TH_ACK) {
		syn->opts = build_ack_ops(syn->p_tsval, syn->p_tsecr);
		syn->opt_len = 12;
	}

	struct iovec   *pio = malloc(s_iov);

	pio->iov_len = s_eth + s_iph + s_tcp + syn->opt_len + syn->data_len;
	pio->iov_base = calloc(1, pio->iov_len);

	build_eth_hdr(pio, syn->p_src_mac, syn->p_dst_mac);

	build_ip_hdr(pio, (uint32_t) pio->iov_len, syn->p_src_ip,
		     syn->p_dst_ip);

	build_tcp_hdr(pio, syn->p_src_port, syn->p_dst_port,
		      syn->p_seq, syn->p_ack, syn->opt_len,
		      syn->p_flags, syn->opts, syn->data,
		      syn->opt_len, syn->data_len);

	memcpy((char *)pio->iov_base + s_eth + s_iph + s_tcp,
	       syn->opts, syn->opt_len);

	memcpy((char *)pio->iov_base + s_eth + s_iph + s_tcp + syn->opt_len,
	       syn->data, syn->data_len);

	return pio;
}

#ifdef __linux__

void mmap_send(struct pkt_info_t *syn)
{
	struct iovec   *pio = build_raw(syn);
	ssize_t         sent;

	struct tpacket_req preq;
	int             rfd;

	if ((rfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		die_with_signal("socket");

	register int    s_ll = sizeof(struct sockaddr_ll);

	struct sockaddr_ll sll;

	memset(&sll, 0x0, s_ll);
	struct ifreq   *ifr = calloc(1, sizeof(struct ifreq));

	memcpy(ifr->ifr_name, "eth1", IFNAMSIZ);

	ioctl(rfd, SIOCGIFINDEX, ifr);

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr->ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if ((bind(rfd, (struct sockaddr *)&sll, s_ll)) < 0)
		die_with_signal("bind");

	int             error;
	socklen_t       errlen = sizeof(int);

	getsockopt(rfd, SOL_SOCKET, SO_ERROR, &error, &errlen);
	if (error > 0) {
		printf("Error %d: %s\n", error, strerror(error));
		die_with_signal("socket error");
	}

	preq.tp_block_size = 4096;
	preq.tp_frame_size = 1024;
	preq.tp_block_nr = 64;
	preq.tp_frame_nr = 256;

	int             size = preq.tp_block_size * preq.tp_block_nr;
	int             data_offset = TPACKET_HDRLEN - s_ll;

	if (setsockopt
	    (rfd, SOL_PACKET, PACKET_TX_RING, (char *)&preq, sizeof(preq)) < 0)
		perror("sockopt");
	struct tpacket_hdr *ps_header_start;

	ps_header_start =
		mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, rfd, 0);

	int             i_index = 0;
	char           *data;

	struct tpacket_hdr *ps_header;

	ps_header =
		((struct tpacket_hdr *)((void *)ps_header_start +
					(4096 * i_index)));
	data = ((void *)ps_header) + data_offset;
	memcpy(data, pio->iov_base, pio->iov_len);

	ps_header->tp_len = pio->iov_len;

	ps_header->tp_status = TP_STATUS_SEND_REQUEST;

	sent = sendto(rfd, NULL, 0, 0, (struct sockaddr *)&sll, s_ll);

	char           *s =
		extract_ip(((struct ip *)(pio->iov_base +
					  s_eth))->ip_src.s_addr);
	char           *d =
		extract_ip(((struct ip *)(pio->iov_base +
					  s_eth))->ip_dst.s_addr);
	printf("\nSENT | (%ld bytes) %s -> %s" "\n.......(seq %d) (ack %d)"
	       "\n.......(ports %d -> %d) (val/secr: %d %d )"
	       "\n.......(flags %s %s %s %s %s %s)" "\n.......(thread %p)\n",
	       sent, s, d, syn->p_seq, syn->p_ack, syn->p_src_port,
	       syn->p_dst_port, syn->p_tsval, syn->p_tsecr,
	       (syn->p_flags & TH_URG ? "URG" : ""),
	       (syn->p_flags & TH_SYN ? "SYN" : ""),
	       (syn->p_flags & TH_ACK ? "ACK" : ""),
	       (syn->p_flags & TH_PUSH ? "PSH" : ""),
	       (syn->p_flags & TH_RST ? "RST" : ""),
	       (syn->p_flags & TH_FIN ? "FIN" : ""), (void *)pthread_self());
}

#endif

void uni_raw_send(struct pkt_info_t *syn)
{
	struct iovec   *pio = build_raw(syn);
	ssize_t         sent;

	sent = write(syn->fd, pio->iov_base, pio->iov_len);

	char           *s =
		extract_ip(((struct ip *)(pio->iov_base +
					  s_eth))->ip_src.s_addr);
	char           *d =
		extract_ip(((struct ip *)(pio->iov_base +
					  s_eth))->ip_dst.s_addr);

	printf("\nSENT | (%ld bytes) %s -> %s"
	       "\n.......(seq %d) (ack %d)"
	       "\n.......(ports %d -> %d) (val/secr: %d %d )"
	       "\n.......(flags %s %s %s %s %s %s)"
	       "\n.......(thread %p)\n",
	       sent, s, d,
	       syn->p_seq, syn->p_ack,
	       syn->p_src_port, syn->p_dst_port,
	       syn->p_tsval, syn->p_tsecr,
	       (syn->p_flags & TH_URG ? "URG" : ""),
	       (syn->p_flags & TH_SYN ? "SYN" : ""),
	       (syn->p_flags & TH_ACK ? "ACK" : ""),
	       (syn->p_flags & TH_PUSH ? "PSH" : ""),
	       (syn->p_flags & TH_RST ? "RST" : ""),
	       (syn->p_flags & TH_FIN ? "FIN" : ""), (void *)pthread_self());
}
