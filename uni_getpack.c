#include "main.h"

char           *extract_ip(int addr)
{
	struct in_addr  proc;
	char           *ret = malloc(INET_ADDRSTRLEN + 1);

	proc.s_addr = addr;
	inet_ntop(AF_INET, &proc, ret, INET_ADDRSTRLEN);
	return ret;
}

struct tcp_timestamp extract_timestamp(int opt_len, char *opts)
{
	struct tcp_timestamp ret;
	uint32_t       *tsval = 0, *tsecr = 0;
	u_char         *p;
	unsigned int    op;
	unsigned int    oplen;
	unsigned int    len = 0;

	p = (u_char *) opts;
	len = opt_len;

	while (len > 0 && *p != TCPOPT_EOL) {
		op = *p++;
		if (op == TCPOPT_EOL)
			break;
		if (op == TCPOPT_NOP) {
			len--;
			continue;
		}
		oplen = *p++;
		if (oplen < 2)
			break;
		if (oplen > len)
			break;
		if (op == TCPOPT_TIMESTAMP && oplen == 10) {
			if (tsval) {
				memcpy((char *)tsval, p, 4);
				ret.tsval = *tsval;
			}
			p += 4;
			if (tsecr) {
				memcpy((char *)tsecr, p, 4);
				ret.tsecr = *tsecr;
			}
			return ret;
		}
		len -= oplen;
		p += oplen - 2;
	}
	return ret;
}

char           *get_packet(int fd)
{
	fd_set          rf;
	size_t          blen, rdct;
	char           *p, *buf;

#ifdef __APPLE__
	blen = 0;
	ioctl(fd, BIOCGBLEN, &blen);
#elif __linux__
	blen = 1460;
#endif

	buf = calloc(1, blen);
	FD_ZERO(&rf);
	FD_SET(fd, &rf);
	if ((select(fd + 1, &rf, NULL, NULL, NULL)) < 0)
		perror("select");
	if (FD_ISSET(fd, &rf)) {
		rdct = read(fd, buf, blen);
#ifdef __APPLE__
		struct bpf_hdr *bh = (struct bpf_hdr *)buf;

		p = buf + bh->bh_hdrlen;
#elif __linux__
		p = buf;
#endif
	}

	free(buf);

	return p;
}

int chk_ip_src(char *tcmp, struct ip_pair **syn)
{
	register char   cnt;

	for (cnt = 0; cnt < syn[0]->total; cnt++) {
		if (!(memcmp(tcmp, syn[cnt]->d_ip, strlen(tcmp))))
			return 1;
	}
	return 0;
}

int thread_destructor(char *_ip1, struct ip_pair **_ip2)
{

	register int    tc;

	for (tc = 0; tc < _ip2[0]->total; tc++) {
		if (memcmp(_ip2[tc]->d_ip, _ip1, strlen(_ip1))) {
			printf("Killing %p (%s) from %p (%s)\n",
			       (void *)_ip2[tc]->thread,
			       _ip2[tc]->d_ip, (void *)pthread_self(), _ip1);
			pthread_cancel(_ip2[tc]->thread);
		}
	}
	return tc;
}

int pack_parse(struct pkt_info_t *syn)
{
	while (1) {

		char           *p = get_packet(syn->fd);

		struct ether_header eth;
		struct ip       ip;
		struct tcphdr   tcp;
		char           *opts;

		memcpy(&eth, p, s_eth);
		if (eth.ether_type == 0x8) {
			memcpy(&ip, &p[s_eth], s_iph);
			if (ip.ip_p == 0x6) {
				memcpy(&tcp, &p[s_eth + s_iph], s_tcp);
				int             opt_len =
					((4 * tcp.th_off) - s_tcp);

				if (opt_len) {
					opts = malloc(opt_len + 1);
					memcpy(opts, &p[s_eth + s_iph + s_tcp],
					       opt_len);
				}

				char           *sip =
					extract_ip(ip.ip_src.s_addr);
				char           *dip =
					extract_ip(ip.ip_dst.s_addr);

				if (chk_ip_src(sip, syn->p_dst_ip)) {

					struct tcp_timestamp time;

					memset(&time, 0x0, s_tme);
					time = extract_timestamp(opt_len, opts);

					syn->p_seq = ntohl(tcp.th_seq);
					syn->p_ack = ntohl(tcp.th_ack);
					syn->p_tsval = ntohl(time.tsval) + 1;
					syn->p_tsecr = ntohl(time.tsecr);

					printf("\nRECV | (%d bytes) %s -> %s"
					       "\n.......(seq %d) (ack %d)"
					       "\n.......(ports %d -> %d) (val/secr: %d %d )"
					       "\n.......(flags %s %s %s %s %s %s) (options %d)"
					       "\n.......(thread %p)\n",
					       s_eth + s_iph + s_tcp + opt_len,
					       sip, dip,
					       syn->p_seq, syn->p_ack,
					       ntohs(tcp.th_sport),
					       ntohs(tcp.th_dport),
					       syn->p_tsval, syn->p_tsecr,
					       (tcp.
						th_flags & TH_URG ? "URG" : ""),
					       (tcp.
						th_flags & TH_SYN ? "SYN" : ""),
					       (tcp.
						th_flags & TH_ACK ? "ACK" : ""),
					       (tcp.
						th_flags & TH_PUSH ? "PSH" :
						""),
					       (tcp.
						th_flags & TH_RST ? "RST" : ""),
					       (tcp.
						th_flags & TH_FIN ? "FIN" : ""),
					       opt_len, (void *)pthread_self());

					if (syn->p_flags & TH_SYN)
						thread_destructor(sip,
								  syn->
								  p_dst_ip);
					return 1;
				}
			}
		}
	}
	return 0;
}
