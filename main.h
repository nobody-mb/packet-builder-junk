
#ifndef _MAIN_H
#define _MAIN_H

#ifdef __linux__

#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#else
#include <net/bpf.h>
#include <sys/kernel.h>
#include <sys/times.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/syscall.h>

#include <net/if.h>
#include <net/ethernet.h>

#include <netdb.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include <signal.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <errno.h>

#define die_with_signal(z) do { 										\
						printf("*ERROR*\n"								\
							   "\n...file \"%s\"" 						\
							   "\n...function \"%s\""  					\
							   "\n...line %d" 							\
							   "\n...Description: %s"    				\
							   "\n...Full Error: %s\n"					\
							   ,__FILE__,__func__,__LINE__,z,			\
							   strerror(errno)); 						\
							   exit(SIGUSR1); 							\
							   } while (0)

#define SA_LEN(sa) __libc_sa_len(((struct sockaddr)(sa)).sa_family)

#ifndef _SIZEOF_ADDR_IFREQ
#define _SIZEOF_ADDR_IFREQ(ifr) \
        (SA_LEN((ifr).ifr_addr) > sizeof(struct sockaddr) ? \
         (sizeof(struct ifreq) - sizeof(struct sockaddr) + \
          SA_LEN((ifr).ifr_addr)) : sizeof(struct ifreq))
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct tcp_timestamp {
	char            kind;
	char            length;
	uint32_t tsval __attribute__ ((__packed__));
	uint32_t tsecr __attribute__ ((__packed__));
	//char            padding[2];
};

struct tcp_winscale {
	uint8_t         kind;
	uint8_t         length;
	uint8_t         shift;
};

struct pseudo_hdr {
	unsigned long int src;
	unsigned long int dst;
	unsigned char   zero;
	unsigned char   protocol;
	unsigned short int tcplen;
};

struct tcp_sack {
	uint8_t         olen;
	uint8_t         mlen;
};

struct tcp_mss {
	char            kind;
	char            length;
	uint16_t mss __attribute__ ((__packed__));
};

#define S_SYN_SENT 0x01
#define S_SYN_RCVD 0x02
#define S_ACK_SENT 0x04
#define S_ACK_RCVD 0x08

struct ip_pair {
	pthread_t       thread;
	uint8_t         total;
	char           *d_ip;
};

struct pkt_info_t {

	pthread_cond_t  cond;
	char            tcm;
	pthread_mutex_t mutex;

	int             fd;

	uint8_t         p_src_mac[ETH_ALEN];
	uint8_t         p_dst_mac[ETH_ALEN];

	char           *p_src_ip;
	struct ip_pair **p_dst_ip;

	uint16_t        p_src_port;
	uint16_t        p_dst_port;

	uint32_t        p_tsval;
	uint32_t        p_tsecr;

	uint32_t        p_ack;
	uint32_t        p_seq;

	uint32_t        p_flags;

	char           *opts;
	char           *(*build_opt) (uint32_t, uint32_t);
	uint32_t        opt_len;

	char           *data;
	uint32_t        data_len;

};

enum sizes_default {
	s_iov = sizeof(struct iovec),
	s_psh = sizeof(struct pseudo_hdr),
	s_eth = sizeof(struct ether_header),
	s_iph = sizeof(struct ip),
	s_tcp = sizeof(struct tcphdr)
};

enum sizes_opts {
	s_wsc = sizeof(struct tcp_winscale),
	s_sck = sizeof(struct tcp_sack),
	s_tme = sizeof(struct tcp_timestamp),
	s_mss = sizeof(struct tcp_mss)
};

#define MAX_SEQ 4294967296
#define MIN_P 1024
#define MAX_P 65535

char           *build_tcp_mss(uint32_t len);
char           *build_tcp_timestamp(uint32_t tsval, uint32_t tsecr);
char           *build_tcp_sack();
char           *build_tcp_window();
char           *build_syn_ops(uint32_t tsval, uint32_t tsecr);
char           *build_ack_ops(uint32_t tsval, uint32_t tsecr);

pthread_key_t   index_ips(struct ip_pair **p);
void            h_mac_quit(int sig);

int             init_socket(char *device);
struct pkt_info_t init_and_connect(char *host, char *port);

static uint16_t checksum_comp(uint16_t * addr, int len);
long            get_tcp_checksum_2(struct iovec *pio, struct ip ip,
				   struct tcphdr tcp, char *opts, char *data,
				   int opt_len, int data_len);
void            build_eth_hdr(struct iovec *pio, uint8_t * src, uint8_t * dst);
void            build_ip_hdr(struct iovec *pio, uint32_t len, char *src,
			     struct ip_pair **dst);
char           *build_tcp_hdr(struct iovec *pio, uint16_t sport, uint16_t dport,
			      uint32_t seq, uint32_t ack, uint32_t optlen,
			      uint32_t flags, char *opts, char *data,
			      int opt_len, int data_len);
struct iovec   *build_raw(struct pkt_info_t *syn);
void            uni_raw_send(struct pkt_info_t *syn);

void           *func_probe(void *vd);
void            p_connect(struct pkt_info_t *pass);

char           *get_device();
char           *get_local_ip(char *device);
struct ip_pair **get_peer_ip(char *hostname, char *port);

void            send_probe(char *ip, char *port);
struct ether_header *uni_get_mac(int fd, char *ip, char *port);

char           *extract_ip(int addr);
struct tcp_timestamp extract_timestamp(int opt_len, char *opts);
char           *get_packet(int fd);
int             chk_ip_src(char *tcmp, struct ip_pair **syn);
int             pack_parse(struct pkt_info_t *syn);
int             thread_destructor(char *_ip1, struct ip_pair **_ip2);

#endif

/*
*Indent settings: 
indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4 -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l80 -lp -npcs -nprs -npsl -sai -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1 uni_getmac.c
*/
