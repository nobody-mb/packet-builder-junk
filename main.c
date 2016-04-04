#include "main.h"

#ifdef __linux__
#include "uni_connect.c"
#include "uni_getpack.c"
#include "uni_buildpack.c"
#include "uni_getmac.c"
#include "opts.c"
#include "uni_getip.c"
#endif

void h_mac_quit(int sig)
{
	switch (sig) {
	case SIGINT:
		printf("\nReceived interrupt by user...quitting\n");
		break;
	case SIGSEGV:
		printf("\nSegmentation fault...quitting\n");
		break;
	case SIGUSR1:
		printf("Quitting\n");
		break;
	}
	raise(SIGKILL);
}

int init_socket(char *device)
{
	int             rfd;

#ifdef __APPLE__

	unsigned int    i = 0;
	char           *dev = calloc(1, 32);

	for (i = 0; i < 255; i++) {
		sprintf(dev, "/dev/bpf%i", i);
		printf("Initializing %s\n", dev);
		rfd = open(dev, O_RDWR);
		if (rfd > -1) {
			struct ifreq    ifr;
			u_int32_t       enable = 1;

			strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);

			if (ioctl(rfd, BIOCSETIF, &ifr) < 0)
				die_with_signal("setif");
			if (ioctl(rfd, BIOCSHDRCMPLT, &enable) < 0)
				die_with_signal("hdrcmplt");
			if (ioctl(rfd, BIOCSSEESENT, &enable) < 0)
				die_with_signal("seesent");
			if (ioctl(rfd, BIOCIMMEDIATE, &enable) < 0)
				die_with_signal("immediate");

			return rfd;
		}
	}

#elif __linux__

	if ((rfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		die_with_signal("socket");

	register int    s_ll = sizeof(struct sockaddr_ll);

	struct sockaddr_ll *sll = calloc(1, s_ll);
	struct ifreq   *ifr = calloc(1, sizeof(struct ifreq));

	memcpy(ifr->ifr_name, device, IFNAMSIZ);

	ioctl(rfd, SIOCGIFINDEX, ifr);

	sll->sll_family = PF_PACKET;
	sll->sll_ifindex = ifr->ifr_ifindex;
	sll->sll_protocol = htons(ETH_P_ALL);

	if ((bind(rfd, (struct sockaddr *)sll, s_ll)) < 0)
		die_with_signal("bind");

#endif
	return rfd;
}

struct pkt_info_t init_and_connect(char *host, char *port)
{

	struct pkt_info_t ret;

	memset(&ret, 0x00, sizeof(struct pkt_info_t));

	char           *device = get_device();

	printf("Got interface: %s\n", device);

	ret.fd = init_socket(device);
	printf("Got socket\n");

	ret.p_src_ip = get_local_ip(device);
	printf("Got local IP: %s\n", ret.p_src_ip);

	ret.p_dst_ip = get_peer_ip(host, port);

	register int    i;

	for (i = 0; i < ret.p_dst_ip[0]->total; i++)
		printf("Got peer IP #%d: %s\n", i, ret.p_dst_ip[i]->d_ip);

	ret.p_src_port = ((arc4random() % 32768) + 32768);
	printf("Got local port: %d\n", ret.p_src_port);

	ret.p_dst_port = atoi(port);
	printf("Got peer port: %d\n", ret.p_dst_port);

	struct ether_header *eh =
		uni_get_mac(ret.fd, ret.p_dst_ip[0]->d_ip, port);

	memcpy(ret.p_src_mac, eh->ether_shost, ETH_ALEN);
	memcpy(ret.p_dst_mac, eh->ether_dhost, ETH_ALEN);

	printf("Got local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eh->ether_shost[0], eh->ether_shost[1],
	       eh->ether_shost[2], eh->ether_shost[3],
	       eh->ether_shost[4], eh->ether_shost[5]);

	printf("Got peer MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eh->ether_dhost[0], eh->ether_dhost[1],
	       eh->ether_dhost[2], eh->ether_dhost[3],
	       eh->ether_dhost[4], eh->ether_dhost[5]);

	return ret;

}

static int builtin_tcp_connect(char *ip, char *port) {

	int tmpfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in use;
	memset(&use, 0x0, sizeof(struct sockaddr_in));
	inet_aton(ip, &use.sin_addr);
	use.sin_family = AF_INET;
	use.sin_port = htons(atoi(port));
	connect(tmpfd, (struct sockaddr *)&use, sizeof(struct sockaddr_in));
	return tmpfd;
}

int main(int argc, char **argv)
{
	signal(SIGINT, &h_mac_quit);
	signal(SIGUSR1, &h_mac_quit);
	signal(SIGSEGV, &h_mac_quit);

#define _TEST
#undef _TEST
	if (getuid() && geteuid())
		die_with_signal("not root");
#ifdef _TEST
	builtin_tcp_connect("192.168.1.102","80");	
#else
	struct pkt_info_t pass = init_and_connect("www.google.com", "80");
	p_connect(&pass);
	close(pass.fd);
#endif
	return 0;
}
