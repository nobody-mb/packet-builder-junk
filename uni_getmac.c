#include "main.h"

void send_probe(char *ip, char *port)
{
	int             probe_fd;

	if ((probe_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		die_with_signal("socket");

	struct sockaddr_in temp;

	memset(&temp, 0x00, sizeof(temp));

	temp.sin_family = AF_INET;
	temp.sin_port = htons(atoi(port));
	temp.sin_addr.s_addr = inet_addr(ip) + 1;

	/*
	 *assuming that the +1 operator will not land on the same host, 
	 *let the kernel fill in the data we need 
	 */
	if (sendto
	    (probe_fd, "/x01", 1, 0, (struct sockaddr *)&temp,
	     sizeof(temp)) < 0)
		die_with_signal("sendto");

	close(probe_fd);
}

struct ether_header *uni_get_mac(int fd, char *ip, char *port)
{
	char           *buf, *p;
	ssize_t         blen;

#ifdef __APPLE__
	ioctl(fd, BIOCGBLEN, &blen);
#elif __linux__
	blen = 1460;
#endif

	buf = malloc(blen + 1);

	send_probe(ip, port);

	if (read(fd, buf, blen) < 0)
		die_with_signal("read");

#ifdef __APPLE__
	struct bpf_hdr *bh = (struct bpf_hdr *)buf;

	p = buf + bh->bh_hdrlen;
#elif __linux__
	p = buf;
#endif

	struct ether_header *eh = calloc(1, sizeof(*eh));

	memcpy(eh, p, s_eth);
	memset(eh->ether_dhost, 0xff, ETH_ALEN);
	return eh;

}
