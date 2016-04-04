#include "main.h"

char           *get_device()
{
	struct ifconf   conf;
	char            data[4096];
	char           *tmp_ip = malloc(INET_ADDRSTRLEN + 1);
	struct ifreq   *ifr;

	int             dg_fd = socket(AF_INET, SOCK_DGRAM, 0);

	conf.ifc_len = sizeof(data);
	conf.ifc_ifcu.ifcu_buf = data;

	ioctl(dg_fd, SIOCGIFCONF, &conf);
	ifr = (struct ifreq *)data;
	while ((char *)ifr < data + conf.ifc_len) {

		inet_ntop(AF_INET,
			  &((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr,
			  tmp_ip, INET_ADDRSTRLEN);

		if ((ifr->ifr_ifru.ifru_addr.sa_family == AF_INET) &&
		    (memcmp(tmp_ip, "127.0.0.1", 9))) {

			close(dg_fd);
			return ifr->ifr_name;
		}
		ifr = (struct ifreq *)((char *)ifr + _SIZEOF_ADDR_IFREQ(*ifr));
	}
	close(dg_fd);
	errno = ECONNRESET;
	die_with_signal("interface");
}

char           *get_local_ip(char *device)
{
	int             sockfd;
	struct ifreq    ifr;
	char           *str;
	struct sockaddr_in *ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	memcpy(ifr.ifr_name, device, IFNAMSIZ);
	ioctl(sockfd, SIOCGIFADDR, &ifr);

	ret = ((struct sockaddr_in *)&ifr.ifr_addr);
	str = (char *)malloc(INET_ADDRSTRLEN + 1);

	inet_ntop(AF_INET, &(ret->sin_addr), str, INET_ADDRSTRLEN);

	close(sockfd);
	return str;
}

struct ip_pair **get_peer_ip(char *hostname, char *port)
{
	struct ip_pair **tmp = malloc(20);

	struct hostent *he;
	struct in_addr **addr_list;

	register int    i;

	he = gethostbyname(hostname);
	addr_list = (struct in_addr **)he->h_addr_list;

	for (i = 0; addr_list[i] != NULL; i++) {

		tmp[i] = malloc(sizeof(struct ip_pair));
		tmp[i]->d_ip = malloc(INET_ADDRSTRLEN + 1);

		inet_ntop(AF_INET, (void *)addr_list[i], tmp[i]->d_ip,
			  INET_ADDRSTRLEN);
	}

	tmp[0]->total = i;

	for (; i < 20; i++)
		tmp[i] = NULL;

	return tmp;
}
