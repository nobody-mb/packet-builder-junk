#include "main.h"

char           *build_tcp_mss(uint32_t len)
{
	struct tcp_mss  mss;
	char           *ret = malloc(s_mss + 1);

	memset(&mss, TCPOPT_NOP, s_mss);

	mss.kind = TCPOPT_MAXSEG;
	mss.length = TCPOLEN_MAXSEG;
	mss.mss = htons(len);

	memcpy(ret, &mss, s_mss);
	return ret;
}

char           *build_tcp_timestamp(uint32_t tsval, uint32_t tsecr)
{
	struct tcp_timestamp time;
	char           *ret = malloc(s_tme + 1);

	memset(&time, TCPOPT_NOP, s_tme);

	if (!tsval) {
		struct timeval  now;

		gettimeofday(&now, NULL);
		time.tsval = htonl((uint32_t) now.tv_sec);
	} else {
		time.tsval = htonl(tsval);
	}
	time.tsecr = htonl(tsecr);
	time.kind = TCPOPT_TIMESTAMP;
	time.length = TCPOLEN_TIMESTAMP;

	memcpy(ret, &time, s_tme);
	return ret;
}

char           *build_tcp_sack()
{
	struct tcp_sack sack;
	char           *ret = malloc(s_sck + 1);

	memset(&sack, TCPOPT_EOL, s_sck);

	sack.mlen = TCPOLEN_SACK_PERMITTED;
	sack.olen = TCPOPT_SACK_PERMITTED;

	memcpy(ret, &sack, s_sck);
	return ret;
}

char           *build_tcp_window()
{
	struct tcp_winscale win;
	char           *ret = malloc(s_wsc + 1);

	win.kind = TCPOPT_WINDOW;
	win.length = TCPOPT_WINDOW;
	win.shift = 7;

	memcpy(ret, &win, s_wsc);
	return ret;
}

char           *build_syn_ops(uint32_t tsval, uint32_t tsecr)
{
	uint32_t        remaining = 40;

	char           *m = build_tcp_mss(1460);

	//remaining -= TCPOLEN_MSS_ALIGNED;     /* 4 */

	char           *t = build_tcp_timestamp(tsval, tsecr);

	//remaining -= TCPOLEN_TSTAMP_ALIGNED; /* 12 */

	char           *w = build_tcp_window();

	//remaining -= TCPOLEN_WSCALE_ALIGNED; /* 4 */

	char           *s = build_tcp_sack();

	//remaining -= TCPOLEN_SACKPERM_ALIGNED; /* 4 */

	char           *tcpopt = malloc(21);

	memset(tcpopt, TCPOPT_NOP, 20);

	memcpy(tcpopt, m, s_mss);
	memcpy(tcpopt + s_mss, s, s_sck);
	memcpy(tcpopt + s_mss + s_sck, t, s_tme);
	memcpy(tcpopt + s_mss + s_sck + s_tme + 1, w, s_wsc);

	return tcpopt;
}

char           *build_ack_ops(uint32_t tsval, uint32_t tsecr)
{

	char           *tcpopt = malloc(12);

	memset(tcpopt, TCPOPT_NOP, 12);
	char           *t = build_tcp_timestamp(tsval, tsecr);

	memcpy(tcpopt + 2, t, s_tme);
	return tcpopt;
}
