#include "main.h"

pthread_key_t index_ips(struct ip_pair **p)
{
	pthread_key_t   key;

	pthread_key_create(&key, NULL);
	register int8_t i;

	for (i = 0; i <= p[0]->total; i++) {
		if (pthread_equal(pthread_self(), p[i]->thread)) {
			pthread_setspecific(key, p[i]->d_ip);
			return key;
		}
	}
	return 0;
}

void           *func_probe(void *vd)
{
	struct pkt_info_t *syn = (struct pkt_info_t *)vd;

	pthread_key_t   i;

	pthread_mutex_lock(&syn->mutex);

	while (syn->tcm < syn->p_dst_ip[0]->total) {

		i = index_ips(syn->p_dst_ip);
		char           *ip = pthread_getspecific(i);

		printf("Using IP %s on thread %p (#%d)\n", ip,
		       (void *)pthread_self(), syn->tcm);

		pthread_cond_wait(&syn->cond, &syn->mutex);
	}
	pthread_mutex_unlock(&syn->mutex);

	syn->p_seq = (int)(arc4random() % MAX_SEQ);
	syn->p_ack = 0;

	syn->p_flags = TH_SYN;
	syn->p_tsval = 0;
	syn->p_tsecr = 0;

	uni_raw_send(syn);

	pack_parse(syn);

	syn->p_flags = TH_ACK;

	uni_raw_send(syn);

	pack_parse(syn);

	pthread_exit(NULL);

}

void p_connect(struct pkt_info_t *pass)
{
	register int    tc = 0;
	register int    tp = pass->p_dst_ip[0]->total;

	pthread_mutex_init(&pass->mutex, NULL);
	pthread_cond_init(&pass->cond, NULL);

	for (pass->tcm = 0; pass->tcm < tp; pass->tcm++) {
		pthread_create(&pass->p_dst_ip[pass->tcm]->thread,
			       NULL, func_probe, (void *)pass);
		printf("Spawned thread %p (#%d)\n",
		       (void *)pass->p_dst_ip[pass->tcm]->thread, pass->tcm);

	}

	pthread_cond_broadcast(&pass->cond);

	for (tc = 0; tc < tp; tc++) {
		pthread_join(pass->p_dst_ip[tc]->thread, NULL);
	}

	printf("\nDONE |: "
	       "\n.......(seq %d) (ack %d)"
	       "\n.......(ports %d -> %d) (val/secr: %d %d )\n",
	       (pass->p_seq), (pass->p_ack),
	       (pass->p_src_port), (pass->p_dst_port),
	       pass->p_tsval, pass->p_tsecr);

	pthread_mutex_destroy(&pass->mutex);
	pthread_cond_destroy(&pass->cond);

}
