#include "core.h"

struct quic_endpoint *quic_create_endpoint(char *ip, uint16_t port, uint8_t is_serv,
					   uint8_t is_kern)
{
	struct sockaddr_in a = {};
	struct quic_endpoint *ep;
	int sd, proto, state;

	proto = is_kern ? IPPROTO_QUIC : 0;
	sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, proto);
	if (sd < 0) {
		printf("socket creation failed\n");
		return NULL;
	}

	ep = malloc(sizeof(*ep));
	if (!ep)
		return NULL;
	memset(ep, 0, sizeof(*ep));
	INIT_LIST_HEAD(&ep->conns);
	ep->sockfd = sd;
	ep->is_serv = is_serv;
	ep->is_kern = is_kern;
	if (!port)
		return ep;

	a.sin_family = AF_INET;
	a.sin_port = htons(port);
	inet_pton(AF_INET, ip, &a.sin_addr.s_addr);
	if (bind(sd, (struct sockaddr *)&a, sizeof(a))) {
		printf("socket bind failed\n");
		return NULL;
	}
	memcpy(&ep->a, &a, sizeof(a));

	if (is_serv && is_kern)  {
		state = QUIC_STATE_USER_CONNECTING;
		if (setsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_STATE, &state, sizeof(state))) {
			printf("socket listen failed\n");
			return NULL;
		}
	}
	return ep;
}

void quic_endpoint_add_conn(struct quic_endpoint *ep, struct quic_connection *conn)
{
	conn->ep = ep;
	list_add_tail(&conn->list, &ep->conns);
}

static struct quic_connection *quic_endpoint_get_conn_byaddr(struct quic_endpoint *ep,
							     struct sockaddr_in *a)
{
	struct quic_connection *conn;

	if (!ep->is_serv)
		return list_first_entry(&ep->conns, struct quic_connection, list);

	list_for_each_entry(conn, &ep->conns, list) {
		if (!memcmp(&conn->ra, a, sizeof(*a)))
			return conn;
	}
	return NULL;
}

struct quic_connection *quic_endpoint_accept_conn(struct quic_endpoint *ep)
{
	struct quic_connection *conn;

	list_for_each_entry(conn, &ep->conns, list) {
		if (!conn->is_accept) {
			conn->is_accept = 1;
			return conn;
		}
	}
	return NULL;
}

static int quic_endpoint_read(struct quic_endpoint *ep)
{
	struct quic_connection *conn = NULL;
	int state, ret, len, count = 0;
	struct sockaddr_in a = {};
	ngtcp2_pkt_info pi = {0};
	ngtcp2_path_storage ps;
	ngtcp2_pkt_hd hd;
	uint8_t buf[2000];

	do {
		len = sizeof(a);
		ret = recvfrom(ep->sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&a, &len);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return count;
			printf("recvfrom failed\n");
			return count;
		}
		conn = quic_endpoint_get_conn_byaddr(ep, &a);
		if (!conn) {
			if (ngtcp2_accept(&hd, buf, ret))
				return count;
			conn = quic_connection_new(ep, &a, &hd);
			if (!conn)
				return count;
		}
		state = conn->state;
		ngtcp2_path_storage_init(&ps, (void *)&conn->la, sizeof(a), (void *)&conn->ra,
					 sizeof(a), NULL);
		ret = ngtcp2_conn_read_pkt(conn->conn, &ps.path, &pi, buf, ret, time(NULL));
		if (ret) {
			printf("ngtcp2_conn_read_pkt failed %d\n", ret);
			return count;
		}
		if (!(buf[0] & 0x80))
			conn->is_ready = 1;
		conn->is_read = 1;
		count++;
	} while (conn->state == state);

	return count;
}

void quic_endpoint_read_cb(struct ev_loop *loop, ev_io *e, int events)
{
	struct quic_endpoint *ep = e->data;
	struct quic_connection *conn;

	if (!quic_endpoint_read(ep))
		return;

	list_for_each_entry(conn, &ep->conns, list) {
		if (!conn->is_read)
			continue;
		if (ep->is_kern && !conn->is_accept && conn->is_ready) {
			ev_break(ep->loop, EVBREAK_ALL);
			return;
		}
		quic_connection_write(conn);
		conn->is_read = 0;
	}
}

void quic_endpoint_async_cb(struct ev_loop *loop, ev_async *e, int events)
{
	struct quic_endpoint *ep = e->data;

	ev_break(ep->loop, EVBREAK_ALL);
}

int quic_release_endpoint(struct quic_endpoint *ep)
{
	struct quic_connection *conn, *tmp;
	long ret = 0;

	ev_async_send(ep->loop, &ep->aev);

	if (!ep->is_kern && pthread_join(ep->thread, (void *)&ret) != 0) {
		printf("pthread_join failed\n");
		return -1;
	}

	list_for_each_entry_safe(conn, tmp, &ep->conns, list) {
		list_del(&conn->list);
		free(conn);
	}

	free(ep);
	return ret;
}

int quic_config_endpoint(struct quic_endpoint *ep, uint8_t optname, char *opt, int len)
{
	switch (optname) {
	case QUIC_CONFIG_PRIVATE_KEY:
		memcpy(ep->private_key, opt, len);
		break;
	case QUIC_CONFIG_CERTIFICATE:
		memcpy(ep->certificate, opt, len);
		break;
	default:
		return -1;
	}
	return 0;
}
