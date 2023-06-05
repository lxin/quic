#include "core.h"

int quic_connection_write(struct quic_connection *conn)
{
	int ret, flags = NGTCP2_WRITE_STREAM_FLAG_FIN, pos = 0, count = 0, stream_id = -1;
	struct quic_message *msg;
	ngtcp2_vec datav = {};
	ngtcp2_path_storage p;
	ngtcp2_pkt_info pi;
	ngtcp2_ssize len;
	uint8_t buf[2000];

	ngtcp2_path_storage_zero(&p);

	msg = quic_message_sndq_dequeue(conn);
	if (msg) {
		if (msg->stream_id == -1 &&
		    ngtcp2_conn_open_uni_stream(conn->conn, &msg->stream_id, NULL)) {
			printf("open stream failed\n");
			return -1;
		}
		datav.base = msg->data;
		datav.len = msg->datalen;
		flags = msg->flags;
		count = 1;
		stream_id = msg->stream_id;
	}

	while (1) {
		ret = ngtcp2_conn_writev_stream(conn->conn, &p.path, &pi, &buf[pos],
						sizeof(buf) - pos, &len, flags, stream_id,
						&datav, count, time(NULL));
		if (ret < 0) {
			printf("ngtcp2_conn_writev_stream failed %d\n", ret);
			return -1;
		}
		pos += ret;
		if (!pos)
			return 0;
		if (ret == 0 || ret < 1200 || conn->state == QUIC_STATE_CONNECTED) {
			ret = sendto(conn->ep->sockfd, buf, pos, 0,
				     (struct sockaddr *)&conn->ra, sizeof(conn->ra));
			break;
		}
	}

	return ret;
}

static void quic_connection_async_cb(struct ev_loop *loop, ev_async *e, int aevents)
{
	struct quic_connection *conn = e->data;

	if (conn->is_ready) {
		quic_connection_write(conn);
		return;
	}
	list_del(&conn->list);
	free(conn);
}

static void *quic_connection_thread(void *arg)
{
	struct quic_endpoint *ep = arg;

	ep->loop = EV_DEFAULT;

	ev_io_init(&ep->rev, quic_endpoint_read_cb, ep->sockfd, EV_READ);
	ep->rev.data = ep;
	ev_io_start(ep->loop, &ep->rev);

	ev_async_init(&ep->aev, quic_endpoint_async_cb);
	ep->aev.data = ep;
	ev_async_start(ep->loop, &ep->aev);

	if (!ep->is_serv) {
		struct quic_connection *conn;

		conn = list_first_entry(&ep->conns, struct quic_connection, list);
		ev_async_init(&conn->aev, quic_connection_async_cb);
		conn->aev.data = conn;
		ev_async_start(ep->loop, &conn->aev);

		quic_connection_write(conn);
	}

	ev_run(ep->loop, 0);
	return quic_endpoint_accept_conn(ep);
}

struct quic_connection *quic_connection_new(struct quic_endpoint *ep,
					    struct sockaddr_in *a, ngtcp2_pkt_hd *hd)
{
	struct quic_connection *conn;

	conn = malloc(sizeof(*conn));
	if (!conn)
		return NULL;
	memset(conn, 0, sizeof(*conn));
	memcpy(&conn->la, &ep->a, sizeof(*a));
	memcpy(&conn->ra, a, sizeof(*a));
	quic_endpoint_add_conn(ep, conn);

	if (quic_ngtcp2_conn_init(conn, hd)) {
		free(conn);
		return NULL;
	}
	INIT_LIST_HEAD(&conn->sndq);
	INIT_LIST_HEAD(&conn->rcvq);
	return conn;
}

struct quic_connection *quic_start_connection(struct quic_endpoint *ep, char *ip, uint16_t port)
{
	struct quic_connection *conn;
	struct sockaddr_in a = {};
	int ret, len, state;

	a.sin_family = AF_INET;
	a.sin_port = htons(port);
	inet_pton(AF_INET, ip, &a.sin_addr.s_addr);

	if (!ep->a.sin_port) { /* do autobind */
		struct sockaddr_in sa = {};

		ret = connect(ep->sockfd, (struct sockaddr *)&a, sizeof(a));
		if (ret)
			return NULL;
		len = sizeof(sa);
		ret = getsockname(ep->sockfd, (struct sockaddr *)&sa, &len);
		if (ret)
			return NULL;
		memcpy(&ep->a, &sa, sizeof(sa));
	}

	if (ep->is_kern)  {
		state = QUIC_STATE_USER_CONNECTING;
		ret = setsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_STATE, &state, sizeof(state));
		if (ret)
			return NULL;
	}

	conn = quic_connection_new(ep, &a, NULL);
	if (!conn)
		return NULL;
	if (ep->is_kern) {
		conn = quic_connection_thread(ep);
		if (!conn)
			return NULL;
		if (quic_kernel_socket_setup(conn, 1))
			return NULL;
		return conn;
	}

	ret = pthread_create(&ep->thread, NULL, quic_connection_thread, (void *)ep);
	if (ret) {
		printf("pthread_create failed\n");
		return NULL;
	}

	while (!conn->is_ready)
		;

	return conn;
}

struct quic_connection *quic_accept_connection(struct quic_endpoint *ep)
{
	struct quic_connection *conn;
	int ret;

	if (ep->is_kern) {
		conn = quic_connection_thread(ep);
		if (!conn)
			return NULL;
		if (quic_kernel_socket_setup(conn, 0))
			return NULL;
		return conn;
	}

	if (!ep->thread) {
		ret = pthread_create(&ep->thread, NULL, quic_connection_thread, (void *)ep);
		if (ret) {
			printf("pthread_create failed\n");
			return NULL;
		}
	}

	while (1) {
		conn = quic_endpoint_accept_conn(ep);
		if (conn)
			break;
	}

	while (!conn->is_ready)
		;

	return conn;
}

int quic_close_connection(struct quic_connection *conn)
{
	conn->is_ready = 0;
	ev_async_send(conn->ep->loop, &conn->aev);
}

int quic_connection_sockfd(struct quic_connection *conn)
{
	return conn->sockfd;
}
