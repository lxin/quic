#include "core.h"

struct quic_message *quic_message_new(const uint8_t *data, uint32_t datalen, uint64_t stream_id,
				      uint32_t flags, uint64_t offset)
{
	struct quic_message *msg;

	msg = malloc(sizeof(*msg));
	if (!msg)
		return NULL;
	msg->data = malloc(datalen);
	if (!msg->data) {
		free(msg);
		return NULL;
	}
	INIT_LIST_HEAD(&msg->list);
	memcpy(msg->data, data, datalen);
	msg->datalen = datalen;
	msg->stream_id = stream_id;
	msg->flags = flags;
	msg->offset = offset;
	return msg;
}

static void quic_message_free(struct quic_message *msg)
{
	free(msg->data);
	free(msg);
}

static void quic_message_sndq_enqueue(struct quic_connection *conn, struct quic_message *msg)
{
	list_add_tail(&conn->sndq, &msg->list);
}

void quic_message_rcvq_enqueue(struct quic_connection *conn, struct quic_message *msg)
{
	list_add_tail(&conn->rcvq, &msg->list);
}

struct quic_message *quic_message_sndq_dequeue(struct quic_connection *conn)
{
	struct quic_message *msg;

	if (list_empty(&conn->sndq))
		return NULL;

	msg = list_first_entry(&conn->sndq, struct quic_message, list);
	list_del_init(&msg->list);

	return msg;
}

static struct quic_message *quic_message_rcvq_dequeue(struct quic_connection *conn)
{
	struct quic_message *msg;

	if (list_empty(&conn->rcvq))
		return NULL;

	msg = list_first_entry(&conn->rcvq, struct quic_message, list);
	list_del_init(&msg->list);

	return msg;
}

int quic_send_message(struct quic_connection *conn, int64_t *stream_id, char *data, size_t datalen)
{
	int flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
	struct quic_message *msg;

	msg = quic_message_new(data, datalen, *stream_id, flags, 0);
	if (!msg)
		return -1;
	quic_message_sndq_enqueue(conn, msg);
	ev_async_send(conn->ep->loop, &conn->aev);

	while (!list_empty(&msg->list))
		;

	*stream_id = msg->stream_id;
	quic_message_free(msg);
	return datalen;
}

int quic_recv_message(struct quic_connection *conn, int64_t *stream_id, char *data, size_t datalen)
{
	struct quic_message *msg = NULL;

	while (!msg)
		msg = quic_message_rcvq_dequeue(conn);

	datalen = msg->datalen;
	*stream_id = msg->stream_id;
	memcpy(data, msg->data, datalen);

	quic_message_free(msg);
	return datalen;
}
