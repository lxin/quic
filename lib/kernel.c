#include <fcntl.h>
#include <errno.h>
#include "core.h"

static int quic_kernel_socket_set_blocking(int sockfd)
{
	int flags = fcntl(sockfd, F_GETFL, 0);
	int ret;

	if (flags == -1)
		return -1;

	flags &= ~O_NONBLOCK;
	ret = fcntl(sockfd, F_SETFL, flags);
	if (ret == -1)
		return -1;

	return 0;
}

static int quic_kernel_socket_setup_cids(struct quic_connection *conn)
{
	int sd = conn->sockfd, count, i, err;
	struct quic_connection_id cid = {};
	const ngtcp2_cid *dest;
	ngtcp2_cid source[3];

	count = ngtcp2_conn_get_scid(conn->conn, source);
	for (i = 0; i < count; i++) {
		cid.number = i;
		cid.len = source[i].datalen;
		memcpy(cid.data, source[i].data, cid.len);
		err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_SOURCE_CONNECTION_ID,
				 &cid, sizeof(cid));
		if (err < 0) {
			qlog("%s ERR %d\n", __func__, errno);
			return -1;
		}
	}

	dest = ngtcp2_conn_get_dcid(conn->conn);
	if (!dest)
		return -1;

	cid.number = 1;
	cid.len = dest->datalen;
	memcpy(cid.data, dest->data, cid.len);
	err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_DEST_CONNECTION_ID,
			&cid, sizeof(cid));
	if (err < 0) {
		qlog("%s ERR %d\n", __func__, errno);
		return -1;
	}

	qlog("%s CONNECTION IDS DONE\n", __func__);
	return 0;
}

static int quic_kernel_socket_setup_addrs(struct quic_connection *conn)
{
	int sd = conn->sockfd, err;

	err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_SOURCE_ADDRESS,
			 &conn->la, sizeof(conn->la));
	if (err < 0) {
		qlog("%s SOURCE ERR %d\n", __func__, errno);
		return -1;
	}

	err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_DEST_ADDRESS,
			 &conn->ra, sizeof(conn->ra));
	if (err < 0) {
		qlog("%s DEST ERR %d\n", __func__, errno);
		return -1;
	}
	qlog("%s ADDRESS DONE\n", __func__);

	return 0;
}

static int quic_kernel_socket_setup_transport_params(struct quic_connection *conn)
{
	struct quic_transport_param param = {};
	const ngtcp2_transport_params *p;
	int sd = conn->sockfd, err;

	p = ngtcp2_conn_get_local_transport_params(conn->conn);
	param.max_udp_payload_size = p->max_udp_payload_size;
	param.ack_delay_exponent = p->ack_delay_exponent;
	param.max_ack_delay = p->max_ack_delay / NGTCP2_MICROSECONDS;
	param.initial_max_data = p->initial_max_data;
	param.initial_max_stream_data_bidi_local = p->initial_max_stream_data_bidi_local;
	param.initial_max_stream_data_bidi_remote = p->initial_max_stream_data_bidi_remote;
	param.initial_max_stream_data_uni = p->initial_max_stream_data_uni;
	param.initial_max_streams_bidi = p->initial_max_streams_bidi;
	param.initial_max_streams_uni = p->initial_max_streams_uni;
	param.initial_smoothed_rtt = conn->connected_ts - conn->connecting_ts;
	err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_LOCAL_TRANSPORT_PARAMS, &param, sizeof(param));
	if (err < 0) {
		qlog("%s LOCAL ERR %d\n", __func__, errno);
		return -1;
	}
	p = ngtcp2_conn_get_remote_transport_params(conn->conn);
	param.max_udp_payload_size = p->max_udp_payload_size;
	param.ack_delay_exponent = p->ack_delay_exponent;
	param.max_ack_delay = p->max_ack_delay / NGTCP2_MICROSECONDS;
	param.initial_max_data = p->initial_max_data;
	param.initial_max_stream_data_bidi_local = p->initial_max_stream_data_bidi_local;
	param.initial_max_stream_data_bidi_remote = p->initial_max_stream_data_bidi_remote;
	param.initial_max_stream_data_uni = p->initial_max_stream_data_uni;
	param.initial_max_streams_bidi = p->initial_max_streams_bidi;
	param.initial_max_streams_uni = p->initial_max_streams_uni;
	err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_PEER_TRANSPORT_PARAMS, &param, sizeof(param));
	if (err < 0) {
		qlog("%s REMOTE ERR %d\n", __func__, errno);
		return -1;
	}
	qlog("%s TRANSPORT PARAMS DONE\n", __func__);
	return 0;
}

static int quic_kernel_socket_setup_crypto_keys(struct quic_connection *conn)
{
	int sd = conn->sockfd, err;

	err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_RECV_SECRET,
			 conn->secret[0].key, conn->secret[0].keylen);
	if (err < 0) {
		qlog("%s RECV ERR %d\n", __func__, errno);
		return -1;
	}
	err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SEND_SECRET,
			 conn->secret[1].key, conn->secret[1].keylen);
	if (err < 0) {
		qlog("%s SEND ERR %d\n", __func__, errno);
		return -1;
	}
	qlog("%s CRYPTO KEYS DONE\n", __func__);
	return 0;
}

static int quic_kernel_socket_setup_state(struct quic_connection *conn)
{
	int sd = conn->sockfd, err;
	uint8_t state;

	state = conn->ep->is_serv ? QUIC_STATE_SERVER_CONNECTED : QUIC_STATE_CLIENT_CONNECTED;

	err = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_STATE, &state, sizeof(state));
	if (err < 0) {
		qlog("%s STATE ERR %d\n", __func__, errno);
		return -1;
	}

	qlog("%s STATE DONE\n", __func__);
	return 0;
}

int quic_kernel_socket_setup(struct quic_connection *conn, uint8_t reuse)
{
	conn->sockfd = conn->ep->sockfd;
	if (!reuse) {
		conn->sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_QUIC);
		if (conn->sockfd < 0)
			return -1;
	}
	if (quic_kernel_socket_set_blocking(conn->sockfd))
		return -1;

	if (quic_kernel_socket_setup_cids(conn))
		return -1;
	if (quic_kernel_socket_setup_addrs(conn))
		return -1;
	if (quic_kernel_socket_setup_transport_params(conn))
		return -1;
	if (quic_kernel_socket_setup_crypto_keys(conn))
		return -1;
	if (quic_kernel_socket_setup_state(conn))
		return -1;
	return 0;
}

int quic_kernel_recvmsg(int sockfd, void *msg, size_t len, uint32_t *stream_id,
			uint32_t *stream_flag)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_rcvinfo))];
	struct cmsghdr *cmsg = NULL;
	struct quic_rcvinfo rinfo;
	struct msghdr inmsg;
	struct iovec iov;
	int error;

	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = msg;
	iov.iov_len = len;

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	error = recvmsg(sockfd, &inmsg, 0);
	if (error < 0)
		return error;

	if (!stream_id)
		return error;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (SOL_QUIC == cmsg->cmsg_level && QUIC_RCVINFO == cmsg->cmsg_type)
			break;
	if (cmsg)
		memcpy(&rinfo, CMSG_DATA(cmsg), sizeof(struct quic_rcvinfo));

	*stream_id = rinfo.stream_id;
	*stream_flag = rinfo.stream_flag;
	return error;
}

int quic_kernel_sendmsg(int sockfd, const void *msg, size_t len, uint32_t stream_id,
			uint32_t stream_flag)
{
	struct quic_sndinfo *sinfo;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char outcmsg[CMSG_SPACE(sizeof(*sinfo))];

	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)msg;
	iov.iov_len = len;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct quic_sndinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct quic_sndinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct quic_sndinfo));
	sinfo->stream_id = stream_id;
	sinfo->stream_flag = stream_flag;

	return sendmsg(sockfd, &outmsg, 0);
}
