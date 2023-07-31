#include <linux/quic.h>

struct quic_context client_context = {
	.local = {
		.max_udp_payload_size = 65527,
		.ack_delay_exponent = 3,
		.max_ack_delay = 25000,
		.initial_max_data = 131072,
		.initial_max_stream_data_bidi_local = 65536,
		.initial_max_stream_data_bidi_remote = 65536,
		.initial_max_stream_data_uni = 65536,
		.initial_max_streams_bidi = 100,
		.initial_max_streams_uni = 100,
		.initial_smoothed_rtt = 333000,
	},
	.remote = {
		.max_udp_payload_size = 65527,
		.ack_delay_exponent = 3,
		.max_ack_delay = 25000,
		.initial_max_data = 131072,
		.initial_max_stream_data_bidi_local = 65536,
		.initial_max_stream_data_bidi_remote = 65536,
		.initial_max_stream_data_uni = 65536,
		.initial_max_streams_bidi = 100,
		.initial_max_streams_uni = 100,
		.initial_smoothed_rtt = 333000,
	},
	.source = {
		.len = 15,
		.data = "7c4d1be2dbab5af",
	},
	.dest = {
		.len = 15,
		.data = "2d386f8793fe1a0",
	},
	.send = {
		.secret = "00575b0939d23d75ea1a28f5f8649abb",
	},
	.recv = {
		.secret = "0eb530a5596bfc1176e26fd224460e84",
	},
};

struct quic_context server_context = {
	.remote = {
		.max_udp_payload_size = 65527,
		.ack_delay_exponent = 3,
		.max_ack_delay = 25000,
		.initial_max_data = 131072,
		.initial_max_stream_data_bidi_local = 65536,
		.initial_max_stream_data_bidi_remote = 65536,
		.initial_max_stream_data_uni = 65536,
		.initial_max_streams_bidi = 100,
		.initial_max_streams_uni = 100,
		.initial_smoothed_rtt = 333000,
	},
	.local = {
		.max_udp_payload_size = 65527,
		.ack_delay_exponent = 3,
		.max_ack_delay = 25000,
		.initial_max_data = 131072,
		.initial_max_stream_data_bidi_local = 65536,
		.initial_max_stream_data_bidi_remote = 65536,
		.initial_max_stream_data_uni = 65536,
		.initial_max_streams_bidi = 100,
		.initial_max_streams_uni = 100,
		.initial_smoothed_rtt = 333000,
	},
	.dest = {
		.len = 15,
		.data = "7c4d1be2dbab5af",
	},
	.source = {
		.len = 15,
		.data = "2d386f8793fe1a0",
	},
	.recv = {
		.secret = "00575b0939d23d75ea1a28f5f8649abb",
	},
	.send = {
		.secret = "0eb530a5596bfc1176e26fd224460e84",
	},
};

int quic_recvmsg(int sockfd, void *msg, size_t len, uint32_t *stream_id, uint32_t *stream_flag)
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

int quic_sendmsg(int sockfd, const void *msg, size_t len, uint32_t stream_id, uint32_t stream_flag)
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
