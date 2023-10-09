#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/quic.h>

#define MSG_LEN	4096

struct quic_context client_context = {
	.local = {
		.max_udp_payload_size = 65527,
		.ack_delay_exponent = 3,
		.max_ack_delay = 25000,
		.active_connection_id_limit = 3,
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
		.active_connection_id_limit = 3,
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
	.is_serv = 0,
};

struct quic_context server_context = {
	.remote = {
		.max_udp_payload_size = 65527,
		.ack_delay_exponent = 3,
		.max_ack_delay = 25000,
		.active_connection_id_limit = 3,
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
		.active_connection_id_limit = 3,
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
	.is_serv = 1,
};

int main(int argc, char *argv[])
{
	struct quic_context ctx = server_context;
	struct sockaddr_in sa = {}, da = {};
	char msg[MSG_LEN + 1];
	int sd, len, ret;

	if (argc != 6 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
		printf("%s <server|client> <LOCAL ADDR> <LOCAL PORT> <PEER ADDR> <PEER PORT>\n", argv[0]);
		return 1;
	}

	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sd < 0) {
		printf("socket creation failed\n");
		return -1;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &sa.sin_addr.s_addr);

	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa))) {
		printf("socket bind failed\n");
		return -1;
	}

	da.sin_family = AF_INET;
	da.sin_port = htons(atoi(argv[5]));
	inet_pton(AF_INET, argv[4], &da.sin_addr.s_addr);

	if (connect(sd, (struct sockaddr *)&da, sizeof(da))) {
		printf("socket connect failed\n");
		return -1;
	}

	/* NOTE: quic_send/recvmsg() allows get/setting stream id and flags,
	 * comparing to send/recv():
	 * sid = 0;
	 * flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	 * quic_sendmsg(sd, msg, strlen(msg), sid, flag);
	 * quic_recvmsg(sd, msg, sizeof(msg), &sid, &flag);
	*/

	if (!strcmp(argv[1], "client")) {
		struct quic_context ctx = client_context;

		if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_CONTEXT, &ctx, sizeof(ctx))) {
			printf("set sockopt failed\n");
			return -1;
		}
		strcpy(msg, "hello quic server!");
		ret = send(sd, msg, strlen(msg), MSG_SYN | MSG_FIN);
		if (ret == -1) {
			printf("send error %d %d\n", ret, errno);
			return -1;
		}
		printf("send %d\n", ret);

		ret = recv(sd, msg, sizeof(msg), 0);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return 1;
		}
		printf("recv: \"%s\", len: %d\n", msg, ret);

		close(sd);
		return 0;
	}

	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_CONTEXT, &ctx, sizeof(ctx))) {
		printf("set sockopt failed\n");
		return -1;
	}

	ret = recv(sd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv: \"%s\", len: %d\n", msg, ret);

	strcpy(msg, "hello quic client!");
	ret = send(sd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send %d\n", ret);

	do {
		ret = recv(sd, msg, sizeof(msg), 0);
	} while (ret > 0);

	close(sd);
	return 0;
}
