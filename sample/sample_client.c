#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "sample_context.h"

#define MSG_LEN	4096

int main(int argc, char *argv[])
{
	struct quic_context ctx = client_context;
	struct sockaddr_in sa, da;
	char msg[MSG_LEN + 1];
	int sd, len, ret;

	if (argc != 5) {
		printf("%s <LOCAL ADDR> <LOCAL PORT> <PEER ADDR> <PEER PORT>\n", argv[0]);
		return 1;
	}

	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sd < 0) {
		printf("socket creation failed\n");
		return -1;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(atoi(argv[2]));
	inet_pton(AF_INET, argv[1], &sa.sin_addr.s_addr);

	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa))) {
		printf("socket bind failed\n");
		return -1;
	}

	da.sin_family = AF_INET;
	da.sin_port = htons(atoi(argv[4]));
	inet_pton(AF_INET, argv[3], &da.sin_addr.s_addr);

	if (connect(sd, (struct sockaddr *)&da, sizeof(da))) {
		printf("socket connect failed\n");
		return -1;
	}

	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_CONTEXT, &ctx, sizeof(ctx))) {
		printf("set sockopt failed\n");
		return -1;
	}

	/* NOTE: quic_send/recvmsg() allows get/setting stream id and flags,
	 * comparing to send/recv():
	 * sid = 0;
	 * flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	 * quic_sendmsg(sd, msg, strlen(msg), sid, flag);
	 * quic_recvmsg(sd, msg, sizeof(msg), &sid, &flag);
	*/

	strcpy(msg, "hello quic server!");
	ret = send(sd, msg, strlen(msg), 0);
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
