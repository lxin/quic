#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/tls.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/quic.h>

#define MSG_LEN	4096
char msg[MSG_LEN + 1];

static int do_client_notification_test(int sockfd)
{
	struct quic_errinfo errinfo = {};
	struct quic_event_option event;
	struct sockaddr_in addr = {};
	struct quic_stream_info info;
	unsigned int optlen, flag;
	union quic_event *ev;
	int ret, port;
	uint64_t sid;

	printf("NOTIFICATION TEST:\n");

	event.type = QUIC_EVENT_STREAM_UPDATE;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test1: PASS (enable stream update event)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid = 100;
	strcpy(msg, "quic event test2");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 100 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test2: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->update.state != QUIC_STREAM_SEND_STATE_RECVD) {
		printf("test2: FAIL state %d\n", ev->update.state);
		return -1;
	}
	printf("test2: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RECVD event)\n");

	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test3: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->update.state != QUIC_STREAM_RECV_STATE_RECVD ||
	    ev->update.errcode != strlen("quic event test2")) {
		printf("test3: FAIL state %d\n", ev->update.state);
		return -1;
	}
	printf("test3: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_RECV_STATE_RECVD event)\n");

	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic event test2") || sid != 100) {
		printf("test4: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test4: PASS (receive msg after events)\n");

	flag = QUIC_STREAM_FLAG_NEW;
	sid  = 102;
	strcpy(msg, "client reset");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 102 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	optlen = sizeof(errinfo);
	errinfo.stream_id = 102;
	errinfo.errcode = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
	if (ret == -1) {
		printf("socket setsockopt stream reset error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test5: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->update.state != QUIC_STREAM_SEND_STATE_RESET_RECVD || ev->update.errcode != 1) {
		printf("test5: FAIL state %d\n", ev->update.state);
		return -1;
	}
	printf("test5: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RESET_RECVD event)\n");

	flag = QUIC_STREAM_FLAG_NEW;
	sid  = 104;
	strcpy(msg, "client stop_sending");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 104 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test6: FAIL flag %d event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->update.state != QUIC_STREAM_SEND_STATE_RESET_SENT || ev->update.errcode != 1) {
		printf("test6: FAIL state %d\n", ev->update.state);
		return -1;
	}
	printf("test6: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RESET_SENT event)\n");

	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test7: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->update.state != QUIC_STREAM_SEND_STATE_RESET_RECVD || ev->update.errcode != 1) {
		printf("test7: FAIL state %d\n", ev->update.state);
		return -1;
	}
	printf("test7: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RESET_RECVD event by stop_sending)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 106;
	strcpy(msg, "client reset");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 106 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	/* skip the QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RECVD event */
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test8: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->update.state != QUIC_STREAM_RECV_STATE_RECV || ev->update.id != 107) {
		printf("test8: FAIL state %d\n", ev->update.state);
		return -1;
	}
	printf("test8: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_RECV_STATE_RECV event)\n");

	sleep(1);
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test9: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->update.state != QUIC_STREAM_RECV_STATE_RESET_RECVD || ev->update.id != 107) {
		printf("test9: FAIL state %d\n", ev->update.state);
		return -1;
	}
	printf("test9: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_RECV_STATE_RESET_RECVD event)\n");

	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client reset") || sid != 107) {
		printf("test10: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test10: PASS (receive the old msg after stream reset events)\n");

	event.type = QUIC_EVENT_STREAM_UPDATE;
	event.on = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test11: PASS (disable stream update event)\n");

	event.type = QUIC_EVENT_STREAM_MAX_STREAM;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test12: PASS (enable max stream event)\n");

	optlen = sizeof(info);
	info.stream_flag = QUIC_STREAM_FLAG_ASYNC;
	info.stream_id = 600;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 600 */
	if (ret != -1 || errno != EAGAIN) {
		printf("test13: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	sleep(1);
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_MAX_STREAM) {
		printf("test13: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->max_stream != 600) {
		printf("test13: FAIL max_stream %lu\n", ev->max_stream);
		return -1;
	}
	printf("test13: PASS (QUIC_EVENT_STREAM_MAX_STREAM event for bidi stream)\n");

	optlen = sizeof(info);
	info.stream_flag = QUIC_STREAM_FLAG_ASYNC;
	info.stream_id = 602;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 602 */
	if (ret != -1 || errno != EAGAIN) {
		printf("test14: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	sleep(1);
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_MAX_STREAM) {
		printf("test14: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->max_stream != 602) {
		printf("test14: FAIL max_stream %lu\n", ev->max_stream);
		return -1;
	}
	printf("test14: PASS (QUIC_EVENT_STREAM_MAX_STREAM event for uni stream)\n");

	event.type = QUIC_EVENT_STREAM_MAX_STREAM;
	event.on = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test15: PASS (disable max stream event)\n");

	event.type = QUIC_EVENT_CONNECTION_MIGRATION;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test16: PASS (enable connection migration event)\n");

	optlen = sizeof(addr);
	ret = getsockname(sockfd, (struct sockaddr *)&addr, &optlen);
	if (ret == -1) {
		printf("socket getsockname error %d\n", errno);
		return -1;
	}
	port = ntohs(addr.sin_port);
	addr.sin_port = htons(port + 1);
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION, &addr, sizeof(addr));
	if (ret == -1) {
		printf("socket setsockopt migration error %d\n", errno);
		return -1;
	}
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 108;
	strcpy(msg, "quic event test17");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 108 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_CONNECTION_MIGRATION) {
		printf("test17: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->local_migration != 1) {
		printf("test17: FAIL local_migration %d\n", ev->local_migration);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic event test17") || sid != 108) {
		printf("test17: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test17: PASS (QUIC_EVENT_CONNECTION_MIGRATION event for local migration)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 110;
	strcpy(msg, "client migration");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 110 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	sleep(4);
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_CONNECTION_MIGRATION) {
		printf("test18: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->local_migration != 0) {
		printf("test18: FAIL local_migration %d\n", ev->local_migration);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client migration")) {
		printf("test18: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test18: PASS (QUIC_EVENT_CONNECTION_MIGRATION event for peer migration)\n");

	event.type = QUIC_EVENT_CONNECTION_MIGRATION;
	event.on = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test19: PASS (enable connection migration event)\n");

	event.type = QUIC_EVENT_KEY_UPDATE;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test20: PASS (enable key update event)\n");

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0);
	if (ret == -1) {
		printf("socket setsockopt migration error %d\n", errno);
		return -1;
	}
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 112;
	strcpy(msg, "quic event test21");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 112 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic event test21") || sid != 112) {
		printf("test21: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	sleep(1);
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 114;
	strcpy(msg, "quic event test21");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 114 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_KEY_UPDATE) {
		printf("test21: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->key_update_phase != 1) {
		printf("test21: FAIL key_phase %d\n", ev->key_update_phase);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic event test21") || sid != 115) {
		printf("test21: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test21: PASS (QUIC_EVENT_KEY_UPDATE event for local key_update)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 116;
	strcpy(msg, "client key_update");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 116 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client key_update") || sid != 116) {
		printf("test22: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	sleep(1);
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 118;
	strcpy(msg, "quic event test22");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 118 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_KEY_UPDATE) {
		printf("test22: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	ev = (void *)&msg[1];
	if (ev->key_update_phase != 0) {
		printf("test22: FAIL key_phase %d\n", ev->key_update_phase);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic event test22") || sid != 119) {
		printf("test22: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test22: PASS (QUIC_EVENT_KEY_UPDATE event for peer key_update)\n");

	event.type = QUIC_EVENT_KEY_UPDATE;
	event.on = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test23: PASS (disable key update event)\n");

	event.type = QUIC_EVENT_NEW_TOKEN;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test24: PASS (enable new token event)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 120;
	strcpy(msg, "client new_token");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 120 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_NEW_TOKEN) {
		printf("test25: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client new_token") || sid != 120) {
		printf("test25: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test25: PASS (QUIC_EVENT_NEW_TOKEN event)\n");

	event.type = QUIC_EVENT_NEW_TOKEN;
	event.on = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test26: PASS (enable new token event)\n");

	return 0;
}

static int do_client_close_test(int sockfd)
{
	struct quic_connection_close *info;
	struct quic_event_option event;
	unsigned int optlen, flag;
	char opt[100] = {};
	uint64_t sid;
	int ret;

	printf("CLOSE TEST:\n");

	info = (struct quic_connection_close *)opt;
	info->errcode = 10;
	info->frame = 1;
	strcpy((char *)info->phrase, "this is app err");
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_CLOSE,
			 info, sizeof(*info) + strlen((char *)info->phrase));
	if (ret != -1) {
		printf("test1: FAIL\n");
		return -1;
	}
	printf("test1: PASS (not allowed to set close info with non-string phrase)\n");

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_CLOSE,
			 info, sizeof(*info) - 1);
	if (ret != -1) {
		printf("test2: FAIL\n");
		return -1;
	}
	printf("test2: PASS (not allowed to set close info with short info)\n");

	optlen = sizeof(opt);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_CLOSE, opt, &optlen);
	if (ret == -1 || optlen != sizeof(*info)) {
		printf("test3: FAIL ret %d, optlen %d\n", ret, optlen);
		return -1;
	}
	printf("test3: PASS (get non-setup close info from socket)\n");

	info = (struct quic_connection_close *)opt;
	info->errcode = 10;
	info->frame = 1;
	strcpy((char *)info->phrase, "this is app err");
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_CLOSE,
			 info, sizeof(*info) + strlen((char *)info->phrase) + 1);
	if (ret == -1) {
		printf("socket setsockopt close info error %d\n", errno);
		return -1;
	}
	optlen = sizeof(opt);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_CLOSE, opt, &optlen);
	if (ret == -1 || info->errcode != 10 || info->frame != 0 ||
	    strcmp((char *)info->phrase, "this is app err")) {
		printf("test4: FAIL ret %d, errcode %d, frame %d, phrase %s\n",
		       ret, info->errcode, info->frame, info->phrase);
		return -1;
	}
	printf("test4: PASS (set and get close info from socket)\n");

	event.type = QUIC_EVENT_CONNECTION_CLOSE;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test5: PASS (enable close event)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid = 64;
	strcpy(msg, "client close");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client close") || sid != 64) {
		printf("test6: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test6: PASS (set peer close info)\n");

	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_NOTIFICATION) || msg[0] != QUIC_EVENT_CONNECTION_CLOSE) {
		printf("test7: FAIL flag %d, event %d\n", flag, msg[0]);
		return -1;
	}
	info = (void *)&msg[1];
	if (info->errcode != 10 || info->frame != 0 ||
	    strcmp((char *)info->phrase, "this is app err")) {
		printf("test7: FAIL errcode %d, frame %d, phrase %s\n",
		       info->errcode, info->frame, info->phrase);
		return -1;
	}
	printf("test7: PASS (received the peer close event)\n");
	close(sockfd);
	return 0;
}

static int do_client_connection_test(int sockfd)
{
	struct quic_connection_id_info info = {};
	struct sockaddr_in addr = {};
	unsigned int optlen, flag;
	char opt[100] = {};
	uint64_t sid = 0;
	int ret, port;

	printf("CONNECTION TEST:\n");

	optlen = sizeof(info);
	info.source = 2;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen); /* 2-8 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.source != 2) {
		printf("test1: FAIL ret %d, source %d\n", ret, info.source);
		return -1;
	}
	printf("test1: PASS (retire source connection id 0)\n");

	optlen = sizeof(info);
	info.source = 3;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen); /* 3-9 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.source != 3) {
		printf("test2: FAIL ret %d, source %d\n", ret, info.source);
		return -1;
	}
	printf("test2: PASS (retire source connection id 1)\n");

	optlen = sizeof(info);
	info.source = 3;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test3: FAIL\n");
		return -1;
	}
	printf("test3: PASS (not allow to retire a retired source connection id)\n");

	optlen = sizeof(info);
	info.source = 10;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test4: FAIL\n");
		return -1;
	}
	printf("test4: PASS (not allow to retire all source connection id)\n");

	optlen = sizeof(info);
	info.source = 5;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen); /* 5-11 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.source != 5) {
		printf("test5: FAIL ret %d, source %d\n", ret, info.source);
		return -1;
	}
	printf("test5: PASS (retire multiple source connection id)\n");

	optlen = sizeof(info);
	info.source = 11;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen); /* 11-17 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.source != 11) {
		printf("test6: FAIL ret %d, source %d\n", ret, info.source);
		return -1;
	}
	printf("test6: PASS (retire max_count - 1 source connection id)\n");

	optlen = sizeof(info);
	info.source = 0;
	info.dest = 2;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen); /* 2-8 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.dest != 2) {
		printf("test7: FAIL ret %d, dest %d\n", ret, info.dest);
		return -1;
	}
	printf("test7: PASS (retire dest connection id 0)\n");

	optlen = sizeof(info);
	info.source = 0;
	info.dest = 3;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen); /* 3-9 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.dest != 3) {
		printf("test8: FAIL ret %d, dest %d\n", ret, info.dest);
		return -1;
	}
	printf("test8: PASS (retire dest connection id 1)\n");

	optlen = sizeof(info);
	info.source = 0;
	info.dest = 3;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test9: FAIL\n");
		return -1;
	}
	printf("test9: PASS (not allow to retire a retired dest connection id)\n");

	optlen = sizeof(info);
	info.source = 0;
	info.dest = 10;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test10: FAIL\n");
		return -1;
	}
	printf("test10: PASS (not allow to retire all dest connection id)\n");

	optlen = sizeof(info);
	info.source = 0;
	info.dest = 5;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen); /* 5-11 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.dest != 5) {
		printf("test11: FAIL ret %d, dest %d\n", ret, info.dest);
		return -1;
	}
	printf("test11: PASS (retire multiple dest connection id)\n");

	optlen = sizeof(info);
	info.source = 0;
	info.dest = 11;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_RETIRE_CONNECTION_ID, &info, optlen); /* 11-17 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.dest != 11) {
		printf("test12: FAIL ret %d, dest %d\n", ret, info.dest);
		return -1;
	}
	printf("test12: PASS (retire max_count - 1 dest connection id)\n");

	optlen = sizeof(addr);
	ret = getsockname(sockfd, (struct sockaddr *)&addr, &optlen);
	if (ret == -1) {
		printf("socket getsockname error %d\n", errno);
		return -1;
	}
	port = ntohs(addr.sin_port);
	addr.sin_port = htons(port + 1);
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION, &addr, sizeof(addr));
	if (ret == -1) {
		printf("socket setsockopt migration error %d\n", errno);
		return -1;
	}
	printf("test13: PASS (connection migration is set)\n");

	strcpy(msg, "quic connection test14");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic connection test14")) {
		printf("test14: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test14: PASS (send message with new address)\n");

	optlen = sizeof(addr);
	ret = getsockname(sockfd, (struct sockaddr *)&addr, &optlen);
	if (ret == -1 || ntohs(addr.sin_port) != port + 1) {
		printf("test15: FAIL new port %d, expected port %d\n", ntohs(addr.sin_port), port + 1);
		return -1;
	}
	printf("test15: PASS (connection migration is done)\n");

	optlen = sizeof(info);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.dest != 11 || info.source != 12) {
		printf("teset16: FAIL ret %d, dest %d, source %d\n", ret, info.dest, info.source);
		return -1;
	}
	printf("test16: PASS (retire source & dest connection id when doing migration)\n");

	optlen = sizeof(addr);
	ret = getpeername(sockfd, (struct sockaddr *)&addr, &optlen);
	if (ret == -1) {
		printf("socket getpeername error %d\n", errno);
		return -1;
	}
	port = ntohs(addr.sin_port);
	strcpy(msg, "client migration");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN); /* 13-19 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "client migration")) {
		printf("test18: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test18: PASS (peer connection migration is set)\n");

	sleep(2);
	optlen = sizeof(addr);
	ret = getpeername(sockfd, (struct sockaddr *)&addr, &optlen);
	if (ret == -1 || ntohs(addr.sin_port) != port + 1) {
		printf("test19: FAIL new port %d, expected port %d\n", ntohs(addr.sin_port), port + 1);
		return -1;
	}
	printf("test19: PASS (connection migration is done)\n");

	optlen = sizeof(info);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ACTIVE_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.dest != 12 || info.source != 12) {
		printf("teset20: FAIL ret %d, dest %d, source %d\n", ret, info.dest, info.source);
		return -1;
	}
	printf("test20: PASS (retire source & dest connection id when doing migration)\n");

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0);
	if (ret == -1) {
		printf("socket setsockopt key update error %d\n", errno);
		return -1;
	}
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0);
	if (ret != -1) {
		printf("test21: FAIL\n");
		return -1;
	}
	printf("test21: PASS (not allowed to do key update when last one is not yet done)\n");

	strcpy(msg, "quic connection test22");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic connection test22")) {
		printf("test22: FAIL msg %s\n", msg);
		return -1;
	}
	sleep(1);
	strcpy(msg, "quic connection test22");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic connection test22")) {
		printf("test22: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test22: PASS (key update is done)\n");

	sleep(1);
	strcpy(msg, "client key_update");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "client key_update")) {
		printf("test23: FAIL msg %s\n", msg);
		return -1;
	}
	sleep(1);
	strcpy(msg, "quic connection test23");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic connection test23")) {
		printf("test23: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test23: PASS (peer key update is done)\n");

	strcpy(msg, "client new_token");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "client new_token")) {
		printf("test24: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test24: PASS (peer new_token is done)\n");

	optlen = sizeof(opt);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, opt, &optlen);
	if (ret == -1 || !optlen) {
		printf("test25: FAIL ret %d, opt %s\n", ret, opt);
		return -1;
	}
	printf("test25: PASS (get token from socket)\n");

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, NULL, 0);
	if (ret != -1) {
		printf("test26: FAIL\n");
		return -1;
	}
	printf("test26: PASS (not allowed to set token with an null value on client)\n");

	flag = QUIC_STREAM_FLAG_DATAGRAM;
	strcpy(msg, "client datagram");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client datagram")) {
		printf("test27: FAIL msg %s\n", msg);
		return -1;
	}
	if (!(flag & QUIC_STREAM_FLAG_DATAGRAM)) {
		printf("test27: FAIL flag %d\n", flag);
		return -1;
	}
	printf("test27: PASS (send and recv datagram)\n");
	return 0;
}

static int do_client_stream_test(int sockfd)
{
	struct quic_stream_info info = {};
	struct quic_errinfo errinfo = {};
	unsigned int optlen, flag;
	uint64_t sid = 0;
	int ret;

	printf("STREAM TEST:\n");

	strcpy(msg, "quic ");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN); /* stream_id: 0 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	strcpy(msg, "test1");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN);
	if (ret != -1) {
		printf("test1: FAIL\n");
		return -1;
	}
	printf("test1: PASS (not allowed send(MSG_SYN) to open a stream when last is not closed)\n");

	strcpy(msg, "test2");
	ret = send(sockfd, msg, strlen(msg), MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic test2")) {
		printf("test2: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test2: PASS (use send(MSG_SYN) to open one stream)\n");

	strcpy(msg, "quic test3");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN | MSG_STREAM_UNI); /* stream_id: 2 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic test3")) {
		printf("test3: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test3: PASS (use send(MSG_SYN) to open next stream after last is closed)\n");

	strcpy(msg, "quic test4");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN); /* stream_id: 4 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic test4")) {
		printf("test4: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test4: PASS (use send(MSG_SYN) to open next bidi stream after last is closed)\n");

	optlen = sizeof(info);
	info.stream_id = 0;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen);
	if (ret != -1) {
		printf("test5: FAIL\n");
		return -1;
	}
	printf("test5: PASS (not allowed to open a stream that is already closed with getsockopt(QUIC_SOCKOPT_STREAM_OPEN))\n");

	optlen = sizeof(info);
	info.stream_id = 6;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 6 */
	if (ret == -1) {
		printf("socket getsockopt alpn error %d\n", errno);
		return -1;
	}
	strcpy(msg, "quic test6");
	ret = send(sockfd, msg, strlen(msg), MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic test6")) {
		printf("test6: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test6: PASS (use getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to open a specific stream)\n");

	optlen = sizeof(info);
	info.stream_id = -1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 8 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	strcpy(msg, "quic test7");
	ret = send(sockfd, msg, strlen(msg), MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic test7") || info.stream_id != 8) {
		printf("test7: FAIL msg %s, sid %lu\n", msg, info.stream_id);
		return -1;
	}
	printf("test7: PASS (use getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to open next bidi stream)\n");

	optlen = sizeof(info);
	info.stream_id = -1;
	info.stream_flag = QUIC_STREAM_FLAG_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 10 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	strcpy(msg, "quic test8");
	ret = send(sockfd, msg, strlen(msg), MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic test8") || info.stream_id != 10) {
		printf("test8: FAIL msg %s, sid %lu\n", msg, info.stream_id);
		return -1;
	}
	printf("test8: PASS (use getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to open next uni stream)\n");

	flag = QUIC_STREAM_FLAG_NEW;
	sid  = 0;
	strcpy(msg, "quic ");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1) {
		printf("test9: FAIL\n");
		return -1;
	}
	printf("test9: PASS (not allowed to open a stream that is already closed with sendmsg(QUIC_STREAM_FLAG_NEW))\n");

	flag = QUIC_STREAM_FLAG_NEW;
	sid  = 12;
	strcpy(msg, "quic ");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 12 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	strcpy(msg, "test10");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1) {
		printf("test10: FAIL\n");
		return -1;
	}
	printf("test10: PASS (not allowed to open a stream twice with sendmsg(QUIC_STREAM_FLAG_NEW))\n");

	flag = QUIC_STREAM_FLAG_FIN;
	sid  = 12;
	strcpy(msg, "test11");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test11") || sid != 12) {
		printf("test11: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test11: PASS (sendmsg with a specific stream normally)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_UNI;
	sid  = -1;
	strcpy(msg, "quic ");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 14 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	strcpy(msg, "test12");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1) {
		printf("test12: FAIL\n");
		return -1;
	}
	printf("test12: PASS (not allowed to open a stream with sendmsg(sid == -1) if it the old one is not closed\n");

	flag = QUIC_STREAM_FLAG_FIN;
	strcpy(msg, "test13");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test13") || sid != 15) {
		printf("test13: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test13: PASS (open next uni stream with sendmsg(sid == -1))\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = -1;
	strcpy(msg, "quic test14");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 16 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test14") || sid != 16) {
		printf("test14: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test14: PASS (open next bidi stream with sendmsg(sid == -1))\n");

	optlen = sizeof(info);
	info.stream_id = 18;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 18 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	optlen = sizeof(info);
	info.stream_id = 20;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 20 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	flag = QUIC_STREAM_FLAG_FIN;
	sid  = 18;
	strcpy(msg, "quic test15");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test15") || sid != 19) {
		printf("test15: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test15: PASS (open multiple stream and send on 1st one)\n");

	flag = QUIC_STREAM_FLAG_FIN;
	sid  = 20;
	strcpy(msg, "quic test16");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test16") || sid != 20) {
		printf("test16: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test16: PASS (open multiple stream and send on 2nd one)\n");

	flag = QUIC_STREAM_FLAG_FIN;
	sid  = 20;
	strcpy(msg, "quic test17");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1) {
		printf("test17: FAIL\n");
		return -1;
	}
	printf("test17: PASS (not allowed to send data on a closed stream)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 400;
	strcpy(msg, "quic test18");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test18") || sid != 400) {
		printf("test18: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test18: PASS (sendmsg with sid > max_streams_bidi in blocked mode)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 402;
	strcpy(msg, "quic test19");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test19") || sid != 403) {
		printf("test19: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test19: PASS (sendmsg with sid > max_streams_uni in blocked mode)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN | QUIC_STREAM_FLAG_ASYNC;
	sid  = 404;
	strcpy(msg, "quic test20");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1 || errno != EAGAIN) {
		printf("test20: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test20: PASS (return -EAGAIN in bidi non-blocked mode)\n");

	sleep(1);
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 404;
	strcpy(msg, "quic test21");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test21") || sid != 404) {
		printf("test21: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test21: PASS (sendmsg with sid > max_streams_bidi in non-blocked mode)\n");

	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN | QUIC_STREAM_FLAG_ASYNC;
	sid  = 406;
	strcpy(msg, "quic test22");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1 || errno != EAGAIN) {
		printf("test22: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test22: PASS (return -EAGAIN in uni non-blocked mode)\n");

	sleep(1);
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 406;
	strcpy(msg, "quic test23");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test23") || sid != 407) {
		printf("test23: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test23: PASS (sendmsg with sid > max_streams_uni in non-blocked mode)\n");

	optlen = sizeof(info);
	info.stream_id = 408;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 408 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	flag = QUIC_STREAM_FLAG_FIN;
	sid = 408;
	strcpy(msg, "quic test24");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test24") || sid != 408) {
		printf("test24: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test24: PASS (getsockopt(QUIC_SOCKOPT_STREAM_OPEN) with sid > max_streams_bidi in blocked mode)\n");

	optlen = sizeof(info);
	info.stream_id = 410;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 410 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	flag = QUIC_STREAM_FLAG_FIN;
	sid  = 410;
	strcpy(msg, "quic test25");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test25") || sid != 411) {
		printf("test25: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test25: PASS (getsockopt(QUIC_SOCKOPT_STREAM_OPEN) with sid > max_streams_uni in blocked mode)\n");

	optlen = sizeof(info);
	info.stream_flag = QUIC_STREAM_FLAG_ASYNC;
	info.stream_id = 412;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 412 */
	if (ret != -1 || errno != EAGAIN) {
		printf("test26: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test26: PASS (return -EAGAIN in bidi non-blocked mode)\n");

	sleep(1);
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 412;
	strcpy(msg, "quic test27");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test27") || sid != 412) {
		printf("test27: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test27: PASS (getsockopt(QUIC_SOCKOPT_STREAM_OPEN) with sid > max_streams_bidi in non-blocked mode)\n");

	optlen = sizeof(info);
	info.stream_flag = QUIC_STREAM_FLAG_ASYNC;
	info.stream_id = 414;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen); /* stream_id: 414 */
	if (ret != -1 || errno != EAGAIN) {
		printf("test28: FAIL ret %d, errno %d\n", ret, errno);
		return -1;
	}
	printf("test28: PASS (return -EAGAIN in uni non-blocked mode)\n");

	sleep(1);
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	sid  = 414;
	strcpy(msg, "quic test29");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test29") || sid != 415) {
		printf("test29: FAIL msg %s, sid %lu\n", msg, sid);
		return -1;
	}
	printf("test29: PASS (sendmsg with sid > max_streams_uni in non-blocked mode)\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = 414;
	errinfo.errcode = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
	if (ret != -1 || errno != EINVAL) {
		printf("test30: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test30: PASS (not allowed to reset a closed stream)\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = 416;
	errinfo.errcode = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
	if (ret != -1 || errno != EINVAL) {
		printf("test31: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test31: PASS (not allowed to reset a stream that hasn't opened)\n");

	flag = QUIC_STREAM_FLAG_NEW;
	sid  = 416;
	strcpy(msg, "client reset");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 416 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	optlen = sizeof(errinfo);
	errinfo.stream_id = 416;
	errinfo.errcode = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
	if (ret == -1) {
		printf("socket setsockopt stream reset error %d\n", errno);
		return -1;
	}
	printf("test32: PASS (reset a opened stream)\n");

	flag = 0;
	strcpy(msg, "test33");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1 || errno != EINVAL) {
		printf("test33: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test33: PASS (not allowed to send data on a reset stream)\n");

	flag = QUIC_STREAM_FLAG_FIN;
	strcpy(msg, "test34");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1 || errno != EINVAL) {
		printf("test34: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test34: PASS (not allowed to send data with FIN on a reset stream)\n");

	flag = QUIC_STREAM_FLAG_NEW;
	sid  = 418;
	strcpy(msg, "client stop_sending");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag); /* stream_id: 418 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	sleep(1);
	flag = 0;
	strcpy(msg, "test35");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1 || errno != EINVAL) {
		printf("test35: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test35: PASS (not allowed to send data on a reset stream by peer stop_sending)\n");

	flag = QUIC_STREAM_FLAG_FIN;
	strcpy(msg, "test36");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret != -1 || errno != EINVAL) {
		printf("test36: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test36: PASS (not allowed to send data with FIN on a reset stream set by peer stop_sending)\n");
	return 0;
}

static int do_client_test(int sockfd)
{
	if (do_client_stream_test(sockfd))
		return -1;

	if (do_client_connection_test(sockfd))
		return -1;

	if (do_client_notification_test(sockfd))
		return -1;

	return do_client_close_test(sockfd);
}

static int do_server_test(int sockfd)
{
	struct quic_errinfo errinfo = {};
	struct sockaddr_in addr = {};
	uint64_t len = 0, sid = 0;
	unsigned int optlen, flag;
	int ret;

	while (1) {
		ret = quic_recvmsg(sockfd, &msg[len], sizeof(msg) - len, &sid, &flag);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return -1;
		}
		len += ret;
		if (!strcmp(msg, "client reset")) {
			if (flag & QUIC_STREAM_FLAG_FIN) {
				flag = QUIC_STREAM_FLAG_NEW;
				if (sid & QUIC_STREAM_TYPE_UNI_MASK) {
					flag |= QUIC_STREAM_FLAG_NEW;
					sid  |= QUIC_STREAM_TYPE_SERVER_MASK;
				}
				ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
				if (ret == -1) {
					printf("send %d %d\n", ret, errno);
					return -1;
				}
				optlen = sizeof(errinfo);
				errinfo.stream_id = sid;
				errinfo.errcode = 1;
				ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
				if (ret == -1) {
					printf("socket setsockopt stream stop_sending failed %d\n", errno);
					return -1;
				}
			}
			goto reset;
		}

		if (!strcmp(msg, "client stop_sending")) {
			optlen = sizeof(errinfo);
			errinfo.stream_id = sid;
			errinfo.errcode = 1;
			ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_STOP_SENDING, &errinfo, optlen);
			if (ret == -1) {
				printf("socket setsockopt stream stop_sending failed %d\n", errno);
				return -1;
			}
			goto reset;
		}

		if (!(flag & QUIC_STREAM_FLAG_FIN))
			continue;

		if (!strcmp(msg, "client migration")) {
			optlen = sizeof(addr);
			ret = getsockname(sockfd, (struct sockaddr *)&addr, &optlen);
			if (ret == -1) {
				printf("socket getsockname failed %d\n", errno);
				return -1;
			}
			addr.sin_port = htons(ntohs(addr.sin_port) + 1);
			ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION, &addr, sizeof(addr));
			if (ret == -1) {
				printf("socket setsockopt migration failed %d\n", errno);
				return -1;
			}
			sleep(2);
		}

		if (!strcmp(msg, "client key_update")) {
			ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0);
			if (ret == -1) {
				printf("socket setsockopt key update failed\n");
				return -1;
			}
		}

		if (!strcmp(msg, "client new_token")) {
			ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, NULL, 0);
			if (ret == -1) {
				printf("socket setsockopt new token failed\n");
				return -1;
			}
		}

		if (!strcmp(msg, "client datagram")) {
			flag = QUIC_STREAM_FLAG_DATAGRAM;
			goto reply;
		}

		if (!strcmp(msg, "client close")) {
			struct quic_connection_close *info;
			char opt[100] = {};

			info = (struct quic_connection_close *)opt;
			info->errcode = 10;
			info->frame = 1;
			strcpy((char *)info->phrase, "this is app err");

			ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_CLOSE,
					 info, sizeof(*info) + strlen((char *)info->phrase) + 1);
			if (ret == -1) {
				printf("socket setsockopt close info error %d\n", errno);
				return -1;
			}
			printf("TEST DONE\n");
		}

		flag = QUIC_STREAM_FLAG_FIN;
		if (sid & QUIC_STREAM_TYPE_UNI_MASK) { /* use the corresp sid in server */
			flag |= QUIC_STREAM_FLAG_NEW;
			sid  |= QUIC_STREAM_TYPE_SERVER_MASK;
		}
reply:
		/* echo reply */
		ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		if (!strcmp(msg, "client close")) {
			sleep(1);
			shutdown(sockfd, SHUT_WR);
			break;
		}
reset:
		len = 0;
		memset(msg, 0, sizeof(msg));
	}
	sleep(1);
	close(sockfd);
	return 0;
}

static int do_client(int argc, char *argv[])
{
	struct quic_transport_param param = {};
	char *pkey = NULL, *cert = NULL;
        struct sockaddr_in ra = {};
	int sockfd;

	if (argc < 3) {
		printf("%s client <PEER ADDR> <PEER PORT> <PSK_FILE> | <PRIVATE_KEY_FILE> <CERTIFICATE_FILE> | NONE\n", argv[0]);
		return 0;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

        ra.sin_family = AF_INET;
        ra.sin_port = htons(atoi(argv[3]));
        inet_pton(AF_INET, argv[2], &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	param.max_datagram_frame_size = 1400;
	param.payload_cipher_type = TLS_CIPHER_AES_GCM_256;
	if (argc < 5)
		goto start;
	pkey = argv[4];
	if (argc == 5) {
		param.payload_cipher_type = TLS_CIPHER_AES_CCM_128;
		goto start;
	}
	cert = argv[5];
start:
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;

	if (quic_client_handshake(sockfd, pkey, cert))
		return -1;
	printf("HANDSHAKE DONE\n");
	return do_client_test(sockfd);
}

static int do_server(int argc, char *argv[])
{
	struct quic_transport_param param = {};
	struct sockaddr_in la = {}, ra = {};
	char *pkey, *cert = NULL;
	int listenfd, sockfd;
	unsigned int addrlen;

	if (argc < 5) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PSK_FILE> | <PRIVATE_KEY_FILE> <CERTIFICATE_FILE>\n", argv[0]);
		return 0;
	}

	la.sin_family = AF_INET;
	la.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &la.sin_addr.s_addr);
	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("socket create failed\n");
		return -1;
	}
	if (bind(listenfd, (struct sockaddr *)&la, sizeof(la))) {
		printf("socket bind failed\n");
		return -1;
	}
	if (listen(listenfd, 1)) {
		printf("socket listen failed\n");
		return -1;
	}
	addrlen = sizeof(ra);

	sockfd = accept(listenfd, (struct sockaddr *)&ra, &addrlen);
	if (sockfd < 0) {
		printf("socket accept failed %d %d\n", errno, sockfd);
		return -1;
	}

	param.max_datagram_frame_size = 1400;
	param.payload_cipher_type = TLS_CIPHER_AES_GCM_256;
	pkey = argv[4];
	if (argc == 5) {
		param.payload_cipher_type = TLS_CIPHER_AES_CCM_128;
		goto start;
	}
	cert = argv[5];
start:
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;

	if (quic_server_handshake(sockfd, pkey, cert))
		return -1;
	printf("HANDSHAKE DONE\n");
	return do_server_test(sockfd);
}

int main(int argc, char *argv[])
{
	if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
		printf("%s server|client ...\n", argv[0]);
		return 0;
	}

	if (!strcmp(argv[1], "client"))
		return do_client(argc, argv);

	return do_server(argc, argv);
}
