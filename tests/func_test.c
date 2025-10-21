#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/tls.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/quic.h>
#include <sys/syslog.h>

#define MSG_LEN	4096
char msg[MSG_LEN + 1];

static const char *parse_address(
	char const *address, char const *port, struct sockaddr_storage *sas)
{
	struct addrinfo hints = {0};
	struct addrinfo *res;
	int rc;

	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(address, port, &hints, &res);
	if (rc != 0)
		return gai_strerror(rc);
	memcpy(sas, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return NULL;
}

static unsigned short get_port(struct sockaddr_storage *sas)
{
	if (sas->ss_family == AF_INET)
		return ntohs(((struct sockaddr_in *)sas)->sin_port);
	return ntohs(((struct sockaddr_in6 *)sas)->sin6_port);
}

static void set_port(struct sockaddr_storage *sas, unsigned short port)
{
	if (sas->ss_family == AF_INET)
		((struct sockaddr_in *)sas)->sin_port = htons(port);
	else
		((struct sockaddr_in6 *)sas)->sin6_port = htons(port);
}

static int do_client_notification_test(int sockfd)
{
	struct quic_connection_id_info connid_info = {};
	struct quic_errinfo errinfo = {};
	struct quic_event_option event;
	struct sockaddr_storage addr = {};
	unsigned int optlen, flags;
	union quic_event *ev;
	int ret;
	int64_t sid;

	printf("NOTIFICATION TEST:\n");

	event.type = QUIC_EVENT_STREAM_UPDATE;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test1: PASS (enable stream update event)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid = 100;
	strcpy(msg, "quic event test2");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 100 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test2: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != QUIC_STREAM_SEND_STATE_RECVD) {
		printf("test2: FAIL state %u\n", ev->update.state);
		return -1;
	}
	printf("test2: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RECVD event)\n");

	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test3: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != QUIC_STREAM_RECV_STATE_RECV) {
		printf("test3: FAIL state %u\n", ev->update.state);
		return -1;
	}
	printf("test3: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_RECV_STATE_RECV event)\n");

	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test4: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != QUIC_STREAM_RECV_STATE_RECVD ||
	    ev->update.finalsz != strlen("quic event test2")) {
		printf("test4: FAIL state %u\n", ev->update.state);
		return -1;
	}
	printf("test4: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_RECV_STATE_RECVD event)\n");

	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) { /* max_bidi_stream_id: 484 */
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic event test2") || sid != 100) {
		printf("test5: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test5: PASS (receive msg after events)\n");

	flags = MSG_QUIC_STREAM_NEW;
	sid  = 102;
	strcpy(msg, "client reset");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 102 */
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
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) { /* max_uni_stream_id: 450 */
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test6: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != QUIC_STREAM_SEND_STATE_RESET_RECVD || ev->update.errcode != 1) {
		printf("test6: FAIL state %u\n", ev->update.state);
		return -1;
	}
	printf("test6: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RESET_RECVD event)\n");

	flags = MSG_QUIC_STREAM_NEW;
	sid  = 104;
	strcpy(msg, "client stop_sending");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 104 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	sleep(1);
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test7: FAIL flags %u event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != QUIC_STREAM_SEND_STATE_RESET_SENT || ev->update.errcode != 1) {
		printf("test7: FAIL state %u\n", ev->update.state);
		return -1;
	}
	printf("test7: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RESET_SENT event)\n");

	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test8: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != QUIC_STREAM_SEND_STATE_RESET_RECVD || ev->update.errcode != 1) {
		printf("test8: FAIL state %u\n", ev->update.state);
		return -1;
	}
	printf("test8: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RESET_RECVD "
	       "event by stop_sending)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 106;
	strcpy(msg, "client reset");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 106 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) { /* max_uni_stream_id: 454 */
		printf("recv error %d\n", errno);
		return -1;
	}
	/* skip the QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_SEND_STATE_RECVD event */
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test9: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != QUIC_STREAM_RECV_STATE_RECV || ev->update.id != 107) {
		printf("test9: FAIL state %u\n", ev->update.state);
		return -1;
	}
	printf("test9: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_RECV_STATE_RECV event)\n");

	sleep(1);
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE) {
		printf("test10: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != QUIC_STREAM_RECV_STATE_RESET_RECVD || ev->update.id != 107) {
		printf("test10: FAIL state %u\n", ev->update.state);
		return -1;
	}
	printf("test10: PASS (QUIC_EVENT_STREAM_UPDATE/QUIC_STREAM_RECV_STATE_RESET_RECVD event)\n");

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


	flags = MSG_QUIC_STREAM_FIN;
	sid  = 200;
	strcpy(msg, "quic test13");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	sleep(1);
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) { /* max_bidi_stream_id: 488 */
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_MAX_STREAM) {
		printf("test13: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->max_stream != 488) {
		printf("test13: FAIL max_stream %d\n", (int)ev->max_stream);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test13") || sid != 200) {
		printf("test13: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test13: PASS (QUIC_EVENT_STREAM_MAX_STREAM event for bidi stream)\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = 198;
	errinfo.errcode = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
	if (ret == -1) {
		printf("test14: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	sleep(1);
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {  /* max_uni_stream_id: 454 */
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_MAX_STREAM) {
		printf("test14: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->max_stream != 458) {
		printf("test14: FAIL max_stream %d\n", (int)ev->max_stream);
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
	set_port(&addr, get_port(&addr) + 1);
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION, &addr, optlen);
	if (ret == -1) {
		printf("socket setsockopt migration error %d\n", errno);
		return -1;
	}
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 108;
	strcpy(msg, "quic event test17");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 108 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_CONNECTION_MIGRATION) {
		printf("test17: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->local_migration != 1) {
		printf("test17: FAIL local_migration %d\n", ev->local_migration);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic event test17") || sid != 108) {
		printf("test17: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test17: PASS (QUIC_EVENT_CONNECTION_MIGRATION event for local migration)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 110;
	strcpy(msg, "client migration");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 110 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	sleep(4);
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_CONNECTION_MIGRATION) {
		printf("test18: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->local_migration != 0) {
		printf("test18: FAIL local_migration %d\n", ev->local_migration);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
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
	printf("test19: PASS (disable connection migration event)\n");

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
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 112;
	strcpy(msg, "quic event test21");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 112 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic event test21") || sid != 112) {
		printf("test21: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test21: PASS (QUIC_EVENT_KEY_UPDATE event for local key_update)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 116;
	strcpy(msg, "client key_update");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 116 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_KEY_UPDATE) {
		printf("test22: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->key_update_phase != 0) {
		printf("test22: FAIL key_phase %d\n", ev->key_update_phase);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client key_update") || sid != 116) {
		printf("test22: FAIL msg %s, sid %d\n", msg, (int)sid);
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

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 120;
	strcpy(msg, "client new_token");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 120 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_NEW_TOKEN) {
		printf("test25: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client new_token") || sid != 120) {
		printf("test25: FAIL msg %s, sid %d\n", msg, (int)sid);
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
	printf("test26: PASS (disable new token event)\n");

	event.type = QUIC_EVENT_CONNECTION_ID;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test27: PASS (enable new connection id event)\n");

	connid_info.dest = 0;
	optlen = sizeof(connid_info);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &connid_info, &optlen);
	if (ret == -1) {
		printf("test28: FAIL ret %d, source %u\n", ret, connid_info.prior_to);
		return -1;
	}

	connid_info.prior_to++;
	connid_info.active = 0;
	connid_info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &connid_info, optlen);
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_CONNECTION_ID) {
		printf("test28: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (ev->info.dest || ev->info.prior_to != connid_info.prior_to) {
		printf("test28: FAIL prior_to %u %u\n", ev->info.prior_to, connid_info.prior_to);
		return -1;
	}
	printf("test28: PASS (QUIC_EVENT_CONNECTION_ID event for source connection ID)\n");

	connid_info.dest = 1;
	optlen = sizeof(connid_info);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &connid_info, &optlen);
	if (ret == -1) {
		printf("test29: FAIL ret %d, source %u\n", ret, connid_info.prior_to);
		return -1;
	}

	connid_info.prior_to++;
	connid_info.active = 0;
	connid_info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &connid_info, optlen);
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_CONNECTION_ID) {
		printf("test29: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	ev = (union quic_event *)&msg[1];
	if (!ev->info.dest || ev->info.prior_to != connid_info.prior_to) {
		printf("test29: FAIL prior_to %u %u\n", ev->info.prior_to, connid_info.prior_to);
		return -1;
	}
	printf("test29: PASS (QUIC_EVENT_CONNECTION_ID event for dest connection ID)\n");

	event.type = QUIC_EVENT_CONNECTION_ID;
	event.on = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}
	printf("test30: PASS (disable new connection id event)\n");

	return 0;
}

static int do_client_close_test(int sockfd)
{
	struct quic_connection_close *info;
	struct quic_event_option event;
	unsigned int optlen, flags;
	char opt[100] = {};
	int64_t sid;
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
		printf("test3: FAIL ret %d, optlen %u\n", ret, optlen);
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
		printf("test4: FAIL ret %d, errcode %u, frame %d, phrase %s\n",
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

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid = 64;
	strcpy(msg, "client close");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client close") || sid != 64) {
		printf("test6: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test6: PASS (set peer close info)\n");

	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != QUIC_EVENT_CONNECTION_CLOSE) {
		printf("test7: FAIL flags %u, event %d\n", flags, msg[0]);
		return -1;
	}
	info = (struct quic_connection_close *)&msg[1];
	if (info->errcode != 10 || info->frame != 0 ||
	    strcmp((char *)info->phrase, "this is app err")) {
		printf("test7: FAIL errcode %u, frame %d, phrase %s\n",
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
	struct sockaddr_storage addr = {};
	unsigned int optlen, flags;
	char opt[100] = {};
	int64_t sid = 0;
	int ret, port;

	printf("CONNECTION TEST:\n");

	optlen = sizeof(info);
	info.prior_to = 2;
	info.active = 0;
	info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen); /* 2-8 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	info.dest = 0;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 2) {
		printf("test1: FAIL ret %d, source %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test1: PASS (retire source connection id 0)\n");

	optlen = sizeof(info);
	info.prior_to = 3;
	info.active = 0;
	info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen); /* 3-9 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	info.dest = 0;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 3 || info.prior_to != 3) {
		printf("test2: FAIL ret %d, source %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test2: PASS (retire source connection id 1)\n");

	optlen = sizeof(info);
	info.prior_to = 3;
	info.active = 5;
	info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test3: FAIL\n");
		return -1;
	}
	info.prior_to = 5;
	info.active = 2;
	info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test3: FAIL active 2\n");
		return -1;
	}
	info.dest = 0;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 3 || info.prior_to != 3) {
		printf("test3: FAIL ret %d, source %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test3: PASS (not allow to retire a retired source connection id)\n");

	optlen = sizeof(info);
	info.prior_to = 10;
	info.active = 5;
	info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test4: FAIL\n");
		return -1;
	}
	info.prior_to = 5;
	info.active = 10;
	info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test4: FAIL active 10\n");
		return -1;
	}
	info.dest = 0;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 3 || info.prior_to != 3) {
		printf("test4: FAIL ret %d, source %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test4: PASS (not allow to retire all source connection id)\n");

	optlen = sizeof(info);
	info.prior_to = 5;
	info.active = 8;
	info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen); /* 5-11 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id %d\n", errno);
		return -1;
	}
	sleep(1);
	info.dest = 0;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 8 || info.prior_to != 5) {
		printf("test5: FAIL ret %d, active: %u, source %u\n",
		       ret, info.active, info.prior_to);
		return -1;
	}
	printf("test5: PASS (retire multiple source connection id)\n");

	optlen = sizeof(info);
	info.prior_to = 11;
	info.active = 0;
	info.dest = 0;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen); /* 11-17 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id %d\n", errno);
		return -1;
	}
	sleep(1);
	info.dest = 0;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 11 || info.prior_to != 11) {
		printf("test6: FAIL ret %d, source %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test6: PASS (retire max_count - 1 source connection id)\n");

	optlen = sizeof(info);
	info.prior_to = 2;
	info.active = 0;
	info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen); /* 2-8 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	info.dest = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 2 || info.prior_to != 2) {
		printf("test7: FAIL ret %d, dest %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test7: PASS (retire dest connection id 0)\n");

	optlen = sizeof(info);
	info.prior_to = 3;
	info.active = 0;
	info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen); /* 3-9 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	info.dest = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 3 || info.prior_to != 3) {
		printf("test8: FAIL ret %d, dest %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test8: PASS (retire dest connection id 1)\n");

	optlen = sizeof(info);
	info.prior_to = 3;
	info.active = 0;
	info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test9: FAIL\n");
		return -1;
	}
	info.prior_to = 5;
	info.active = 2;
	info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test9: FAIL active 2\n");
		return -1;
	}
	info.dest = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 3 || info.prior_to != 3) {
		printf("test9: FAIL ret %d, source %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test9: PASS (not allow to retire a retired dest connection id)\n");

	optlen = sizeof(info);
	info.prior_to = 10;
	info.active = 5;
	info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test10: FAIL\n");
		return -1;
	}
	info.prior_to = 5;
	info.active = 10;
	info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen);
	if (ret != -1) {
		printf("test10: FAIL active 10\n");
		return -1;
	}
	info.dest = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 3 || info.prior_to != 3) {
		printf("test10: FAIL ret %d, source %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test10: PASS (not allow to retire all dest connection id)\n");

	optlen = sizeof(info);
	info.prior_to = 5;
	info.active = 8;
	info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen); /* 5-11 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	info.dest = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 8 || info.prior_to != 5) {
		printf("test11: FAIL ret %d, active: %u, dest %u\n",
		       ret, info.active, info.prior_to);
		return -1;
	}
	printf("test11: PASS (retire multiple dest connection id)\n");

	optlen = sizeof(info);
	info.prior_to = 11;
	info.active = 0;
	info.dest = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen); /* 11-17 */
	if (ret == -1) {
		printf("socket setsockopt retire connection id error %d\n", errno);
		return -1;
	}
	sleep(1);
	info.dest = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 11 || info.prior_to != 11) {
		printf("test12: FAIL ret %d, dest %u\n", ret, info.prior_to);
		return -1;
	}
	printf("test12: PASS (retire max_count - 1 dest connection id)\n");

	optlen = sizeof(addr);
	ret = getsockname(sockfd, (struct sockaddr *)&addr, &optlen);
	if (ret == -1) {
		printf("socket getsockname error %d\n", errno);
		return -1;
	}
	port = get_port(&addr);
	set_port(&addr, port + 1);
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION, &addr, optlen);
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
	if (ret == -1) { /* max_bidi_stream_id: 456 */
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
	if (ret == -1 || get_port(&addr) != port + 1) {
		printf("test15: FAIL new port %d, expected port %d\n", get_port(&addr),
		       port + 1);
		return -1;
	}
	printf("test15: PASS (connection migration is done)\n");

	info.dest = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 12) {
		printf("teset16: FAIL ret %d, dest %u\n", ret, info.active);
		return -1;
	}
	printf("test16: PASS (retire source & dest connection id when doing migration)\n");

	optlen = sizeof(addr);
	ret = getpeername(sockfd, (struct sockaddr *)&addr, &optlen);
	if (ret == -1) {
		printf("socket getpeername error %d\n", errno);
		return -1;
	}
	port = get_port(&addr);
	strcpy(msg, "client migration");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN); /* 13-19 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) { /* max_bidi_stream_id: 460 */
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "client migration")) {
		printf("test17: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test17: PASS (peer connection migration is set)\n");

	sleep(2);
	optlen = sizeof(addr);
	ret = getpeername(sockfd, (struct sockaddr *)&addr, &optlen);
	if (ret == -1 || get_port(&addr) != port + 1) {
		printf("test18: FAIL new port %d, expected port %d\n", get_port(&addr),
		       port + 1);
		return -1;
	}
	printf("test18: PASS (connection migration is done)\n");

	optlen = sizeof(info);
	info.dest = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen);
	if (ret == -1 || info.active != 13) {
		printf("teset20: FAIL ret %d, dest %u, source %u\n", ret, info.dest, info.prior_to);
		return -1;
	}
	printf("test19: PASS (retire source & dest connection id when doing migration)\n");

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0);
	if (ret == -1) {
		printf("socket setsockopt key update error %d\n", errno);
		return -1;
	}
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0);
	if (ret != -1) {
		printf("test20: FAIL\n");
		return -1;
	}
	printf("test20: PASS (not allowed to do key update when last one is not yet done)\n");

	strcpy(msg, "quic connection test21");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) { /* max_bidi_stream_id: 464 */
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic connection test21")) {
		printf("test21: FAIL msg %s\n", msg);
		return -1;
	}
	sleep(1);
	strcpy(msg, "quic connection test21");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) { /* max_bidi_stream_id: 468 */
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic connection test21")) {
		printf("test21: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test21: PASS (key update is done)\n");

	sleep(1);
	strcpy(msg, "client key_update");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) { /* max_bidi_stream_id: 472 */
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "client key_update")) {
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
	if (ret == -1) { /* max_bidi_stream_id: 476 */
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "quic connection test22")) {
		printf("test22: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test22: PASS (peer key update is done)\n");

	strcpy(msg, "client new_token");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) { /* max_bidi_stream_id: 480 */
		printf("recv error %d\n", errno);
		return 1;
	}
	if (strcmp(msg, "client new_token")) {
		printf("test23: FAIL msg %s\n", msg);
		return -1;
	}
	printf("test23: PASS (peer new_token is done)\n");

	optlen = sizeof(opt);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, opt, &optlen);
	if (ret == -1 || !optlen) {
		printf("test24: FAIL ret %d, opt %s\n", ret, opt);
		return -1;
	}
	printf("test24: PASS (get token from socket)\n");

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, NULL, 0);
	if (ret != -1) {
		printf("test25: FAIL\n");
		return -1;
	}
	printf("test25: PASS (not allowed to set token with an null value on client)\n");

	flags = MSG_QUIC_DATAGRAM;
	strcpy(msg, "client datagram");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "client datagram")) {
		printf("test26: FAIL msg %s\n", msg);
		return -1;
	}
	if (!(flags & MSG_QUIC_DATAGRAM)) {
		printf("test26: FAIL flags %u\n", flags);
		return -1;
	}
	printf("test26: PASS (send and recv datagram)\n");

	flags = MSG_QUIC_DATAGRAM;
	strcpy(msg, "client datagram");
	ret = quic_sendmsg(sockfd, msg, sizeof(msg), sid, flags);
	if (ret != -1) {
		printf("test27: FAIL msg len %d\n", ret);
		return -1;
	}
	printf("test27: PASS (do not allow to send datagram bigger than max_datagram)\n");
	return 0;
}

static int do_client_stream_test(int sockfd)
{
	struct quic_stream_info info = {};
	struct quic_errinfo errinfo = {};
	unsigned int optlen, flags;
	int64_t sid = 0;
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
	printf("test1: PASS (not allowed send(MSG_SYN) to open a stream "
	       "when last is not closed)\n");

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
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN | MSG_QUIC_STREAM_UNI); /* stream_id: 2 */
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
	printf("test5: PASS (not allowed to open a stream that is already closed with "
	       "getsockopt(QUIC_SOCKOPT_STREAM_OPEN))\n");

	optlen = sizeof(info);
	info.stream_id = 6;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 6 */
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
	printf("test6: PASS (use getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to "
	       "open a specific stream)\n");

	optlen = sizeof(info);
	info.stream_id = -1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 8 */
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
		printf("test7: FAIL msg %s, sid %d\n", msg, (int)info.stream_id);
		return -1;
	}
	printf("test7: PASS (use getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to open next bidi stream)\n");

	optlen = sizeof(info);
	info.stream_id = -1;
	info.stream_flags = MSG_QUIC_STREAM_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 10 */
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
		printf("test8: FAIL msg %s, sid %d\n", msg, (int)info.stream_id);
		return -1;
	}
	printf("test8: PASS (use getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to open next uni stream)\n");

	flags = MSG_QUIC_STREAM_NEW;
	sid  = 0;
	strcpy(msg, "quic ");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1) {
		printf("test9: FAIL\n");
		return -1;
	}
	printf("test9: PASS (not allowed to open a stream that is already closed with "
	       "sendmsg(MSG_QUIC_STREAM_NEW))\n");

	flags = MSG_QUIC_STREAM_NEW;
	sid  = 12;
	strcpy(msg, "quic ");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 12 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	strcpy(msg, "test10");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1) {
		printf("test10: FAIL\n");
		return -1;
	}
	printf("test10: PASS (not allowed to open a stream twice with sendmsg(MSG_QUIC_STREAM_NEW))\n");

	flags = MSG_QUIC_STREAM_FIN;
	sid  = 12;
	strcpy(msg, "test11");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test11") || sid != 12) {
		printf("test11: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test11: PASS (sendmsg with a specific stream normally)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_UNI;
	sid  = -1;
	strcpy(msg, "quic ");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 14 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	strcpy(msg, "test12");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1) {
		printf("test12: FAIL\n");
		return -1;
	}
	printf("test12: PASS (not allowed to open a stream with sendmsg(sid == -1) "
	       "if it the old one is not closed\n");

	flags = MSG_QUIC_STREAM_FIN;
	strcpy(msg, "test13");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test13") || sid != 15) {
		printf("test13: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test13: PASS (open next uni stream with sendmsg(sid == -1))\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = -1;
	strcpy(msg, "quic test14");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 16 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test14") || sid != 16) {
		printf("test14: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test14: PASS (open next bidi stream with sendmsg(sid == -1))\n");

	optlen = sizeof(info);
	info.stream_id = 18;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 18 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	optlen = sizeof(info);
	info.stream_id = 20;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 20 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	flags = MSG_QUIC_STREAM_FIN;
	sid  = 18;
	strcpy(msg, "quic test15");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test15") || sid != 19) {
		printf("test15: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test15: PASS (open multiple stream and send on 1st one)\n");

	flags = MSG_QUIC_STREAM_FIN;
	sid  = 20;
	strcpy(msg, "quic test16");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test16") || sid != 20) {
		printf("test16: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test16: PASS (open multiple stream and send on 2nd one)\n");

	flags = MSG_QUIC_STREAM_FIN;
	sid  = 20;
	strcpy(msg, "quic test17");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1) {
		printf("test17: FAIL\n");
		return -1;
	}
	printf("test17: PASS (not allowed to send data on a closed stream)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 400;
	strcpy(msg, "quic test18");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test18") || sid != 400) {
		printf("test18: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test18: PASS (sendmsg with sid > original max_streams_bidi)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 402;
	strcpy(msg, "quic test19");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test19") || sid != 403) {
		printf("test19: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test19: PASS (sendmsg with sid > original max_streams_uni)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_DONTWAIT;
	sid  = 428;
	strcpy(msg, "quic test20");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1 || errno != EAGAIN) {
		printf("test20: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test20: PASS (return -EAGAIN if sid > current max_streams_bidi)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 404;
	strcpy(msg, "quic test21");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test21") || sid != 404) {
		printf("test21: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 428;
	strcpy(msg, "quic test21");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test21") || sid != 428) {
		printf("test21: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test21: PASS (sendmsg after current max_streams_bidi grows)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_DONTWAIT;
	sid  = 426;
	strcpy(msg, "quic test22");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1 || errno != EAGAIN) {
		printf("test22: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test22: PASS (return -EAGAIN if sid > current max_streams_uni)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 406;
	strcpy(msg, "quic test23");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test23") || sid != 407) {
		printf("test23: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 426;
	strcpy(msg, "quic test23");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test23") || sid != 427) {
		printf("test23: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test23: PASS (sendmsg after current max_streams_uni grows)\n");

	optlen = sizeof(info);
	info.stream_id = 408;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 408 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	flags = MSG_QUIC_STREAM_FIN;
	sid = 408;
	strcpy(msg, "quic test24");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test24") || sid != 408) {
		printf("test24: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test24: PASS (getsockopt(STREAM_OPEN) with sid > original max_streams_bidi)\n");

	optlen = sizeof(info);
	info.stream_id = 410;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 410 */
	if (ret == -1) {
		printf("socket getsockopt stream open error %d\n", errno);
		return -1;
	}
	flags = MSG_QUIC_STREAM_FIN;
	sid  = 410;
	strcpy(msg, "quic test25");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test25") || sid != 411) {
		printf("test25: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test25: PASS (getsockopt(STREAM_OPEN) with sid > original max_streams_uni)\n");

	optlen = sizeof(info);
	info.stream_flags = MSG_QUIC_STREAM_DONTWAIT;
	info.stream_id = 440;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 440 */
	if (ret != -1 || errno != EAGAIN) {
		printf("test26: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test26: PASS (return -EAGAIN if sid > current max_streams_bidi)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 412;
	strcpy(msg, "quic test27");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test27") || sid != 412) { /* max_bidi_stream_id: 440 */
		printf("test27: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	optlen = sizeof(info);
	info.stream_flags = 0;
	info.stream_id = 440;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 440 */
	if (ret == -1) {
		printf("test27: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	flags = MSG_QUIC_STREAM_FIN;
	sid  = 440;
	strcpy(msg, "quic test27");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test27") || sid != 440) { /* max_bidi_stream_id: 444 */
		printf("test27: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test27: PASS (getsockopt(STREAM_OPEN) after max_streams_bidi grows)\n");

	optlen = sizeof(info);
	info.stream_flags = MSG_QUIC_STREAM_DONTWAIT;
	info.stream_id = 438;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 438 */
	if (ret != -1 || errno != EAGAIN) {
		printf("test28: FAIL ret %d, errno %d\n", ret, errno);
		return -1;
	}
	printf("test28: PASS (return -EAGAIN if sid > current max_streams_uni)\n");

	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	sid  = 414;
	strcpy(msg, "quic test29");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test29") || sid != 415) {
		printf("test29: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	optlen = sizeof(info);
	info.stream_flags = 0;
	info.stream_id = 438;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 &info, &optlen); /* stream_id: 438 */
	if (ret == -1) {
		printf("test29: FAIL ret %d, errno %d\n", ret, errno);
		return -1;
	}
	flags = MSG_QUIC_STREAM_FIN;
	sid  = 438;
	strcpy(msg, "quic test29");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test29") || sid != 439) { /* max_uni_stream_id: 442 */
		printf("test29: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	printf("test29: PASS (getsockopt(STREAM_OPEN) max_streams_bidi grows)\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = 414;
	errinfo.errcode = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
	if (ret != -1 || errno != ENOSTR) {
		printf("test30: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test30: PASS (not allowed to reset a closed stream)\n");

	flags = MSG_QUIC_STREAM_FIN;
	sid  = 416;
	strcpy(msg, "quic test31");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) { /* max_bidi_stream_id: 448 */
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test31") || sid != 416) {
		printf("test31: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	flags = MSG_QUIC_STREAM_FIN;
	sid  = 420;
	strcpy(msg, "quic test31");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
	if (ret == -1) {  /* max_bidi_stream_id: 452 */
		printf("recv error %d\n", errno);
		return -1;
	}
	if (strcmp(msg, "quic test31") || sid != 420) {
		printf("test31: FAIL msg %s, sid %d\n", msg, (int)sid);
		return -1;
	}
	optlen = sizeof(errinfo);
	errinfo.stream_id = 444;
	errinfo.errcode = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
	if (ret != -1 || errno != EINVAL) {
		printf("test31: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test31: PASS (not allowed to reset a stream that hasn't opened)\n");

	flags = MSG_QUIC_STREAM_NEW;
	sid  = 444;
	strcpy(msg, "client reset");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 444 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	}
	optlen = sizeof(errinfo);
	errinfo.stream_id = 444;
	errinfo.errcode = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen);
	if (ret == -1) {
		printf("socket setsockopt stream reset error %d\n", errno);
		return -1;
	}
	printf("test32: PASS (reset a opened stream)\n");

	flags = 0;
	strcpy(msg, "test33");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1 || errno != EINVAL) {
		printf("test33: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test33: PASS (not allowed to send data on a reset stream)\n");

	flags = MSG_QUIC_STREAM_FIN;
	strcpy(msg, "test34");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1 || errno != EINVAL) {
		printf("test34: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test34: PASS (not allowed to send data with FIN on a reset stream)\n");

	flags = MSG_QUIC_STREAM_NEW;
	sid  = 418;
	strcpy(msg, "client stop_sending");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags); /* stream_id: 418 */
	if (ret == -1) {
		printf("send error %d\n", errno);
		return -1;
	} /* max_uni_stream_id: 446 */
	sleep(1);
	flags = 0;
	strcpy(msg, "test35");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1 || errno != ENOSTR) {
		printf("test35: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test35: PASS (not allowed to send data on a reset stream by peer stop_sending)\n");

	flags = MSG_QUIC_STREAM_FIN;
	strcpy(msg, "test36");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret != -1 || errno != ENOSTR) {
		printf("test36: FAIL ret %d, error %d\n", ret, errno);
		return -1;
	}
	printf("test36: PASS (not allowed to send data with FIN on a reset stream set by peer "
	       "stop_sending)\n");
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
	unsigned int optlen, flags = 0;
	struct sockaddr_storage addr = {};
	int64_t len = 0, sid = 0;
	int ret;

	while (1) {
		ret = quic_recvmsg(sockfd, &msg[len], sizeof(msg) - len, &sid, &flags);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return -1;
		}
		len += ret;
		if (!strcmp(msg, "client reset")) {
			if (flags & MSG_QUIC_STREAM_FIN) {
				sleep(1);
				flags = MSG_QUIC_STREAM_NEW;
				if (sid & QUIC_STREAM_TYPE_UNI_MASK) {
					flags |= MSG_QUIC_STREAM_NEW;
					sid  |= QUIC_STREAM_TYPE_SERVER_MASK;
				}
				ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
				if (ret == -1) {
					printf("send %d %d\n", ret, errno);
					return -1;
				}
				optlen = sizeof(errinfo);
				errinfo.stream_id = sid;
				errinfo.errcode = 1;
				ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_RESET,
						 &errinfo, optlen);
				if (ret == -1) {
					printf("socket setsockopt stream stop_sending failed %d\n",
					       errno);
					return -1;
				}
			}
			goto reset;
		}

		if (!strcmp(msg, "client stop_sending")) {
			optlen = sizeof(errinfo);
			errinfo.stream_id = sid;
			errinfo.errcode = 1;
			ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_STOP_SENDING,
					 &errinfo, optlen);
			if (ret == -1) {
				printf("socket setsockopt stream stop_sending failed %d\n", errno);
				return -1;
			}
			goto reset;
		}

		if (!(flags & MSG_QUIC_STREAM_FIN) && !(flags & MSG_QUIC_DATAGRAM))
			continue;

		if (!strcmp(msg, "client migration")) {
			optlen = sizeof(addr);
			ret = getsockname(sockfd, (struct sockaddr *)&addr, &optlen);
			if (ret == -1) {
				printf("socket getsockname failed %d\n", errno);
				return -1;
			}
			set_port(&addr, get_port(&addr) + 1);
			ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION,
					 &addr, optlen);
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
			flags = MSG_QUIC_DATAGRAM;
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

		flags = MSG_QUIC_STREAM_FIN;
		if (sid & QUIC_STREAM_TYPE_UNI_MASK) { /* use the corresp sid in server */
			flags |= MSG_QUIC_STREAM_NEW;
			sid  |= QUIC_STREAM_TYPE_SERVER_MASK;
		}
reply:
		/* echo reply */
		ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
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
	close(sockfd);
	return 0;
}

static int do_client(int argc, char *argv[])
{
	struct quic_transport_param param = {};
	struct sockaddr_storage ra = {};
	char *pkey = NULL;
	const char *rc;
	int sockfd;

	if (argc < 3) {
		printf("%s client <PEER ADDR> <PEER PORT> [PSK_FILE]\n", argv[0]);
		return 0;
	}

	rc = parse_address(argv[2], argv[3], &ra);
	if (rc != NULL) {
		printf("parse address failed: %s\n", rc);
		return -1;
	}

	sockfd = socket(ra.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	param.max_datagram_frame_size = 1400;
	if (argc < 5)
		goto start;
	pkey = argv[4];
start:
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;

	if (quic_client_handshake(sockfd, pkey, NULL, NULL))
		return -1;
	printf("HANDSHAKE DONE\n");
	return do_client_test(sockfd);
}

static int do_server(int argc, char *argv[])
{
	struct quic_transport_param param = {};
	struct sockaddr_storage la = {}, ra = {};
	char *pkey, *cert = NULL;
	int listenfd, sockfd;
	unsigned int addrlen;
	const char *rc;

	if (argc < 5) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PSK_FILE> | <PRIVATE_KEY_FILE> "
		       "<CERTIFICATE_FILE>\n", argv[0]);
		return 0;
	}

	rc = parse_address(argv[2], argv[3], &la);
	if (rc != NULL) {
		printf("parse address failed: %s\n", rc);
		return -1;
	}
	listenfd = socket(la.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
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
	pkey = argv[4];
	cert = argv[5];

	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;

	if (quic_server_handshake(sockfd, pkey, cert, NULL))
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

	quic_set_log_level(LOG_NOTICE);

	if (!strcmp(argv[1], "client"))
		return do_client(argc, argv);

	return do_server(argc, argv);
}
