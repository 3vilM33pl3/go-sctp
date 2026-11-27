/*
 * usrsctpecho: SCTP-over-UDP echo client/server on usrsctp, same protocol as
 * goecho (100 messages, stream i%5, PPID 0x10000+i, message 50 is 200 KiB).
 *
 *   usrsctpecho server <sctp_port> <local_udp_port> [remote_udp_port]
 *   usrsctpecho client <ip> <sctp_port> <local_udp_port> <remote_udp_port>
 *
 * Build: cc -O2 -I<usrsctp>/usrsctplib usrsctpecho.c <usrsctp>/build/usrsctplib/libusrsctp.a -lpthread
 */
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <usrsctp.h>

#define N 100
#define BIG (200 * 1024)
#define STREAMS 5

static int big = BIG;

static size_t psize(int i) { return i == N / 2 ? (size_t)big : (size_t)(64 + (i * 37) % 2000); }

static unsigned char *payload(int i) {
	size_t n = psize(i);
	unsigned char *b = malloc(n);
	for (size_t j = 0; j < n; j++)
		b[j] = (unsigned char)(j * 7 + i);
	uint32_t be = htonl((uint32_t)i);
	memcpy(b, &be, 4);
	return b;
}

static const char *role = "usrsctp";

static void lg(const char *fmt, ...) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);
	fprintf(stderr, "[usrsctp-%s] %02d:%02d:%02d.%06ld ", role, tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

#define FAIL(...) do { lg("FAIL: " __VA_ARGS__); exit(1); } while (0)

static void setup(struct socket *s) {
	const int on = 1;
	uint16_t ev[] = {SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_EVENT, SCTP_REMOTE_ERROR, SCTP_SEND_FAILED_EVENT};
	struct sctp_event e;
	struct sctp_initmsg im;
	usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof on);
	memset(&e, 0, sizeof e);
	e.se_assoc_id = SCTP_ALL_ASSOC;
	e.se_on = 1;
	for (unsigned i = 0; i < sizeof ev / sizeof ev[0]; i++) {
		e.se_type = ev[i];
		if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_EVENT, &e, sizeof e) < 0)
			perror("SCTP_EVENT");
	}
	memset(&im, 0, sizeof im);
	im.sinit_num_ostreams = 10;
	im.sinit_max_instreams = 10;
	usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_INITMSG, &im, sizeof im);
	int buf = 1 << 20;
	usrsctp_setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
	usrsctp_setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
}

static void set_encaps(struct socket *s, int port) {
	struct sctp_udpencaps enc;
	memset(&enc, 0, sizeof enc);
	enc.sue_address.ss_family = AF_INET;
	enc.sue_assoc_id = SCTP_FUTURE_ASSOC;
	enc.sue_port = htons((uint16_t)port);
	if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, &enc, sizeof enc) < 0)
		perror("SCTP_REMOTE_UDP_ENCAPS_PORT");
}

/* Returns 1 for a notification, 0 for a complete message, -1 on EOF. */
struct msg {
	unsigned char *data;
	size_t len, cap;
	struct sctp_rcvinfo info;
	struct sockaddr_in from;
	uint16_t ntype, nstate;
};

static int next(struct socket *s, struct msg *m) {
	static unsigned char buf[65536];
	m->len = 0;
	for (;;) {
		struct sockaddr_in from;
		socklen_t fl = sizeof from, il = sizeof m->info;
		unsigned int it = 0;
		int flags = 0;
		struct sctp_rcvinfo ri;
		ssize_t n = usrsctp_recvv(s, buf, sizeof buf, (struct sockaddr *)&from, &fl, &ri, &il, &it, &flags);
		if (n < 0)
			FAIL("recvv: %s", strerror(errno));
		if (n == 0)
			return -1;
		if (flags & MSG_NOTIFICATION) {
			union sctp_notification *sn = (void *)buf;
			m->ntype = sn->sn_header.sn_type;
			m->nstate = m->ntype == SCTP_ASSOC_CHANGE ? sn->sn_assoc_change.sac_state : 0;
			if (m->ntype == SCTP_SEND_FAILED_EVENT)
				lg("notification SEND_FAILED error=%u", sn->sn_send_failed_event.ssfe_error);
			else if (m->ntype == SCTP_REMOTE_ERROR)
				lg("notification REMOTE_ERROR error=%u", ntohs(sn->sn_remote_error.sre_error));
			else
				lg("notification type=%#x state=%u", m->ntype, m->nstate);
			return 1;
		}
		if (m->len + (size_t)n > m->cap) {
			m->cap = (m->len + (size_t)n) * 2;
			m->data = realloc(m->data, m->cap);
		}
		memcpy(m->data + m->len, buf, (size_t)n);
		m->len += (size_t)n;
		if (it == SCTP_RECVV_RCVINFO)
			m->info = ri;
		m->from = from;
		if (flags & MSG_EOR)
			return 0;
	}
}

static void sendmsg_(struct socket *s, const void *b, size_t n, uint16_t sid, uint32_t ppid, sctp_assoc_t a,
                     struct sockaddr *to, socklen_t tl) {
	struct sctp_sndinfo si;
	memset(&si, 0, sizeof si);
	si.snd_sid = sid;
	si.snd_ppid = htonl(ppid);
	si.snd_assoc_id = a;
	if (usrsctp_sendv(s, b, n, to, to ? 1 : 0, &si, sizeof si, SCTP_SENDV_SNDINFO, 0) < 0)
		FAIL("sendv sid=%u len=%zu: %s", sid, n, strerror(errno));
}

static void server(int port, int lport, int rport) {
	role = "server";
	usrsctp_init((uint16_t)lport, NULL, NULL);
	usrsctp_sysctl_set_sctp_blackhole(2);
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0);
	struct socket *s = usrsctp_socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP, NULL, NULL, 0, NULL);
	if (!s)
		FAIL("socket");
	setup(s);
	if (rport)
		set_encaps(s, rport);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (usrsctp_bind(s, (struct sockaddr *)&a, sizeof a) < 0)
		FAIL("bind: %s", strerror(errno));
	usrsctp_listen(s, 1);
	lg("listening sctp port %d, udp port %d", port, lport);
	struct msg m = {0};
	int count = 0;
	size_t bytes = 0;
	for (;;) {
		int r = next(s, &m);
		if (r < 0)
			FAIL("EOF after %d", count);
		if (r == 1) {
			if (m.ntype == SCTP_ASSOC_CHANGE && m.nstate == SCTP_SHUTDOWN_COMP) {
				lg("PASS: echoed %d messages (%zu bytes), graceful shutdown complete", count, bytes);
				break;
			}
			if (m.ntype == SCTP_ASSOC_CHANGE && m.nstate == SCTP_COMM_LOST)
				FAIL("COMM_LOST after %d", count);
			continue;
		}
		count++;
		bytes += m.len;
		sendmsg_(s, m.data, m.len, m.info.rcv_sid, ntohl(m.info.rcv_ppid), m.info.rcv_assoc_id, NULL, 0);
	}
	usrsctp_close(s);
	sleep(1);
	usrsctp_finish();
}

static void client(const char *ip, int port, int lport, int rport) {
	role = "client";
	usrsctp_init((uint16_t)lport, NULL, NULL);
	usrsctp_sysctl_set_sctp_blackhole(2);
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0);
	struct socket *s = usrsctp_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
	if (!s)
		FAIL("socket");
	setup(s);
	set_encaps(s, rport);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
	inet_pton(AF_INET, ip, &a.sin_addr);
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (usrsctp_connect(s, (struct sockaddr *)&a, sizeof a) < 0)
		FAIL("connect: %s", strerror(errno));
	lg("connected to %s:%d (udp %d -> %d)", ip, port, lport, rport);
	/* Send everything first: the socket buffer (1 MiB) holds all of it. */
	for (int i = 0; i < N; i++) {
		unsigned char *p = payload(i);
		sendmsg_(s, p, psize(i), (uint16_t)(i % STREAMS), 0x10000u + (uint32_t)i, 0, NULL, 0);
		free(p);
	}
	struct msg m = {0};
	int got = 0, per[STREAMS] = {0};
	while (got < N) {
		int r = next(s, &m);
		if (r < 0)
			FAIL("EOF after %d", got);
		if (r == 1)
			continue;
		uint32_t be;
		memcpy(&be, m.data, 4);
		int i = (int)ntohl(be);
		unsigned char *p = i >= 0 && i < N ? payload(i) : NULL;
		if (!p || m.len != psize(i) || memcmp(p, m.data, m.len) != 0)
			FAIL("payload mismatch msg %d len %zu", i, m.len);
		free(p);
		if (m.info.rcv_sid != i % STREAMS || ntohl(m.info.rcv_ppid) != 0x10000u + (uint32_t)i)
			FAIL("msg %d metadata sid=%u ppid=%#x", i, m.info.rcv_sid, ntohl(m.info.rcv_ppid));
		if (per[m.info.rcv_sid] != i / STREAMS)
			FAIL("msg %d out of order", i);
		per[m.info.rcv_sid]++;
		got++;
	}
	lg("verified %d echoes (big=%d)", got, big);
	usrsctp_shutdown(s, SHUT_WR);
	for (;;) {
		int r = next(s, &m);
		if (r < 0) {
			lg("EOF after shutdown");
			break;
		}
		if (r == 1 && m.ntype == SCTP_ASSOC_CHANGE && m.nstate == SCTP_SHUTDOWN_COMP)
			break;
		if (r == 0)
			FAIL("data after shutdown");
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	lg("PASS: %d messages echoed and verified, graceful shutdown in %.1fms", got,
	   (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6);
	usrsctp_close(s);
	usrsctp_finish();
}

static void *watchdog(void *arg) {
	(void)arg;
	sleep(60);
	FAIL("timeout");
	return NULL;
}

int main(int argc, char **argv) {
	if (getenv("BIG"))
		big = atoi(getenv("BIG"));
	pthread_t t;
	pthread_create(&t, NULL, watchdog, NULL);
	if (argc >= 4 && strcmp(argv[1], "server") == 0)
		server(atoi(argv[2]), atoi(argv[3]), argc > 4 ? atoi(argv[4]) : 0);
	else if (argc >= 6 && strcmp(argv[1], "client") == 0)
		client(argv[2], atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
	else {
		fprintf(stderr, "usage: see source\n");
		return 2;
	}
	return 0;
}
