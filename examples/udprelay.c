#include <libudp_splice.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#define die(fmt, args...) \
do { \
	fprintf(stderr, fmt "\n", ##args); \
	exit(EXIT_FAILURE); \
} while (0)

#define fail(fmt, args...) die("Failed to " fmt, ##args)

static int sock_bind(unsigned short port)
{
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;

	if (sock < 0)
		goto err;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
		goto err2;

	return sock;
err2:
	close(sock);
err:
	return -1;
}

static int sock_connect(const char *ip, unsigned short port)
{
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;

	if (sock < 0)
		goto err;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_port = htons(port);
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)))
		goto err2;

	return sock;
err2:
	close(sock);
err:
	return -1;
}

static void sock_passive_connect(int sock)
{
	char buf[1];
	int len;
	struct sockaddr_in addr;
	socklen_t addr_len;

	addr_len = sizeof(addr);
	len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr,
			&addr_len);
	if (len <= 0)
		fail("read sock");
	printf("receive message from %s:%u\n", inet_ntoa(addr.sin_addr),
			ntohs(addr.sin_port));
	if (connect(sock, (struct sockaddr *)&addr, addr_len)) {
		fail("connect to %s:%u\n", inet_ntoa(addr.sin_addr),
				ntohs(addr.sin_port));
	}
	printf("connect to %s:%u from", inet_ntoa(addr.sin_addr),
			ntohs(addr.sin_port));
	if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) < 0)
		fail("getsockname");
	printf(" %s:%u\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
}

static int sock, sock2, sock3, sock4;

void *ping(void *arg)
{
	int i;
	char buf[16];
	int len;


	for (i = 0; i < 10; i++) {
		sprintf(buf, "ping %d", i);
		printf("ping: send ping: %d\n", i);
		if (write(sock3, buf, 6) != 6)
			fail("ping: write");
		len = read(sock3, buf, sizeof(buf));
		if (len != 6 || memcmp(buf, "pong ", 5) || buf[5] != '0' + i)
			fail("ping: read");
		printf("ping: receive pong: %d\n", i);
		sleep(i + 1);
	}

	return NULL;
}

void *pong(void *arg)
{
	char buf[16];
	int len;

	while (1) {
		len = read(sock4, buf, sizeof(buf));
		if (len != 6 || memcmp(buf, "ping ", 5))
			fail("pong: read");
		buf[1] = 'o';
		printf("pong: receive ping: %d\n", buf[5] - '0');
		printf("pong: send pong: %d\n", buf[5] - '0');
		if (write(sock4, buf, 6) != 6)
			fail("pong: write");
	}

	return NULL;
}

void *relay1to2(void *arg)
{
	char buf[16];
	int len;

	while (1) {
		len = read(sock, buf, sizeof(buf));
		if (len <= 0)
			fail("relay1to2: read");
		printf("relay1to2: ");
		fwrite(buf, len, 1, stdout);
		printf("\n");
		if (write(sock2, buf, len) != len)
			fail("relay1to2: write");
	}

	return NULL;
}

void *relay2to1(void *arg)
{
	char buf[16];
	int len;

	while (1) {
		len = read(sock2, buf, sizeof(buf));
		if (len <= 0)
			fail("relay2to1: read");
		printf("relay2to1: ");
		fwrite(buf, len, 1, stdout);
		printf("\n");
		if (write(sock, buf, len) != len)
			fail("relay2to1: write");
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t tid;
	void *handle;

	sock = sock_bind(8080);
	if (sock < 0)
		fail("bind to 8080");
	sock2 = sock_bind(8888);
	if (sock2 < 0)
		fail("bind to 8888");

	sock3 = sock_connect("127.0.0.1", 8080);
	if (write(sock3, "@", 1) < 0)
		fail("knock");
	sock_passive_connect(sock);

	sock4 = sock_connect("127.0.0.1", 8888);
	if (write(sock4, "@", 1) < 0)
		fail("knock");
	sock_passive_connect(sock2);

	handle = udp_splice_open();
	if (!handle)
		die("udp splice isn't supported\n");

	if (udp_splice_add(handle, sock, sock2, 5))
		perror("udp_splice");

	if (pthread_create(&tid, NULL, pong, NULL))
		fail("create thread pong");
	if (pthread_create(&tid, NULL, relay1to2, NULL))
		fail("create thread relay1to2");
	if (pthread_create(&tid, NULL, relay2to1, NULL))
		fail("create thread relay2to1");

	ping(NULL);

	return EXIT_SUCCESS;
}
