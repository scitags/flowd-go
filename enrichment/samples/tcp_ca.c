#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h> /* inet_addr */
#include <netinet/tcp.h> /* TCP_CONGESTION */
#include <netinet/in.h> /* IPPROTO_TCP */
#include <unistd.h> /* sleep() */
#include <signal.h>

#define CA_ALGORITHM "illinois"

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 8888
#define SEND_INTERVAL_USEC 10000

static volatile int keepRunning = 1;

void intHandler(int dummy) {
    keepRunning = 0;
}

int main() {
	signal(SIGINT, intHandler);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket creation failed");
		return 1;
	}

	if (setsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, CA_ALGORITHM, strlen(CA_ALGORITHM)) < 0) {
		perror("setsockopt failed");
		return 1;
	}
	printf("TCP congestion control set to %s\n", CA_ALGORITHM);
	
	struct sockaddr_in server = {
		.sin_addr.s_addr = inet_addr(SERVER_ADDRESS),
		.sin_family = AF_INET,
		.sin_port = htons(SERVER_PORT)
	};

	if (connect(sockfd , (struct sockaddr *)&server , sizeof(server)) < 0) {
		perror("connect failed. Error");
		return 1;
	}
	printf("connected\n");
	
	int acc = 0, msg_len;
	char msg[1000];
	while(keepRunning) {
		msg_len = sprintf(msg, "hello there # %d\n", acc);
		if(send(sockfd , msg , msg_len , 0) < 0) {
			printf("send failed");
			return 1;
		}

		acc++;
		usleep(SEND_INTERVAL_USEC);
	}
	
	printf("bye!\n");
	close(sockfd);
	return 0;
}
