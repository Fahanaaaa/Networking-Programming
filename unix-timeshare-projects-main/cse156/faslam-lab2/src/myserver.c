#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX_PACKET_SIZE 32768

unsigned char checksum(const char *data, int len) {
    unsigned long sum = 0;
    for (int i = 0; i < len; ++i) {
        sum += (unsigned char)data[i];
        if (sum & 0xFFFF0000) {
            sum &= 0xFFFF;
            sum++;
        }
    }
    return (unsigned char)(sum & 0xFF);
}

void print_error(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) print_error("socket");

    struct sockaddr_in servaddr, cliaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        print_error("bind error");

    char buffer[MAX_PACKET_SIZE] = {0};

    printf("Server listening on port %d...\n", port);

    while (1) {
        socklen_t len = sizeof(cliaddr);
        ssize_t recv_len = recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0,
                                    (struct sockaddr *)&cliaddr, &len);

        if (recv_len <= 0) {
            fprintf(stderr, "recvfrom error\n");
            continue;
        }

        //printf("RCV %zd bytes from %s:%d\n", recv_len, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));

        if (recv_len < 10) {
            fprintf(stderr, "Packet too small\n");
            continue;
        }

        unsigned char received_chk = buffer[recv_len - 1];
        unsigned char computed_chk = checksum(buffer, recv_len - 1);

        printf("chcksm %u vs rcvd %u\n", computed_chk, received_chk);

        if (computed_chk != received_chk) {
            fprintf(stderr, "Checksum error: expected %u, got %u\n",
                    computed_chk, received_chk);
            continue;
        }

        ssize_t sent_len = sendto(sockfd, buffer, recv_len, 0,
                                  (struct sockaddr *)&cliaddr, len);
        if (sent_len != recv_len) {
            fprintf(stderr, "Failed to send full packet (%zd/%zd bytes)\n",
                    sent_len, recv_len);
        } else {
            printf("Echoed %zd bytes to %s:%d\n",
                   sent_len, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));
        }
    }

    close(sockfd);
    return 0;
}

