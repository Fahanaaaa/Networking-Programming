// FINAL myserver.c — fixed -Wsign-compare by casting sizeof() for safe comparison

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
#include <time.h>
#include <libgen.h>

#define MAX_PACKET_SIZE 32768
#define CRUZID_LEN 7
#define HEADER_SIZE 9
#define TYPE_META 0x2
#define TYPE_DATA 0x1

unsigned char checksum(const unsigned char *data, int len) {
    unsigned int sum = 0;
    for (int i = 0; i < len; ++i) {
        sum += data[i];
    }
    return (unsigned char)(sum % 256);
}

char *rfc3339_time() {
    static char buf[64];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = gmtime(&ts.tv_sec);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);
    int ms = ts.tv_nsec / 1000000;
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".%03dZ", ms);
    return buf;
}

int should_drop(int droppc) {
    return (rand() % 100) < droppc;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <port> <droppc> <root_folder>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    int droppc = atoi(argv[2]);
    char *root_folder = argv[3];

    srand(time(NULL));
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in servaddr, cliaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("Server listening on port %d...\n", port);

    FILE *fout = NULL;
    int expected_seq = 1;
    char buffer[MAX_PACKET_SIZE];
    char active_path[2048];
    char active_client[64] = "";

    while (1) {
        socklen_t len = sizeof(cliaddr);
        ssize_t recv_len = recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr *)&cliaddr, &len);
        if (recv_len < HEADER_SIZE + CRUZID_LEN + 1) continue;

        unsigned char type = buffer[0];
        int seq, datalen;
        memcpy(&seq, buffer + 1, 4);
        memcpy(&datalen, buffer + 5, 4);
        seq = ntohl(seq);
        datalen = ntohl(datalen);

        if (should_drop(droppc)) {
            printf("%s, %d, %s, %d, DROP %s, %d\n", rfc3339_time(), port, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), (type == TYPE_DATA ? "DATA" : "META"), seq);
            continue;
        }

        unsigned char received_chk = buffer[recv_len - 1];
        unsigned char computed_chk = checksum((unsigned char *)buffer, recv_len - 1);
        if (received_chk != computed_chk) continue;

        char client_id[64];
        snprintf(client_id, sizeof(client_id), "%s:%d", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));

        if (type == TYPE_META && seq == 0) {
            if (fout != NULL && strcmp(active_client, client_id) != 0) {
                fprintf(stderr, "File is in progress by another client\n");
                continue;
            }

            char outfile_rel[1024] = {0};
            memcpy(outfile_rel, buffer + HEADER_SIZE + CRUZID_LEN, datalen);
            if ((size_t)snprintf(active_path, sizeof(active_path), "%s/%s", root_folder, outfile_rel) >= sizeof(active_path)) {
                fprintf(stderr, "Path too long\n");
                continue;
            }

            char path_copy[2048];
            strncpy(path_copy, active_path, sizeof(path_copy));
            path_copy[sizeof(path_copy) - 1] = '\0';
            char mkdir_cmd[2048];
            snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", dirname(path_copy));
            system(mkdir_cmd);

            fout = fopen(active_path, "wb");
            if (!fout) {
                perror("fopen");
                return 1;
            }
            strncpy(active_client, client_id, sizeof(active_client));
            expected_seq = 1;
        } else if (type == TYPE_DATA && seq == expected_seq && fout != NULL) {
            fwrite(buffer + HEADER_SIZE + CRUZID_LEN, 1, datalen, fout);
            fflush(fout);
            expected_seq++;
        }

        if (should_drop(droppc)) {
            printf("%s, %d, %s, %d, DROP ACK, %d\n", rfc3339_time(), port, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), seq);
            continue;
        }

        char ack[10] = {0};
        ack[0] = TYPE_META;
        int net_seq = htonl(seq);
        int dummy = htonl(0);
        memcpy(ack + 1, &net_seq, 4);
        memcpy(ack + 5, &dummy, 4);
        ack[9] = checksum((unsigned char *)ack, 9);
        sendto(sockfd, ack, 10, 0, (struct sockaddr *)&cliaddr, len);

        printf("%s, %d, %s, %d, ACK, %d\n", rfc3339_time(), port, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), seq);
    }

    if (fout) fclose(fout);
    close(sockfd);
    return 0;
}
