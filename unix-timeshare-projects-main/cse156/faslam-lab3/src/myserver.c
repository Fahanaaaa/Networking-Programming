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
#define HEADER_SIZE 9  // 1 byte type + 4 byte seq + 4 byte length
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
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <droppc>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    int droppc = atoi(argv[2]);
    if (droppc < 0 || droppc > 100) {
        fprintf(stderr, "droppc must be between 0 and 100\n");
        return 1;
    }

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

        // Drop logic (DATA/META are both dropped as DATA here)
        if (should_drop(droppc)) {
            printf("%s, DROP %s, %d\n", rfc3339_time(), type == TYPE_META ? "DATA" : "DATA", seq);
            continue;
        }

        unsigned char received_chk = buffer[recv_len - 1];
        unsigned char computed_chk = checksum((unsigned char *)buffer, recv_len - 1);
        if (received_chk != computed_chk) continue;

        if (type == TYPE_META && seq == 0 && fout == NULL) {
            // Extract output file path
            char outfile_path[1024] = {0};
            memcpy(outfile_path, buffer + HEADER_SIZE + CRUZID_LEN, datalen);

            // Create necessary directories
            char *pathcopy = strdup(outfile_path);
            char mkdir_cmd[1024];
            snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", dirname(pathcopy));
            system(mkdir_cmd);
            free(pathcopy);

            // Open file
            fout = fopen(outfile_path, "wb");
            if (!fout) {
                perror("fopen");
                return 1;
            }
            expected_seq = 1;
        }
        else if (type == TYPE_DATA && seq == expected_seq && fout != NULL) {
            fwrite(buffer + HEADER_SIZE + CRUZID_LEN, 1, datalen, fout);
            fflush(fout);
            expected_seq++;
        }

        // Send ACK unless dropped
        if (should_drop(droppc)) {
            printf("%s, DROP ACK, %d\n", rfc3339_time(), seq);
            continue;
        }

        char ack[10] = {0};
        ack[0] = 0x2;
        int net_seq = htonl(seq);
        int dummy = htonl(0);
        memcpy(ack + 1, &net_seq, 4);
        memcpy(ack + 5, &dummy, 4);
        ack[9] = checksum((unsigned char *)ack, 9);
        sendto(sockfd, ack, 10, 0, (struct sockaddr *)&cliaddr, len);
        printf("%s, ACK, %d\n", rfc3339_time(), seq);
    }

    if (fout) fclose(fout);
    close(sockfd);
    return 0;
}

