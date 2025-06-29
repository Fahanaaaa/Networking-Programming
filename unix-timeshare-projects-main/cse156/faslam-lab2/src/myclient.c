#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <libgen.h>
#include <time.h>

#define HEADER_SIZE 10
#define TIMEOUT_SEC 60
#define CRUZID "faslam:"

void print_error(const char *msg) {
    perror(msg);
    exit(1);
}

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

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "To use: %s <server_ip> <server_port> <mss> <infile> <outfile>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    int mss = atoi(argv[3]);
    const char *infile = argv[4];
    const char *outfile = argv[5];

    if ((size_t)mss <= HEADER_SIZE + strlen(CRUZID)) {
        fprintf(stderr, "Required minimum MSS is %ld + 1\n", HEADER_SIZE + strlen(CRUZID));
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) print_error("socket error");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &servaddr.sin_addr) <= 0)
        print_error("inet_pton error");

    FILE *fin = fopen(infile, "rb");
    if (!fin) print_error("fopen infile");

    char *outfile_dir = strdup(outfile);
    char *dir = dirname(outfile_dir);
    char mkdir_cmd[512];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", dir);
    system(mkdir_cmd);
    free(outfile_dir);

    FILE *fout = fopen(outfile, "wb+");
    if (!fout) print_error("fopen outfile");

    int seq = 0;
    int payload_size = mss - HEADER_SIZE - strlen(CRUZID);
    char *payload = malloc(payload_size);
    char *packet = malloc(mss);
    char *recvbuf = malloc(mss);
    time_t start_time, current_time;

    start_time = time(NULL);

    while (!feof(fin)) {
        size_t read_len = fread(payload, 1, payload_size, fin);
        if (read_len == 0 && feof(fin)) break;

        packet[0] = 0x1;
        int net_seq = htonl(seq);
        int net_len = htonl((int)read_len);
        memcpy(packet + 1, &net_seq, 4);
        memcpy(packet + 5, &net_len, 4);
        memcpy(packet + 9, CRUZID, strlen(CRUZID));
        memcpy(packet + 9 + strlen(CRUZID), payload, read_len);

        int pkt_size = 9 + strlen(CRUZID) + read_len + 1;
        packet[pkt_size - 1] = checksum(packet, pkt_size - 1);

        //printf("Send packet #%d (%d bytes total)\n", seq, pkt_size);
        sendto(sockfd, packet, pkt_size, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));

        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t recv_len;

        while (1) {
            recv_len = recvfrom(sockfd, recvbuf, mss, MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
            if (recv_len > 0) break;

            current_time = time(NULL);
            if (difftime(current_time, start_time) >= TIMEOUT_SEC) {
                fprintf(stderr, "Cannot detect server\n");
                fclose(fin); fclose(fout); free(payload); free(packet); free(recvbuf);
                return 1;
            }

            usleep(100000); 
        }

        int recv_seq;
        memcpy(&recv_seq, recvbuf + 1, 4);
        recv_seq = ntohl(recv_seq);
        int recv_data_len;
        memcpy(&recv_data_len, recvbuf + 5, 4);
        recv_data_len = ntohl(recv_data_len);

        unsigned char expected_chk = checksum(recvbuf, recv_len - 1);
        unsigned char received_chk = recvbuf[recv_len - 1];

        //printf("RVC packet #%d (%zd bytes). EXP checksum: %u, RCV: %u\n", recv_seq, recv_len, expected_chk, received_chk);

        if (received_chk != expected_chk) {
            fprintf(stderr, "Packet loss detected\n");
            fclose(fin); fclose(fout); free(payload); free(packet); free(recvbuf);
            return 2;
        }

        fwrite(recvbuf + 9 + strlen(CRUZID), 1, recv_data_len, fout);
        seq++;

        start_time = time(NULL);
    }

    fclose(fin);
    fclose(fout);
    free(payload);
    free(packet);
    free(recvbuf);
    return 0;
}

