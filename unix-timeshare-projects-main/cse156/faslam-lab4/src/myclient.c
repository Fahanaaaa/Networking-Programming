// FINAL myclient.c — sequence-point bug fixed: split increment & assignment for checksum storage
// Changes: meta[pkt_len++] = ... → meta[pkt_len] = ...; pkt_len++;
// and window[idx][full_len++] = ... → window[idx][full_len] = ...; full_len++;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>

#define HEADER_SIZE 9
#define MAX_PACKET_SIZE 32768
#define MAX_RETRIES 5
#define TIMEOUT_SEC 3
#define DEADLINE_SEC 30
#define TYPE_META 0x2
#define TYPE_DATA 0x1
#define CRUZID_LEN 7
#define MAX_SERVERS 10

const char* CRUZID = "faslam:";

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

unsigned char checksum(const unsigned char *data, int len) {
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

struct thread_args {
    char ip[INET_ADDRSTRLEN];
    int port;
    int mss;
    int winsz;
    char file_path[1024];
    char rel_path[1024];
};

void* send_file_thread(void* arg) {
    struct thread_args *args = (struct thread_args*)arg;
    FILE *fp = fopen(args->file_path, "rb");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &servaddr.sin_addr);
    socklen_t addrlen = sizeof(servaddr);

    char meta[2048];
    meta[0] = TYPE_META;
    int net_seq = htonl(0);
    int net_len = htonl(strlen(args->rel_path));
    memcpy(meta + 1, &net_seq, 4);
    memcpy(meta + 5, &net_len, 4);
    memcpy(meta + HEADER_SIZE, CRUZID, CRUZID_LEN);
    memcpy(meta + HEADER_SIZE + CRUZID_LEN, args->rel_path, strlen(args->rel_path));
    int pkt_len = HEADER_SIZE + CRUZID_LEN + strlen(args->rel_path);
    meta[pkt_len] = checksum((unsigned char *)meta, pkt_len);
    pkt_len++;
    sendto(sockfd, meta, pkt_len, 0, (struct sockaddr *)&servaddr, addrlen);

    char window[args->winsz][MAX_PACKET_SIZE];
    int lens[args->winsz], retries[args->winsz];
    time_t timers[args->winsz];

    int base = 1, nextsn = 1, finished = 0;
    time_t start_time = time(NULL);

    while (!finished) {
        while (nextsn < base + args->winsz) {
            int idx = nextsn % args->winsz;
            size_t data_len = fread(window[idx] + HEADER_SIZE + CRUZID_LEN, 1,
                args->mss - HEADER_SIZE - CRUZID_LEN - 1, fp);
            if (data_len == 0 && feof(fp)) break;

            window[idx][0] = TYPE_DATA;
            int net_seq = htonl(nextsn);
            int net_len = htonl(data_len);
            memcpy(window[idx] + 1, &net_seq, 4);
            memcpy(window[idx] + 5, &net_len, 4);
            memcpy(window[idx] + HEADER_SIZE, CRUZID, CRUZID_LEN);
            int full_len = HEADER_SIZE + CRUZID_LEN + data_len;
            window[idx][full_len] = checksum((unsigned char*)window[idx], full_len);
            full_len++;

            sendto(sockfd, window[idx], full_len, 0, (struct sockaddr*)&servaddr, addrlen);
            lens[idx] = full_len;
            timers[idx] = time(NULL);
            retries[idx] = 0;
            printf("%s, %d, %s, %d, DATA, %d, %d, %d, %d\n", rfc3339_time(), args->port, args->ip, args->port, nextsn, base, nextsn, base + args->winsz);
            nextsn++;
        }

        fd_set readfds;
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        if (select(sockfd + 1, &readfds, NULL, NULL, &tv) > 0 && FD_ISSET(sockfd, &readfds)) {
            char ackbuf[64];
            recvfrom(sockfd, ackbuf, sizeof(ackbuf), 0, NULL, NULL);
            int ack;
            memcpy(&ack, ackbuf + 1, 4);
            ack = ntohl(ack);
            if (ack >= base) base = ack + 1;
            printf("%s, %d, %s, %d, ACK, %d, %d, %d, %d\n", rfc3339_time(), args->port, args->ip, args->port, ack, base, nextsn, base + args->winsz);
        }

        for (int i = base; i < nextsn; ++i) {
            int idx = i % args->winsz;
            if (difftime(time(NULL), timers[idx]) >= TIMEOUT_SEC) {
                if (++retries[idx] > MAX_RETRIES) {
                    fprintf(stderr, "Reached max re-transmission limit IP %s\n", args->ip);
                    exit(4);
                }
                sendto(sockfd, window[idx], lens[idx], 0, (struct sockaddr*)&servaddr, addrlen);
                timers[idx] = time(NULL);
                fprintf(stderr, "Packet loss detected\n");
                printf("%s, %d, %s, %d, RETRANSMIT, %d, %d, %d, %d\n", rfc3339_time(), args->port, args->ip, args->port, i, base, nextsn, base + args->winsz);
            }
        }

        if (feof(fp) && base == nextsn) finished = 1;
        if (difftime(time(NULL), start_time) > DEADLINE_SEC) {
            fprintf(stderr, "Cannot detect server IP %s port %d\n", args->ip, args->port);
            exit(3);
        }
    }

    fclose(fp);
    close(sockfd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <servn> <servaddr.conf> <mss> <winsz> <infile> <outfile>\n", argv[0]);
        return 1;
    }

    int servn = atoi(argv[1]);
    if (servn <= 0 || servn > MAX_SERVERS) {
        fprintf(stderr, "Invalid server count (max %d)\n", MAX_SERVERS);
        return 1;
    }

    char *conf_file = argv[2];
    int mss = atoi(argv[3]);
    int winsz = atoi(argv[4]);
    char *infile = argv[5];
    char *outfile = argv[6];

    int min_mss = HEADER_SIZE + CRUZID_LEN + 1;
    if (mss < min_mss) {
        fprintf(stderr, "Required minimum MSS is %d\n", min_mss);
        return 1;
    }

    struct thread_args args[MAX_SERVERS];
    pthread_t threads[MAX_SERVERS];

    FILE *f = fopen(conf_file, "r");
    if (!f) {
        perror("fopen conf");
        return 1;
    }

    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && count < servn) {
        if (line[0] == '#' || strlen(line) < 3) continue;
        sscanf(line, "%s %d", args[count].ip, &args[count].port);
        count++;
    }
    fclose(f);

    if (count != servn) {
        fprintf(stderr, "Expected %d servers, found %d\n", servn, count);
        return 1;
    }

    for (int i = 0; i < servn; ++i) {
        strncpy(args[i].file_path, infile, sizeof(args[i].file_path));
        strncpy(args[i].rel_path, outfile, sizeof(args[i].rel_path));
        args[i].mss = mss;
        args[i].winsz = winsz;
        pthread_create(&threads[i], NULL, send_file_thread, &args[i]);
    }

    for (int i = 0; i < servn; ++i)
        pthread_join(threads[i], NULL);

    return 0;
}
