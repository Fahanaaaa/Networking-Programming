#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HEADER_SIZE 9  // 1B type + 4B seq + 4B length
#define MAX_RETRIES 5
#define TIMEOUT_SEC 2
#define TYPE_DATA 0x1
#define TYPE_META 0x2

const char* CRUZID = "faslam:";

// Same as before
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


// Server responses
void log_event(const char* event, int seq, int base, int nextsn, int window_end) {
    char timebuf[64];
    struct timespec ts;
    struct tm *tm_info;

    clock_gettime(CLOCK_REALTIME, &ts);
    time_t sec = ts.tv_sec;
    tm_info = gmtime(&sec);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", tm_info);

    printf("%s.%03ldZ, %s, %d, %d, %d, %d\n",
           timebuf,
           ts.tv_nsec / 1000000,
           event,
           seq,
           base,
           nextsn,
           window_end);
    fflush(stdout);
}

int make_packet(unsigned char *packet, int type, int seq, const char *data, int len) {
    int offset = 0;
    packet[offset++] = (unsigned char)type;

    int net_seq = htonl(seq);
    memcpy(packet + offset, &net_seq, 4);
    offset += 4;

    int net_len = htonl(len);
    memcpy(packet + offset, &net_len, 4);
    offset += 4;

    memcpy(packet + offset, CRUZID, strlen(CRUZID));
    offset += strlen(CRUZID);

    memcpy(packet + offset, data, len);
    offset += len;

    packet[offset] = checksum(packet, offset);
    return offset + 1;
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port> <mss> <winsz> <infile> <outfile>\n", argv[0]);
        exit(1);
    }

    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    int mss = atoi(argv[3]);
    int winsz = atoi(argv[4]);
    const char *infile = argv[5];
    const char *outfile = argv[6];

    if (mss <= HEADER_SIZE + (int)strlen(CRUZID)) {
        fprintf(stderr, "MSS must be greater than HEADER_SIZE + CruzID length.\n");
        exit(1);
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    memset(&server_addr, 0, addr_len);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    FILE *fp = fopen(infile, "rb");
    if (!fp) {
        perror("fopen infile");
        exit(1);
    }

    int base = 1, nextsn = 1, retries = 0;
    char data_buf[mss - HEADER_SIZE - strlen(CRUZID)];
    unsigned char window[winsz][1500];
    int lens[winsz];
    int last_packet_sent = 0;
    int finished = 0;

    // Sending meta packetsssss
    unsigned char meta_packet[1500];
    int meta_len = make_packet(meta_packet, TYPE_META, 0, outfile, strlen(outfile));
    sendto(sockfd, meta_packet, meta_len, 0, (struct sockaddr *)&server_addr, addr_len);

    fd_set read_fds;
    struct timeval timeout;

    while (!finished) {
        // GBN send windo
        while (nextsn < base + winsz && !last_packet_sent) {
            int nread = fread(data_buf, 1, sizeof(data_buf), fp);
            if (nread <= 0) {
                last_packet_sent = 1;
                break;
            }
            int plen = make_packet(window[nextsn % winsz], TYPE_DATA, nextsn, data_buf, nread);
            lens[nextsn % winsz] = plen;
            sendto(sockfd, window[nextsn % winsz], plen, 0, (struct sockaddr *)&server_addr, addr_len);
            log_event("DATA", nextsn, base, nextsn + 1, base + winsz);
            nextsn++;
        }

        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = 0;

        int rv = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

        if (rv == 0) { // Timeout
            retries++;
            if (retries >= MAX_RETRIES) {
                fprintf(stderr, "Max retries reached. Exiting.\n");
                exit(1);
            }
            for (int i = base; i < nextsn; ++i) {
                sendto(sockfd, window[i % winsz], lens[i % winsz], 0, (struct sockaddr *)&server_addr, addr_len);
                log_event("DATA", i, base, nextsn, base + winsz);
            }
        } else if (FD_ISSET(sockfd, &read_fds)) {
            unsigned char ack_buf[1500];
            int rlen = recvfrom(sockfd, ack_buf, sizeof(ack_buf), 0, (struct sockaddr *)&server_addr, &addr_len);
            if (rlen >= 5) {
                int ack_seq;
                memcpy(&ack_seq, ack_buf + 1, 4);
                ack_seq = ntohl(ack_seq);
                log_event("ACK", ack_seq, base, nextsn, base + winsz);
                if (ack_seq >= base) {
                    base = ack_seq + 1;
                    retries = 0;
                    if (last_packet_sent && base == nextsn) {
                        finished = 1;
                    }
                }
            }
        }
    }

    fclose(fp);
    close(sockfd);
    return 0;
}


