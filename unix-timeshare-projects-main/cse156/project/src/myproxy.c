   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include <unistd.h>
   #include <errno.h>
   #include <fcntl.h>
   #include <netdb.h>
   #include <pthread.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <sys/socket.h>
   #include <sys/types.h>
   #include <time.h>
   #include <openssl/ssl.h>
   #include <openssl/err.h>
   
   #define MAX_REQ 8192
   #define MAX_HOST 256
   #define MAX_LOG_LINE 2048
   #define MAX_FORBIDDEN 1000
   
   char *forbidden_sites[MAX_FORBIDDEN];
   int forbidden_count = 0;
   FILE *log_file;
   pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
   
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
   
   int is_forbidden(const char *host) {
       for (int i = 0; i < forbidden_count; i++) {
           if (strstr(host, forbidden_sites[i])) return 1;
       }
       return 0;
   }
   
   void load_forbidden(const char *path) {
       FILE *f = fopen(path, "r");
       if (!f) { perror("forbidden file"); exit(1); }
       char line[MAX_HOST];
       while (fgets(line, sizeof(line), f) && forbidden_count < MAX_FORBIDDEN) {
           if (line[0] == '#' || strlen(line) < 2) continue;
           line[strcspn(line, "\r\n")] = 0;
           forbidden_sites[forbidden_count++] = strdup(line);
       }
       fclose(f);
   }
   
   void write_log(const char *client_ip, const char *request_line, int status, size_t resp_size) {
       pthread_mutex_lock(&log_mutex);
       char req_line[2048];
       const char *end = strstr(request_line, "\r\n");
       if (!end) end = request_line + strlen(request_line);
       size_t len = end - request_line;
       if (len >= sizeof(req_line)) len = sizeof(req_line) - 1;
       strncpy(req_line, request_line, len);
       req_line[len] = '\0';
       fprintf(log_file, "%s %s \"%s\" %d %zu\n", rfc3339_time(), client_ip, req_line, status, resp_size);
       fflush(log_file);
       pthread_mutex_unlock(&log_mutex);
   }
   
   void send_http_error(int client_fd, int status, const char *desc, const char *client_ip, const char *req_line) {
       char buf[512];
       int len = snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, desc);
       send(client_fd, buf, len, 0);
       write_log(client_ip, req_line, status, len);
   }
   
   void *handle_client(void *arg) {
       int client_fd = *(int *)arg;
       free(arg);
   
       char buffer[MAX_REQ];
       struct sockaddr_in addr;
       socklen_t len = sizeof(addr);
       getpeername(client_fd, (struct sockaddr *)&addr, &len);
       char client_ip[INET_ADDRSTRLEN];
       inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
   
       int bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
       if (bytes <= 0) { close(client_fd); return NULL; }
       buffer[bytes] = 0;
   
       char method[16], url[2048], version[32];
       sscanf(buffer, "%15s %2047s %31s", method, url, version);
   
       if (strcmp(method, "GET") && strcmp(method, "HEAD")) {
           send_http_error(client_fd, 501, "Not Implemented", client_ip, buffer);
           close(client_fd);
           return NULL;
       }
   
       if (strncmp(url, "http://", 7) != 0) {
           send_http_error(client_fd, 400, "Bad Request", client_ip, buffer);
           close(client_fd);
           return NULL;
       }
   
       char *host_start = url + 7;
       char *path = strchr(host_start, '/');
       if (!path) path = "";
       else *path = '\0';
   
       char hostname[1024];
       int port = 443;
       char *colon = strchr(host_start, ':');
       if (colon) {
           *colon = '\0';
           port = atoi(colon + 1);
       }
       strncpy(hostname, host_start, sizeof(hostname) - 1);
       hostname[sizeof(hostname) - 1] = '\0';
   
       if (is_forbidden(hostname)) {
           send_http_error(client_fd, 403, "Forbidden", client_ip, buffer);
           close(client_fd);
           return NULL;
       }
   
       struct hostent *he = gethostbyname(hostname);
       if (!he) {
           send_http_error(client_fd, 502, "Bad Gateway", client_ip, buffer);
           close(client_fd);
           return NULL;
       }
   
       int server_fd = socket(AF_INET, SOCK_STREAM, 0);
       fcntl(server_fd, F_SETFL, O_NONBLOCK);
       struct sockaddr_in serv_addr = {0};
       serv_addr.sin_family = AF_INET;
       serv_addr.sin_port = htons(port);
       memcpy(&serv_addr.sin_addr, he->h_addr, he->h_length);
   
       int conn_res = connect(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
       if (conn_res < 0 && errno != EINPROGRESS) {
           send_http_error(client_fd, 504, "Gateway Timeout", client_ip, buffer);
           close(server_fd);
           close(client_fd);
           return NULL;
       }
   
       fd_set wfds;
       struct timeval tv;
       FD_ZERO(&wfds);
       FD_SET(server_fd, &wfds);
       tv.tv_sec = 5;
       tv.tv_usec = 0;
   
       int sel_res = select(server_fd + 1, NULL, &wfds, NULL, &tv);
       if (sel_res <= 0) {
           send_http_error(client_fd, 504, "Gateway Timeout", client_ip, buffer);
           close(server_fd);
           close(client_fd);
           return NULL;
       }
   
       int so_error = 0;
       socklen_t len_opt = sizeof(so_error);
       getsockopt(server_fd, SOL_SOCKET, SO_ERROR, &so_error, &len_opt);
       if (so_error != 0) {
           send_http_error(client_fd, 504, "Gateway Timeout", client_ip, buffer);
           close(server_fd);
           close(client_fd);
           return NULL;
       }
   
       fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) & ~O_NONBLOCK);
   
       SSL_library_init();
       SSL_load_error_strings();
       SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
       SSL *ssl = SSL_new(ctx);
       SSL_set_fd(ssl, server_fd);
       if (SSL_connect(ssl) != 1) {
           send_http_error(client_fd, 502, "Bad Gateway", client_ip, buffer);
           SSL_free(ssl); SSL_CTX_free(ctx); close(server_fd); close(client_fd);
           return NULL;
       }
   
       char modified[MAX_REQ];
       snprintf(modified, sizeof(modified), "%s %s%s %s\r\n", method, url, path, version);
       char *headers = strstr(buffer, "\r\n");
       if (!headers) {
           send_http_error(client_fd, 400, "Bad Request", client_ip, buffer);
           close(client_fd);
           return NULL;
       }
   
       strncat(modified, headers + 2, sizeof(modified) - strlen(modified) - 1);
       char xff[256];
       snprintf(xff, sizeof(xff), "X-Forwarded-For: %s\r\n", client_ip);
       strncat(modified, xff, sizeof(modified) - strlen(modified) - 1);
   
       SSL_write(ssl, modified, strlen(modified));
   
       char resp[MAX_REQ];
       int total_sent = 0, n;
       while ((n = SSL_read(ssl, resp, sizeof(resp))) > 0) {
           send(client_fd, resp, n, 0);
           total_sent += n;
       }
   
       write_log(client_ip, buffer, 200, total_sent);
   
       SSL_shutdown(ssl);
       SSL_free(ssl);
       SSL_CTX_free(ctx);
       close(server_fd);
       close(client_fd);
       return NULL;
   }
   
   int main(int argc, char *argv[]) {
       if (argc != 7 || strcmp(argv[1], "-p") || strcmp(argv[3], "-a") || strcmp(argv[5], "-l")) {
           fprintf(stderr, "Usage: %s -p <port> -a <forbidden_file> -l <log_file>\n", argv[0]);
           exit(1);
       }
   
       int port = atoi(argv[2]);
       load_forbidden(argv[4]);
       log_file = fopen(argv[6], "a");
       if (!log_file) { perror("log_file"); exit(1); }
   
       int sockfd = socket(AF_INET, SOCK_STREAM, 0);
       int opt = 1;
       setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
   
       struct sockaddr_in addr = {0};
       addr.sin_family = AF_INET;
       addr.sin_port = htons(port);
       addr.sin_addr.s_addr = INADDR_ANY;
   
       if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(sockfd, 50) < 0) {
           perror("bind/listen");
           exit(1);
       }
   
       printf("Server listening on port %d...\n", port);
   
       while (1) {
           int *client_fd = malloc(sizeof(int));
           *client_fd = accept(sockfd, NULL, NULL);
           if (*client_fd < 0) continue;
           pthread_t tid;
           pthread_create(&tid, NULL, handle_client, client_fd);
           pthread_detach(tid);
       }
   
       fclose(log_file);
       return 0;
   }
   
