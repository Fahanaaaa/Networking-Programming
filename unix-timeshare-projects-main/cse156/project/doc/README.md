# Final Project: Proxy Client-to-Server HTTP Communication

## General overview
This project implements a concurrent proxy server that accepts HTTP requests, translates them to HTTPS, forwards them to the destination server, and relays the response back to the HTTP client. It also filters access based on a forbidden list and logs all traffic.

##Key Feautures
- HTTP-to-HTTPS Conversion 
- Access Control Filtering
- Concurrent Client Handling
- Timeout-Driven Connection Handling
- Comprehensive Error Handling
  Returns appropriate HTTP errors:
  - `400 Bad Request` for malformed requests  
  - `501 Not Implemented` for unsupported methods  
  - `502 Bad Gateway` for DNS resolution or SSL issues  
  - `504 Gateway Timeout` for unreachable servers

- RFC3339 Logging
- Header Injection
- Persistent Listener  
- Simple CLI Startup

## Build Instructions
To compile:
```bash
make
```
To clean:
```bash
make clean
```
