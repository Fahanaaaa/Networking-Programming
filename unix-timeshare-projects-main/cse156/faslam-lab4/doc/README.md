# UDP File Transfer: Reliable Client-Multi-Server Communication

## General overview
This project implements a reliable UDP file transfer system using a sliding window protocol (Go-Back-N)for the support replication of a file to multiple servers concurrently. It builds on top of Lab 3 by introducing redundancy, concurrency, retransmissions, and robust error handling.



##Key Feautures
- RFC3339-compliant logging of `DATA` and `ACK` packets
- Sliding window transport using `winsz` configurable window size
- Client-to-multiple-server transfer using threads
- Server-enforced file locks: one client may write to a file at a time
- MSS validation and path-based file reconstruction
- Timeout and retransmission handling with retry limits
- Independent per-packet and per-direction packet drop simulation on server
- Graceful exit with proper error codes and log messages

The system supports:
- MSS length checks
- Server timeout detection
- Packet loss detection using checksum
- Direct file writing
- Server packet drops
- Client side retransmissions
- Unique CruzID fingerprint

## Build Instructions
To compile:
```bash
make
```
To clean:
```bash
make clean
```
