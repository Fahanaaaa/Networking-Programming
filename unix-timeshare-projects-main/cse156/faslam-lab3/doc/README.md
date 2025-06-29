# UDP File Transfer ROUND 2: Using Go-Back-N Protocol and Reliability

## General overview
This project is a UDP-based file transfer system that implements reliable transport using the Go-Back-N protocol. The client will send data in numbered packets using a sliding window. The server then receives and acknowledges the packets. It also writes valid data to a file. The client handles retransmissions when ACKs are not received.


The system supports:
- MSS length checks
- Server timeout detection
- Packet loss detection using checksum
- Direct file writing
- Unique CruzID fingerprint
- Sliding window control with adjustable window size
- Packet retransmission
- Filename transmission
- Custom packet format (type, seq, length, fingerprint, data, checksum)
- Logging in RFC 3339 CSV format

## Build Instructions
To compile:
```bash
make
```
To clean:
```bash
make clean
```
