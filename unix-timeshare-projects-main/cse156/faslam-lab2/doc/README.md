# UDP File Transfer: Client-Server Communication

## General overview
This project is a UDP-based file transfer system that includes reliable transport using stop-and-wait protocol. The client sends data in packets of a fixed size and waits for an echo response from the server. The server echoes the packets back after validating a checksum. The client then validates responses before writing them to disk.

The system supports:
- MSS length checks
- Server timeout detection
- Packet loss detection using checksum
- Direct file writing
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
