#!/usr/bin/env python3
"""Minimal UDP echo server. Prefixes every reply with b'ECHO:' so the
client can distinguish echoed packets from stray traffic."""
import socket
import sys

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7777
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    while True:
        data, addr = s.recvfrom(65536)
        s.sendto(b"ECHO:" + data, addr)

if __name__ == "__main__":
    main()
