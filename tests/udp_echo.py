#!/usr/bin/env python3
"""Minimal UDP echo server. Prefixes every reply with b'ECHO:' so the
client can distinguish echoed packets from stray traffic.

Usage:
    udp_echo.py <port>              # legacy form, binds 127.0.0.1
    udp_echo.py <bind_addr> <port>  # family is derived from bind_addr
"""
import socket
import sys

def main():
    if len(sys.argv) >= 3:
        host, port = sys.argv[1], int(sys.argv[2])
    else:
        host = "127.0.0.1"
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 7777

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((host, port))
    while True:
        data, addr = s.recvfrom(65536)
        s.sendto(b"ECHO:" + data, addr)

if __name__ == "__main__":
    main()
