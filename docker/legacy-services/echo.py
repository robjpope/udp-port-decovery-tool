#!/usr/bin/env python3
import socket

def echo_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 7))
    print("Echo server listening on UDP port 7")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            # Echo the data back exactly
            sock.sendto(data, addr)
            print(f"Echoed {len(data)} bytes to {addr}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    echo_server()