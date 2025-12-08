#!/usr/bin/env python3
import socket
import datetime

def daytime_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 13))
    print("Daytime server listening on UDP port 13")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            now = datetime.datetime.now()
            response = now.strftime("%A, %B %d, %Y %H:%M:%S")
            sock.sendto(response.encode("ascii"), addr)
            print(f"Sent daytime to {addr}: {response}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    daytime_server()