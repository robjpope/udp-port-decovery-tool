#!/usr/bin/env python3
import socket
import time as time_module
import struct

def time_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 37))
    print("Time server listening on UDP port 37")

    # Time protocol uses seconds since 1900-01-01
    epoch_1900 = 2208988800

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            current_time = int(time_module.time()) + epoch_1900
            response = struct.pack("!I", current_time)
            sock.sendto(response, addr)
            print(f"Sent time to {addr}: {current_time}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    time_server()