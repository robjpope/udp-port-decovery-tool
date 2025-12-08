#!/usr/bin/env python3
import socket
import string
import random

def chargen_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 19))
    print("Chargen server listening on UDP port 19")

    # Character set for generation
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            # Generate 512 characters in a cycling pattern
            start = random.randint(0, len(chars) - 1)
            response = ""
            for i in range(512):
                response += chars[(start + i) % len(chars)]
            sock.sendto(response.encode("ascii"), addr)
            print(f"Sent {len(response)} chars to {addr}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    chargen_server()