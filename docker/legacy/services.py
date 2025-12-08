#!/usr/bin/env python3
"""
Simple implementations of legacy UDP services for testing
"""
import socket
import sys
import time
import random
import string
from datetime import datetime

def echo_service(data):
    """Echo service - returns what it receives"""
    return data

def discard_service(data):
    """Discard service - returns nothing"""
    return b""

def daytime_service(data):
    """Daytime service - returns current date and time"""
    return datetime.now().strftime("%A, %B %d, %Y %H:%M:%S").encode()

def qotd_service(data):
    """Quote of the Day service"""
    quotes = [
        "Testing is the process of comparing the invisible to the ambiguous to avoid the unthinkable.",
        "There are only two hard things in Computer Science: cache invalidation and naming things.",
        "It works on my machine.",
        "Have you tried turning it off and on again?",
        "640K ought to be enough for anybody.",
    ]
    return random.choice(quotes).encode()

def chargen_service(data):
    """Character Generator - returns random ASCII characters"""
    chars = string.ascii_letters + string.digits + string.punctuation + ' \n'
    return ''.join(random.choice(chars) for _ in range(512)).encode()

def time_service(data):
    """Time service - returns seconds since 1900-01-01"""
    # Time protocol uses seconds since 1900-01-01 00:00:00
    epoch_1900 = 2208988800  # Seconds between 1900 and 1970
    current_time = int(time.time()) + epoch_1900
    return current_time.to_bytes(4, byteorder='big')

def main():
    if len(sys.argv) != 2:
        print("Usage: services.py <service_name>")
        sys.exit(1)

    service_name = sys.argv[1]

    services = {
        'echo': (echo_service, 7),
        'discard': (discard_service, 9),
        'daytime': (daytime_service, 13),
        'qotd': (qotd_service, 17),
        'chargen': (chargen_service, 19),
        'time': (time_service, 37),
    }

    if service_name not in services:
        print(f"Unknown service: {service_name}")
        sys.exit(1)

    handler, default_port = services[service_name]
    port = default_port

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))

    print(f"Starting {service_name} service on UDP port {port}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            response = handler(data)
            if response:
                sock.sendto(response, addr)
        except Exception as e:
            print(f"Error in {service_name}: {e}")

if __name__ == "__main__":
    main()