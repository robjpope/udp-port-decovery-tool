#!/usr/bin/env python3
"""
Simple IKE responder for testing UDP discovery
Simulates a basic IKEv1 responder on port 500
"""

import socket
import struct
import sys

def parse_ike_header(data):
    """Parse basic IKE header"""
    if len(data) < 28:
        return None

    initiator_cookie = data[0:8]
    responder_cookie = data[8:16]
    next_payload = data[16]
    version = data[17]
    exchange_type = data[18]
    flags = data[19]
    message_id = data[20:24]
    length = struct.unpack('>I', data[24:28])[0]

    return {
        'initiator_cookie': initiator_cookie,
        'responder_cookie': responder_cookie,
        'next_payload': next_payload,
        'version': version,
        'exchange_type': exchange_type,
        'flags': flags,
        'message_id': message_id,
        'length': length
    }

def create_ike_response(request_header):
    """Create a basic IKE Main Mode response"""
    # Use the initiator's cookie and generate a responder cookie
    initiator_cookie = request_header['initiator_cookie']
    responder_cookie = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'  # Fixed responder cookie

    # IKE Header for response
    next_payload = 0x01  # SA
    version = request_header['version']  # Echo back same version
    exchange_type = request_header['exchange_type']  # Same exchange type
    flags = 0x00  # No flags
    message_id = request_header['message_id']  # Echo message ID

    # Simple SA payload
    sa_next = 0x0d  # Vendor ID
    sa_reserved = 0x00
    sa_length = struct.pack('>H', 52)

    # DOI and Situation
    doi = b'\x00\x00\x00\x01'  # IPSec DOI
    situation = b'\x00\x00\x00\x01'  # SIT_IDENTITY_ONLY

    # Proposal
    proposal_next = 0x00
    proposal_reserved = 0x00
    proposal_length = struct.pack('>H', 40)
    proposal_num = 0x01
    protocol_id = 0x01  # ISAKMP
    spi_size = 0x00
    num_transforms = 0x01

    # Transform
    transform_next = 0x00
    transform_reserved = 0x00
    transform_length = struct.pack('>H', 28)
    transform_num = 0x01
    transform_id = 0x01
    transform_reserved2 = b'\x00\x00'

    # Basic attributes
    attrs = (
        b'\x80\x01\x00\x05' +  # Encryption: 3DES
        b'\x80\x02\x00\x02' +  # Hash: SHA1
        b'\x80\x03\x00\x01' +  # Auth: PSK
        b'\x80\x04\x00\x02' +  # DH Group: 2
        b'\x80\x0b\x00\x01' +  # Life Type: Seconds
        b'\x00\x0c\x00\x04\x00\x00\x70\x80'  # Life Duration
    )

    # Build SA payload
    sa_payload = (
        struct.pack('BB', sa_next, sa_reserved) + sa_length +
        doi + situation +
        struct.pack('BB', proposal_next, proposal_reserved) + proposal_length +
        struct.pack('BBBB', proposal_num, protocol_id, spi_size, num_transforms) +
        struct.pack('BB', transform_next, transform_reserved) + transform_length +
        struct.pack('BB', transform_num, transform_id) + transform_reserved2 +
        attrs
    )

    # Vendor ID payloads
    # strongSwan vendor ID
    vendor1_next = 0x0d  # Another vendor ID
    vendor1_reserved = 0x00
    vendor1_data = b'strongSwan 5.9.8'
    vendor1_length = struct.pack('>H', 4 + len(vendor1_data))
    vendor1_payload = (
        struct.pack('BB', vendor1_next, vendor1_reserved) +
        vendor1_length + vendor1_data
    )

    # Generic VPN vendor ID
    vendor2_next = 0x00  # No more payloads
    vendor2_reserved = 0x00
    vendor2_data = b'Test VPN Server'
    vendor2_length = struct.pack('>H', 4 + len(vendor2_data))
    vendor2_payload = (
        struct.pack('BB', vendor2_next, vendor2_reserved) +
        vendor2_length + vendor2_data
    )

    # Calculate total length
    total_length = 28 + len(sa_payload) + len(vendor1_payload) + len(vendor2_payload)

    # Build IKE header
    ike_header = (
        initiator_cookie +
        responder_cookie +
        struct.pack('BBBB', next_payload, version, exchange_type, flags) +
        message_id +
        struct.pack('>I', total_length)
    )

    return ike_header + sa_payload + vendor1_payload + vendor2_payload

def main():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to port 500
    sock.bind(('0.0.0.0', 500))
    print(f"IKE test server listening on port 500", flush=True)

    while True:
        try:
            # Receive data
            data, addr = sock.recvfrom(4096)
            print(f"Received {len(data)} bytes from {addr}", flush=True)

            # Parse IKE header
            header = parse_ike_header(data)
            if header:
                print(f"  IKE version: {(header['version'] >> 4) & 0x0F}", flush=True)
                print(f"  Exchange type: {header['exchange_type']}", flush=True)

                # Create and send response
                response = create_ike_response(header)
                sock.sendto(response, addr)
                print(f"  Sent {len(response)} byte response", flush=True)
            else:
                print("  Invalid IKE packet", flush=True)

        except KeyboardInterrupt:
            print("\nShutting down...")
            break
        except Exception as e:
            print(f"Error: {e}", flush=True)

    sock.close()

if __name__ == "__main__":
    main()