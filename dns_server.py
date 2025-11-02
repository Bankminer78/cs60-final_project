#!/usr/bin/env python3
"""
Simple DNS Server that responds to queries by decoding the base64 label
contained before the .com suffix and returning it in a TXT record.
"""

import socket
import base64
from scapy.all import DNS, DNSQR, DNSRR

# Configuration
DNS_PORT = 53  # Standard DNS port (requires root privileges)
LISTEN_IP = "0.0.0.0"  # Listen on all interfaces

def parse_dns_query(data):
    """Parse DNS query using scapy."""
    try:
        dns_packet = DNS(data)
        return dns_packet
    except Exception as e:
        print(f"Error parsing DNS packet: {e}")
        return None

def create_dns_response(query_packet):
    """Create a DNS response packet using scapy."""
    try:
        # Extract the query details
        qname = query_packet[DNSQR].qname
        qtype = query_packet[DNSQR].qtype
        qclass = query_packet[DNSQR].qclass

        print(f"Query for: {qname.decode() if isinstance(qname, bytes) else qname}")
        print(f"Query type: {qtype}")

        decoded_payload = decode_base64_label(qname)
        print(f"Decoded payload: {decoded_payload}")

        # Create the response
        response = DNS(
            id=query_packet.id,
            qr=1,  # This is a response
            aa=1,  # Authoritative answer
            rd=query_packet.rd,
            qd=query_packet.qd,  # Copy the query
            an=DNSRR(
                rrname=qname,
                type='TXT',  # Return decoded payload as TXT record
                ttl=300,
                rdata=decoded_payload
            )
        )

        return bytes(response)
    except Exception as e:
        print(f"Error creating DNS response: {e}")
        return None

def decode_base64_label(qname):
    """Decode the leftmost label before .com from the queried domain."""
    if isinstance(qname, bytes):
        qname = qname.decode()

    # Remove trailing dot if present (fully qualified domain)
    qname = qname.rstrip('.')

    # Only consider the part before .com
    if not qname.lower().endswith(".com") or len(qname) < 5:
        return ""

    label = qname[:-4]  # Strip the .com suffix
    label = label.split('.')[-1]  # Take the immediate label before .com

    # Restore padding if it was stripped to make the label DNS-safe
    padding = '=' * (-len(label) % 4)
    try:
        decoded_bytes = base64.b64decode(label + padding, validate=False)
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"Failed to decode base64 label '{label}': {e}")
        return ""

def start_dns_server():
    """Start the DNS server."""
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Allow reuse of address
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to the DNS port
    try:
        sock.bind((LISTEN_IP, DNS_PORT))
        print(f"DNS Server started on {LISTEN_IP}:{DNS_PORT}")
        print("Responding to queries with decoded base64 payloads (TXT records)")
        print("Waiting for DNS queries...")
    except PermissionError:
        print(f"Error: Permission denied. Please run with sudo to bind to port {DNS_PORT}")
        return
    except Exception as e:
        print(f"Error binding to port: {e}")
        return

    # Main server loop
    while True:
        try:
            # Receive DNS query
            data, addr = sock.recvfrom(512)  # DNS packets are typically 512 bytes max
            print(f"\n{'='*50}")
            print(f"Received query from {addr[0]}:{addr[1]}")

            # Parse the query
            query = parse_dns_query(data)
            if query is None:
                continue

            # Create response
            response = create_dns_response(query)
            if response is None:
                continue

            # Send response
            sock.sendto(response, addr)
            print("Sent response with TXT payload")

        except KeyboardInterrupt:
            print("\n\nShutting down DNS server...")
            break
        except Exception as e:
            print(f"Error handling request: {e}")
            continue

    sock.close()
    print("DNS Server stopped.")

if __name__ == "__main__":
    start_dns_server()
