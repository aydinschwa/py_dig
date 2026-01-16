import random
import socket
import struct



# DNS packets are sent using UDP transport and are limited to 512 bytes

# first: construct DNS header
# ID	Packet Identifier	16 bits	A random identifier is assigned to query packets. Response packets must reply with the same id. This is needed to differentiate responses due to the stateless nature of UDP.
# QR	Query Response	1 bit	0 for queries, 1 for responses.
# OPCODE	Operation Code	4 bits	Typically always 0, see RFC1035 for details.
# AA	Authoritative Answer	1 bit	Set to 1 if the responding server is authoritative - that is, it "owns" - the domain queried.
# TC	Truncated Message	1 bit	Set to 1 if the message length exceeds 512 bytes. Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.
# RD	Recursion Desired	1 bit	Set by the sender of the request if the server should attempt to resolve the query recursively if it does not have an answer readily available.
# RA	Recursion Available	1 bit	Set by the server to indicate whether or not recursive queries are allowed.
# Z	Reserved	3 bits	Originally reserved for later use, but now used for DNSSEC queries.
# RCODE	Response Code	4 bits	Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed, and in the latter case providing details about the cause of the failure.
# QDCOUNT	Question Count	16 bits	The number of entries in the Question Section
# ANCOUNT	Answer Count	16 bits	The number of entries in the Answer Section
# NSCOUNT	Authority Count	16 bits	The number of entries in the Authority Section
# ARCOUNT	Additional Count	16 bits	The number of entries in the Additional Section

def encode_domain_name(domain_name: str) -> bytes:
    encoded_domain_name = b""
    parts = domain_name.split(".") # split on dots
    lengths = [len(part) for part in parts] # get length of part
    for part, length in zip(parts, lengths):
        encoded_domain_name += struct.pack("!B", length) + part.encode() 
    encoded_domain_name += b"\x00"
    return encoded_domain_name

def build_dns_packet(domain_name):
    packet_id = random.randint(0, 65_535)
    print(packet_id)

    dns_header = struct.pack("!HHHHHH", 
    packet_id,
    0x0100, # flags: QR, OPCODE, AA, TC, RD, RA, Z, RCODE all packed together
    1,
    0,
    0,
    0
    )

    dns_question = encode_domain_name(domain_name) + struct.pack("!HH", 1, 1)

    return dns_header + dns_question


if __name__ == "__main__":

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

        
        dns_packet = build_dns_packet("google.com")
        sock.sendto(dns_packet, ("8.8.8.8", 53))
        response = sock.recv(1024)


        dns_header = struct.unpack("!HHHHHH", response[:12])

        print(response)
        print(dns_header)