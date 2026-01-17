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
    dns_header = struct.pack("!HHHHHH", 
    packet_id,
    0x0100, # flags: QR, OPCODE, AA, TC, RD, RA, Z, RCODE all packed together
    1, # Question count
    0, # Answer count
    0, # Authority count
    0 # Additional count
    )

    dns_question = encode_domain_name(domain_name) + struct.pack("!HH", 1, 1)

    return dns_header + dns_question


def extract_domain_name(packet, pos):
    words = []
    jumped = False
    original_pos = pos
    
    while True:
        length = packet[pos]
        
        # Check if this is a compression pointer (top 2 bits set)
        if length & 0xC0 == 0xC0:
            # Calculate offset from the two bytes
            offset = ((length & 0x3F) << 8) | packet[pos + 1]
            if not jumped:
                original_pos = pos + 2  # Save where to continue after
            pos = offset
            jumped = True
            continue
        
        if length == 0:
            break
            
        pos += 1
        word = packet[pos:pos + length].decode()
        words.append(word)
        pos += length
    
    # Return position after the name (or after the pointer if we jumped)
    end_pos = original_pos if jumped else pos + 1
    return ".".join(words), end_pos

def parse_dns_packet(dns_packet):

    # parse DNS header
    dns_header = dns_packet[:12]
    packet_id, flags, qcount, acount, authcount, addcount = struct.unpack("!HHHHHH", dns_header)

    # parse DNS question
    domain_name, pos = extract_domain_name(dns_packet, 12)

    record_type, record_class = struct.unpack("!HH", dns_packet[pos: pos + 4])
    pos += 4

    # parse DNS answer
    domain_name, pos = extract_domain_name(dns_packet, pos)
    record_type, record_class = struct.unpack("!HH", dns_packet[pos: pos + 4])
    pos +=4 

    record_ttl, = struct.unpack("!I", dns_packet[pos:pos + 4])
    pos += 4

    record_length, = struct.unpack("!H", dns_packet[pos:pos+2])
    pos += 2

    ip_bytes = dns_packet[pos:pos + record_length]
    ip_address = ".".join(str(b) for b in ip_bytes)
    print(f"Domain {domain_name} has IP address {ip_address}")


if __name__ == "__main__":

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

        
        dns_packet = build_dns_packet("google.com")
        sock.sendto(dns_packet, ("8.8.8.8", 53))
        response = sock.recv(512)
        parse_dns_packet(response)