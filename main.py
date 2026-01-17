import random
import socket
import struct
from dataclasses import dataclass
from enum import Enum

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

@dataclass
class DnsHeader():
    packet_id: int
    flags: int
    qcount: int
    acount: int
    authcount: int
    addcount: int
    opcode: int
    rcode: int

@dataclass
class DnsQuestion():
    domain_name: str
    record_type: int
    record_class: int

@dataclass
class DnsRecord():
    domain_name: str
    record_type: int
    record_class: int
    ttl: int 
    ip_address: str # only applicable for A records

class ResultCode(Enum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5

    def __str__(self):
        return self.name
            
class RecordType(Enum):
    A = 1
    CNAME = 5

    def __str__(self):
        return self.name




class DnsPacket():
    def __init__(self, buffer):
        if len(buffer) > 512:
            raise Exception(f"Invalid length for DNS packet: {len(buffer)}")
        self.buffer = buffer
        self.pos = 12 # start at the tip of the dns header

        # parse DNS header
        packet_id, flags, qcount, acount, authcount, addcount = struct.unpack("!HHHHHH", self.buffer[:self.pos])
        # grab the info I care about from the flags
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        self.header = DnsHeader(packet_id, flags, qcount, acount, authcount, addcount, opcode, rcode)

        # parse DNS question
        self.questions = []
        for _ in range(qcount):
            domain_name, self.pos = self.extract_domain_name(self.pos)

            record_type, record_class = struct.unpack("!HH", self.buffer[self.pos: self.pos + 4])
            self.pos += 4

            self.questions.append(DnsQuestion(domain_name, record_type, record_class))

        # parse DNS answer
        self.answers = []
        for _ in range(acount):
            domain_name, self.pos = self.extract_domain_name(self.pos)
            record_type, record_class = struct.unpack("!HH", self.buffer[self.pos: self.pos + 4])
            self.pos +=4 

            ttl, = struct.unpack("!I", self.buffer[self.pos:self.pos + 4])
            self.pos += 4

            record_length, = struct.unpack("!H", self.buffer[self.pos:self.pos+2])
            self.pos += 2

            ip_bytes = self.buffer[self.pos:self.pos + record_length]
            self.pos += record_length

            ip_address = ".".join(str(b) for b in ip_bytes)
            self.answers.append(DnsRecord(domain_name, record_type, record_class, ttl, ip_address))

    def extract_domain_name(self, pos):
        words = []
        jumped = False
        original_pos = pos
        
        while True:
            length = self.buffer[pos]
            
            # Check if this is a compression pointer (top 2 bits set)
            if length & 0xC0 == 0xC0:
                # Calculate offset from the two bytes
                offset = ((length & 0x3F) << 8) | self.buffer[pos + 1]
                if not jumped:
                    original_pos = pos + 2  # Save where to continue after
                pos = offset
                jumped = True
                continue
            
            if length == 0:
                break
                
            pos += 1
            word = self.buffer[pos:pos + length].decode()
            words.append(word)
            pos += length
        
        # Return position after the name (or after the pointer if we jumped)
        end_pos = original_pos if jumped else pos + 1
        return ".".join(words), end_pos

    def __repr__(self):

        for q, a in zip(self.questions, self.answers):
            print(f"; <<>> AyDiG 1.0.0 <<>> {q.domain_name}")
            print(";; Got answer:")
            print(f";; ->>HEADER<<- opcode: {self.header.opcode}, status: {ResultCode(self.header.rcode)}, id: {self.header.packet_id}")
            print(f";; flags: qr rd ra; QUERY: {self.header.qcount}, ANSWER: {self.header.acount}, AUTHORITY: {self.header.authcount}, ADDITIONAL: {self.header.addcount}")
            print()
            print(";; QUESTION SECTION:")
            print(f";{q.domain_name}.\t\t\tIN\t{RecordType(q.record_type)}")
            print()
            print(";; ANSWER SECTION:")
            print(f"{a.domain_name}.\t\t{a.ttl}\tIN\t{RecordType(a.record_type)}\t{a.ip_address}")
            return ""




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


if __name__ == "__main__":

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

        
        dns_packet = build_dns_packet("asap-static.site")
        sock.sendto(dns_packet, ("8.8.8.8", 53))
        response = sock.recv(512)
        packet = DnsPacket(response)
        print(packet)