from dataclasses import dataclass
from enum import Enum
import struct

class BytePacketBuffer:

    # this will give us a fresh buffer holding the packet contents (512 bytes) and a way to index into it
    def __init__(self):
        self.buf = [0] * 512
        self.pos = 0

    # step the buffer position forward a specific number of steps
    def step(self, steps):
        self.pos += steps

    # change buffer position
    def seek(self, pos):
        self.pos = pos

    # read a single byte and move the position one step forward
    def read(self):
        if self.pos > 512:
            raise Exception("End of buffer")

        res = self.buf[self.pos]
        self.pos += 1
        return res

    # get a single byte without changing the buffer position
    def get(self, pos):
        if pos >= 512:
            raise Exception("End of buffer")
        return self.buf[pos]

    # get a range of bytes
    def get_range(self, start, len):
        if start + len >= 512:
            raise Exception("End of buffer")

        byte_range = self.buf[start:start+len]
        return byte_range 

    # read two bytes, stepping two steps forward
    def read_u16(self):
        return self.read() << 8 | self.read()

    # read four bytes, stepping four steps forward
    def read_u32(self):
        return self.read() << 24 | self.read() << 16 | self.read() << 8 | self.read()

    def read_qname(self):

        outstr = ""
        
        # track position locally since we might encounter jumps. This lets us move the pos
        # past the curreny qname while still keeping track of progress on the current qname
        pos = self.pos

        # track whether or not we've jumped
        jumped = False
        max_jumps = 5 
        jumps_performed = 0

        # delimiter which we append for each label. Since we don't want a dot
        # at the beginning of the domain name we leave it empty for now and set
        # it as "." at the end of the first iteration.
        delim = ""
        while True:
            # dns packets can have evil data, e.g. putting a cycle in the jump instrs
            # must guard against this
            if jumps_performed > max_jumps:
                return Exception(f"Limit of {max_jumps} exceeded")

            # at this point we're always at the beginning of a label. Labels always
            # start with a length byte
            length = self.get(pos)

            # if length has MSB set, it represents a jump to some other offset in the packet
            if length & 0xC0 == 0xC0:
                # update the buffer position to a point past the current label
                if not jumped:
                    self.seek(pos + 2)

                # read another byte, calculate offset and perform the jump by updating local pos var
                b2 = self.get(pos + 1)
                offset = ((length ^ 0xC0) << 8 ) | b2
                pos = offset

                # indicate that a jump was performed
                jumped = True
                jumps_performed += 1
                continue

            # base case, where we're reading a single label and appending it to the output
            else:
                # move a single byte forward past the length byte
                pos += 1

                # domain names are terminated by an empty label so if the length is zero we're done
                if length == 0:
                    break

                outstr += delim
                str_buffer = self.get_range(pos, length)
                outstr += str_buffer.decode().lower()

                delim = "."

                # move forward the full length of the label
                pos += length


            if not jumped:
                self.seek(pos)
        
        return outstr



class ResultCode(Enum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5

    def from_num(self, num):
        match num:
            case 1:
                return self.FORMERR
            case 2:
                return self.SERVFAIL
            case 3:
                return self.NXDOMAIN
            case 4:
                return self.NOTIMP 
            case 5:
                return self.REFUSED
            case 0:
                return self.NOERROR
            

@dataclass
class DnsHeader():

    id: int # 16 bits
    recursion_desired: bool # 1 bit
    truncated_message: bool # 1 bit
    authoritative_answer: bool # 1 bit
    opcode: int # 4 bits
    response: bool # 1 bit

    rescode: ResultCode # 4 bits
    checking_disabled: bool
    authed_data: bool
    z: bool
    recursion_available: bool

    questions: int # 16 bits
    answers: int # 16 bits
    authoritative_entries: int # 16 bits
    resource_entries: int # 16 bits


