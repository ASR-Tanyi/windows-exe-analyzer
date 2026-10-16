"""Hand-authored native PE fixtures for unwind validation; never execute these files."""
from pathlib import Path
import struct


def make_unwind_pe(path: Path, records=None, nodes=None, code=None, *, bits=64):
    """Return mutable bytes; RVAs and raw file offsets intentionally differ."""
    records = [(0x1010, 0x1030, 0x3000)] if records is None else records
    nodes = {0x3000: bytes([1, 0, 0, 0])} if nodes is None else nodes
    code = {0x1000: b'\xc3', 0x1010: b'\xc3', 0x1020: b'\xc3', 0x1040: b'\xc3'} if code is None else code
    b = bytearray(0x1600)
    b[:2] = b'MZ'; struct.pack_into('<I', b, 0x3c, 0x80); b[0x80:0x84] = b'PE\0\0'
    opt_size = 0xf0 if bits == 64 else 0xe0
    struct.pack_into('<HHIIIHH', b, 0x84, 0x8664 if bits == 64 else 0x14c, 3, 0, 0, 0, opt_size, 0x102)
    opt = 0x98; section = opt + opt_size
    struct.pack_into('<H', b, opt, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I', b, opt+16, 0x1000)
    struct.pack_into('<Q' if bits == 64 else '<I', b, opt+(24 if bits == 64 else 28),
                     0x140000000 if bits == 64 else 0x400000)
    struct.pack_into('<II', b, opt+32, 4096, 512)
    struct.pack_into('<II', b, opt+56, 0x5000, 0x400)
    struct.pack_into('<I', b, opt+(108 if bits == 64 else 92), 16)
    struct.pack_into('<II', b, opt+(112 if bits == 64 else 96)+24, 0x2000, len(records)*12)
    for i, (name, rva, size, raw, flags) in enumerate([
        (b'.text',0x1000,0x200,0x400,0x60000020),
        (b'.records',0x2000,0x200,0x600,0x40000040),
        (b'.xdata',0x3000,0xe00,0x800,0x40000040),
    ]):
        at=section+i*40; b[at:at+8]=name.ljust(8,b'\0')
        struct.pack_into('<IIII',b,at+8,size,rva,size,raw);struct.pack_into('<I',b,at+36,flags)
    for rva, content in code.items():
        at=0x400+rva-0x1000;b[at:at+len(content)]=content
    for i, record in enumerate(records): struct.pack_into('<III',b,0x600+i*12,*record)
    for rva, content in nodes.items():
        at=0x800+rva-0x3000
        if at<0x800 or at+len(content)>len(b): raise ValueError('Fixture node outside xdata')
        b[at:at+len(content)]=content
    path.write_bytes(b)
    return b


def info(*, flags=0, prolog=0, codes=b'', frame=0, trailer=b'', version=1):
    if len(codes)%2: raise ValueError('Codes must contain whole two-byte slots')
    count=len(codes)//2
    if count>255: raise ValueError('Too many fixture slots')
    return bytes([version|(flags<<3),prolog,count,frame])+codes+(b'\0\0' if count%2 else b'')+trailer
