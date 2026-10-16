"""Create tiny PE-like header fixtures for static disassembly tests (not Windows-executable apps)."""
from pathlib import Path
import struct

def make_samples(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for is64 in (False, True):
        b = bytearray(0x400)
        b[0:2] = b'MZ'
        struct.pack_into('<I', b, 0x3c, 0x80)
        b[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<HHIIIHH', b, 0x84,
                         0x8664 if is64 else 0x14c, 1, 0, 0, 0,
                         0xF0 if is64 else 0xE0, 0x102)
        opt = 0x98
        struct.pack_into('<H', b, opt, 0x20b if is64 else 0x10b)
        struct.pack_into('<I', b, opt+16, 0x1000)
        if is64:
            struct.pack_into('<Q', b, opt+24, 0x140000000)
        else:
            struct.pack_into('<I', b, opt+28, 0x400000)
        sec = opt + (0xF0 if is64 else 0xE0)
        b[sec:sec+8] = b'.text\0\0\0'
        struct.pack_into('<IIII', b, sec+8, 0x100, 0x1000, 0x200, 0x200)
        struct.pack_into('<I', b, sec+36, 0x60000020)
        code = bytes.fromhex('B8 02 00 00 00 83 C0 03 C3') # mov eax,2; add eax,3; ret
        b[0x200:0x200+len(code)] = code
        file = output / ('sample64.exe' if is64 else 'sample32.exe')
        file.write_bytes(b)
        print(file)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    make_samples(parser.parse_args().output)
