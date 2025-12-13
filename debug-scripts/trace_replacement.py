#!/usr/bin/env python3
"""
Trace what our code should be replacing.
"""

import struct
import sys

def main():
    # Read /bin/ls ELF header
    with open("/bin/ls", "rb") as f:
        # ELF header
        e_ident = f.read(16)
        assert e_ident[:4] == b'\x7fELF', "Not an ELF file"
        is_64bit = e_ident[4] == 2
        is_le = e_ident[5] == 1

        fmt = '<' if is_le else '>'

        if is_64bit:
            ehdr = struct.unpack(fmt + 'HHIQQQIHHHHHH', f.read(48))
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = ehdr
        else:
            raise Exception("32-bit not supported")

        print(f"ELF Header:")
        print(f"  e_phoff: 0x{e_phoff:x}")
        print(f"  e_phnum: {e_phnum}")
        print(f"  e_shoff: 0x{e_shoff:x}")
        print(f"  e_shnum: {e_shnum}")
        print(f"  e_shentsize: {e_shentsize}")

        # Calculate PHT size like our code
        ehdr_size = 64
        phdr_entry_size = 56
        num_notes = 0

        # Read section headers to count notes
        f.seek(e_shoff)
        for i in range(e_shnum):
            shdr = struct.unpack(fmt + 'IIQQQQIIQQ', f.read(e_shentsize))
            sh_type = shdr[1]
            if sh_type == 7:  # SHT_NOTE
                num_notes += 1

        print(f"\nNumber of NOTE sections: {num_notes}")

        pht_size = ehdr_size + (e_phnum + num_notes + 1) * phdr_entry_size
        # Round up to 8-byte alignment
        pht_size = (pht_size + 7) & ~7
        print(f"Calculated PHT size: 0x{pht_size:x} ({pht_size})")

        # Read section header string table
        f.seek(e_shoff + e_shstrndx * e_shentsize)
        shstrtab_hdr = struct.unpack(fmt + 'IIQQQQIIQQ', f.read(e_shentsize))
        shstrtab_off = shstrtab_hdr[4]
        shstrtab_size = shstrtab_hdr[5]

        f.seek(shstrtab_off)
        shstrtab = f.read(shstrtab_size)

        def get_name(offset):
            end = shstrtab.find(b'\x00', offset)
            return shstrtab[offset:end].decode('utf-8')

        # Now analyze which sections would be replaced
        print(f"\nSections to replace (offset <= 0x{pht_size:x}):")
        f.seek(e_shoff)
        replaceable_sections = []
        for i in range(e_shnum):
            shdr = struct.unpack(fmt + 'IIQQQQIIQQ', f.read(e_shentsize))
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = shdr[:6]
            name = get_name(sh_name)

            if i == 0:  # Skip NULL section
                continue

            SHT_PROGBITS = 1
            SHT_NOBITS = 8

            can_replace = True
            reason = ""
            if sh_type == SHT_PROGBITS and name != ".interp":
                can_replace = False
                reason = "PROGBITS (not .interp)"
            elif sh_type == SHT_NOBITS:
                can_replace = False
                reason = "NOBITS"

            in_way = sh_offset <= pht_size

            if in_way:
                status = "REPLACE" if can_replace else f"SKIP ({reason})"
                print(f"  [{i:2}] {name:<25} offset=0x{sh_offset:08x} type={sh_type:2} -> {status}")
                if can_replace:
                    replaceable_sections.append(name)

        print(f"\nTotal sections to replace: {len(replaceable_sections)}")
        for name in replaceable_sections:
            print(f"  - {name}")

if __name__ == "__main__":
    main()
