#!/usr/bin/env python3
"""
Debug script to check what sections patchelf moves.
"""

import subprocess
import shutil
import tempfile
from pathlib import Path

def run_cmd(cmd):
    """Run command and return stdout"""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def parse_sections(output):
    """Parse section headers from readelf -S output"""
    sections = []
    lines = output.strip().split('\n')
    for i, line in enumerate(lines):
        if line.strip().startswith('['):
            # Parse section info
            # Format: [Nr] Name Type Address Offset Size ...
            parts = line.split()
            if len(parts) >= 6:
                try:
                    nr = parts[0].strip('[]')
                    name = parts[1]
                    sec_type = parts[2]
                    addr = parts[3]
                    offset = parts[4] if len(parts[4]) > 4 else parts[5]  # Handle multi-line
                    sections.append({
                        'nr': nr,
                        'name': name,
                        'type': sec_type,
                        'offset': offset
                    })
                except (ValueError, IndexError):
                    continue
    return sections

def main():
    tmpdir = Path(tempfile.mkdtemp(prefix="debug_sections_"))
    print(f"Working directory: {tmpdir}")

    binary = "/bin/ls"
    patchelf_out = tmpdir / "patchelf_out"

    shutil.copy(binary, patchelf_out)
    subprocess.run(["patchelf", "--set-interpreter", "/short", str(patchelf_out)])

    print("=== Section offset comparison ===")
    print(f"{'Section':<25} {'Original':<12} {'Patchelf':<12} {'Changed?'}")
    print("-" * 60)

    orig_sections = run_cmd(["readelf", "-SW", binary])
    new_sections = run_cmd(["readelf", "-SW", str(patchelf_out)])

    # Parse sections - simple approach: look for offsets
    orig_lines = orig_sections.split('\n')
    new_lines = new_sections.split('\n')

    for i, (orig, new) in enumerate(zip(orig_lines[4:20], new_lines[4:20])):
        if orig.strip() and new.strip():
            # Extract name and offset from each line
            orig_parts = orig.split()
            new_parts = new.split()
            if len(orig_parts) > 4 and len(new_parts) > 4:
                name = orig_parts[1] if orig_parts[0].startswith('[') else orig_parts[0]
                # Find the hex offset
                for p in orig_parts:
                    if len(p) == 8 and p.isalnum() and p[0] != '0':
                        continue
                    if len(p) >= 6 and all(c in '0123456789abcdef' for c in p):
                        orig_off = p
                        break
                else:
                    orig_off = "?"
                for p in new_parts:
                    if len(p) >= 6 and all(c in '0123456789abcdef' for c in p):
                        new_off = p
                        break
                else:
                    new_off = "?"
                changed = "YES" if orig_off != new_off else ""
                print(f"{name:<25} 0x{orig_off:<10} 0x{new_off:<10} {changed}")

    print("\n=== Full patchelf section headers ===")
    print(run_cmd(["readelf", "-SW", str(patchelf_out)]))

if __name__ == "__main__":
    main()
