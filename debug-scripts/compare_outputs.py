#!/usr/bin/env python3
"""
Debug script to compare patchelf and goblin outputs in detail.
"""

import subprocess
import shutil
import tempfile
from pathlib import Path

def run_cmd(cmd):
    """Run command and return stdout"""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def main():
    # Setup
    tmpdir = Path(tempfile.mkdtemp(prefix="debug_"))
    print(f"Working directory: {tmpdir}")

    binary = "/bin/ls"
    patchelf_out = tmpdir / "patchelf_out"
    goblin_out = tmpdir / "goblin_out"

    # Copy binaries
    shutil.copy(binary, patchelf_out)
    shutil.copy(binary, goblin_out)

    # Get goblin binary path
    goblin_binary = Path(__file__).parent.parent / "target" / "release" / "examples" / "patchelf"
    if not goblin_binary.exists():
        print("Building goblin...")
        subprocess.run(["cargo", "build", "--release", "--example", "patchelf"],
                      cwd=Path(__file__).parent.parent)

    print(f"\n=== Original binary sections (first 15) ===")
    print(run_cmd(["readelf", "-S", binary]).split('\n')[:20])

    # Run patchelf
    print(f"\n=== Running patchelf ===")
    subprocess.run(["patchelf", "--set-interpreter", "/short", str(patchelf_out)])

    # Run goblin
    print(f"\n=== Running goblin ===")
    result = subprocess.run([str(goblin_binary), "--set-interpreter", "/short", str(goblin_out)],
                           capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")

    # Compare headers
    print(f"\n=== Patchelf ELF Header ===")
    print(run_cmd(["readelf", "-h", str(patchelf_out)]))

    print(f"\n=== Goblin ELF Header ===")
    print(run_cmd(["readelf", "-h", str(goblin_out)]))

    # Compare program headers
    print(f"\n=== Patchelf Program Headers ===")
    patchelf_phdrs = run_cmd(["readelf", "-l", str(patchelf_out)])
    for line in patchelf_phdrs.split('\n')[:45]:
        print(line)

    print(f"\n=== Goblin Program Headers ===")
    goblin_phdrs = run_cmd(["readelf", "-l", str(goblin_out)])
    for line in goblin_phdrs.split('\n')[:45]:
        print(line)

    # Compare section headers
    print(f"\n=== Patchelf Section Headers (first 15) ===")
    patchelf_shdrs = run_cmd(["readelf", "-S", str(patchelf_out)])
    for line in patchelf_shdrs.split('\n')[:22]:
        print(line)

    print(f"\n=== Goblin Section Headers (first 15) ===")
    goblin_shdrs = run_cmd(["readelf", "-S", str(goblin_out)])
    for line in goblin_shdrs.split('\n')[:22]:
        print(line)

    # File sizes
    print(f"\n=== File Sizes ===")
    print(f"Original: {Path(binary).stat().st_size}")
    print(f"Patchelf: {patchelf_out.stat().st_size}")
    print(f"Goblin:   {goblin_out.stat().st_size}")

    # Keep files for inspection
    print(f"\n=== Files kept at {tmpdir} ===")

if __name__ == "__main__":
    main()
