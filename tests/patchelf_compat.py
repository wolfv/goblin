#!/usr/bin/env python3
"""
Test harness for verifying byte-for-byte compatibility between goblin's ELF rewriter
and patchelf.

Usage:
    python tests/patchelf_compat.py [options]

Options:
    --build         Build the goblin patchelf example first
    --verbose       Show detailed output
    --keep-temp     Keep temporary files for debugging
"""

import os
import sys
import shutil
import subprocess
import tempfile
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def color_print(msg: str, color: str = Colors.RESET):
    """Print with color if stdout is a tty"""
    if sys.stdout.isatty():
        print(f"{color}{msg}{Colors.RESET}")
    else:
        print(msg)


class PatchelfCompatTest:
    """Test harness for comparing goblin and patchelf outputs"""

    def __init__(
        self,
        goblin_binary: Path,
        patchelf_binary: Path = None,
        verbose: bool = False,
        keep_temp: bool = False,
    ):
        self.goblin_binary = goblin_binary
        self.patchelf_binary = patchelf_binary or shutil.which("patchelf")
        self.verbose = verbose
        self.keep_temp = keep_temp
        self.test_results: List[Tuple[str, bool, str]] = []

        if not self.patchelf_binary:
            raise RuntimeError("patchelf not found in PATH")
        if not self.goblin_binary.exists():
            raise RuntimeError(f"goblin binary not found: {self.goblin_binary}")

    def _hex_diff(self, expected: bytes, actual: bytes, max_diffs: int = 20) -> str:
        """Generate a hex diff between two byte arrays"""
        lines = []
        diff_count = 0

        for i, (e, a) in enumerate(zip(expected, actual)):
            if e != a:
                lines.append(f"  Offset 0x{i:08x}: expected 0x{e:02x}, got 0x{a:02x}")
                diff_count += 1
                if diff_count >= max_diffs:
                    lines.append(f"  ... ({len(expected)} bytes total)")
                    break

        if len(expected) != len(actual):
            lines.append(f"  Size mismatch: expected {len(expected)}, got {len(actual)}")

        return "\n".join(lines)

    def _run_command(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and capture output"""
        if self.verbose:
            color_print(f"  Running: {' '.join(cmd)}", Colors.BLUE)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
        )

        if check and result.returncode != 0:
            raise RuntimeError(
                f"Command failed: {' '.join(cmd)}\n"
                f"stdout: {result.stdout.decode('utf-8', errors='replace')}\n"
                f"stderr: {result.stderr.decode('utf-8', errors='replace')}"
            )

        return result

    def compare_operation(
        self,
        test_name: str,
        binary_path: Path,
        operation: str,
        *args: str,
    ) -> bool:
        """Run the same operation with both patchelf and goblin, compare outputs"""
        if self.verbose:
            color_print(f"\nTest: {test_name}", Colors.BOLD)
            color_print(f"  Binary: {binary_path}", Colors.BLUE)
            color_print(f"  Operation: {operation} {' '.join(args)}", Colors.BLUE)

        tmpdir = tempfile.mkdtemp(prefix="patchelf_test_")
        try:
            patchelf_out = Path(tmpdir) / "patchelf_out"
            goblin_out = Path(tmpdir) / "goblin_out"

            # Copy original binaries
            shutil.copy(binary_path, patchelf_out)
            shutil.copy(binary_path, goblin_out)

            # Run patchelf
            patchelf_cmd = [self.patchelf_binary, f"--{operation}"] + list(args) + [str(patchelf_out)]
            try:
                self._run_command(patchelf_cmd)
            except RuntimeError as e:
                self.test_results.append((test_name, False, f"patchelf failed: {e}"))
                return False

            # Run goblin
            goblin_cmd = [str(self.goblin_binary), f"--{operation}"] + list(args) + [str(goblin_out)]
            try:
                self._run_command(goblin_cmd)
            except RuntimeError as e:
                self.test_results.append((test_name, False, f"goblin failed: {e}"))
                return False

            # Compare outputs
            patchelf_bytes = patchelf_out.read_bytes()
            goblin_bytes = goblin_out.read_bytes()

            if patchelf_bytes == goblin_bytes:
                self.test_results.append((test_name, True, ""))
                if self.verbose:
                    color_print("  PASS: Byte-for-byte identical", Colors.GREEN)
                return True
            else:
                diff = self._hex_diff(patchelf_bytes, goblin_bytes)
                self.test_results.append((test_name, False, f"Output differs:\n{diff}"))
                if self.verbose:
                    color_print(f"  FAIL: Output differs", Colors.RED)
                    print(diff)
                return False

        finally:
            if not self.keep_temp:
                shutil.rmtree(tmpdir, ignore_errors=True)
            else:
                print(f"  Temp dir kept: {tmpdir}")

    def print_summary(self):
        """Print test summary"""
        passed = sum(1 for _, ok, _ in self.test_results if ok)
        total = len(self.test_results)

        print("\n" + "=" * 60)
        color_print(f"Test Summary: {passed}/{total} passed", Colors.BOLD)
        print("=" * 60)

        for name, ok, msg in self.test_results:
            status = f"{Colors.GREEN}PASS{Colors.RESET}" if ok else f"{Colors.RED}FAIL{Colors.RESET}"
            print(f"  [{status}] {name}")
            if not ok and msg:
                for line in msg.split("\n")[:5]:
                    print(f"         {line}")

        return passed == total


def find_test_binaries() -> List[Path]:
    """Find suitable ELF binaries for testing"""
    candidates = [
        "/bin/ls",
        "/usr/bin/ls",
        "/bin/cat",
        "/usr/bin/cat",
        "/bin/echo",
        "/usr/bin/echo",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
    ]

    binaries = []
    for path in candidates:
        p = Path(path)
        if p.exists() and p.is_file():
            # Verify it's an ELF file
            try:
                with open(p, 'rb') as f:
                    magic = f.read(4)
                    if magic == b'\x7fELF':
                        binaries.append(p)
            except (IOError, PermissionError):
                continue

    return binaries


def is_executable(binary: Path) -> bool:
    """Check if binary has PT_INTERP (is an executable, not a library)"""
    try:
        result = subprocess.run(
            ["readelf", "-l", str(binary)],
            capture_output=True,
            text=True,
        )
        return "INTERP" in result.stdout
    except Exception:
        return False


def run_tests(
    goblin_binary: Path,
    verbose: bool = False,
    keep_temp: bool = False,
) -> bool:
    """Run all compatibility tests"""
    test = PatchelfCompatTest(
        goblin_binary=goblin_binary,
        verbose=verbose,
        keep_temp=keep_temp,
    )

    binaries = find_test_binaries()
    if not binaries:
        color_print("No test binaries found!", Colors.RED)
        return False

    color_print(f"Found {len(binaries)} test binaries", Colors.BLUE)
    for b in binaries:
        color_print(f"  - {b}", Colors.BLUE)

    # Test set-interpreter on executables
    for binary in binaries:
        if not is_executable(binary):
            continue

        test.compare_operation(
            f"set-interpreter (short): {binary.name}",
            binary,
            "set-interpreter",
            "/short",
        )

        test.compare_operation(
            f"set-interpreter (long): {binary.name}",
            binary,
            "set-interpreter",
            "/a/very/long/new/interpreter/path/that/is/much/longer/than/original",
        )

    # Test set-rpath
    for binary in binaries:
        test.compare_operation(
            f"set-rpath: {binary.name}",
            binary,
            "set-rpath",
            "/new/rpath:/another/path",
        )

    # Test add-needed
    for binary in binaries:
        test.compare_operation(
            f"add-needed: {binary.name}",
            binary,
            "add-needed",
            "libtest.so.1",
        )

    # Print summary
    return test.print_summary()


def build_goblin_example(project_dir: Path) -> Path:
    """Build the goblin patchelf example"""
    color_print("Building goblin patchelf example...", Colors.BLUE)

    result = subprocess.run(
        ["cargo", "build", "--release", "--example", "patchelf"],
        cwd=project_dir,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        color_print("Build failed!", Colors.RED)
        print(result.stderr)
        sys.exit(1)

    binary = project_dir / "target" / "release" / "examples" / "patchelf"
    if not binary.exists():
        color_print(f"Binary not found at {binary}", Colors.RED)
        sys.exit(1)

    color_print(f"Built: {binary}", Colors.GREEN)
    return binary


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Test goblin patchelf compatibility")
    parser.add_argument("--build", action="store_true", help="Build goblin example first")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--keep-temp", action="store_true", help="Keep temp files")
    parser.add_argument("--binary", type=Path, help="Path to goblin patchelf binary")
    args = parser.parse_args()

    # Find project directory
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent if script_dir.name == "tests" else script_dir

    # Build or locate binary
    if args.binary:
        goblin_binary = args.binary
    elif args.build:
        goblin_binary = build_goblin_example(project_dir)
    else:
        goblin_binary = project_dir / "target" / "release" / "examples" / "patchelf"
        if not goblin_binary.exists():
            color_print("Goblin binary not found. Use --build to build it.", Colors.YELLOW)
            goblin_binary = build_goblin_example(project_dir)

    # Check patchelf is available
    if not shutil.which("patchelf"):
        color_print("patchelf not found in PATH. Please install patchelf.", Colors.RED)
        sys.exit(1)

    # Run tests
    success = run_tests(
        goblin_binary=goblin_binary,
        verbose=args.verbose,
        keep_temp=args.keep_temp,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
