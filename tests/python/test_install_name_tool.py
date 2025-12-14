#!/usr/bin/env python3
"""
Test framework for comparing goblin's MachOWriter against Apple's install_name_tool.

This script tests various modifications on dylib files and compares the output
of goblin's install_name_tool implementation against Apple's official tool.

Usage:
    python test_install_name_tool.py [options] <dylib_path_or_folder>

Options:
    --goblin-tool PATH    Path to goblin's install_name_tool binary
    --max-files N         Maximum number of files to test (default: all)
    --verbose, -v         Verbose output
    --strict              Require bit-for-bit identical output (not just structural)
    --skip-fat            Skip fat/universal binaries
    --include-executables Also test executable Mach-O files (not just dylibs)
    --operations OPS      Comma-separated list of operations to test
                          (change_id, change_dylib, add_rpath, delete_rpath, change_rpath)
    --test-entitlements   Test that entitlements are preserved when modifying binaries
                          (creates test binaries with custom entitlements and verifies
                          both Apple and goblin tools preserve them identically)
"""

import argparse
import hashlib
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional


def safe_copy(src: Path, dst: Path) -> None:
    """Copy a file without copying file flags (which can fail on system files)."""
    shutil.copy(src, dst)  # Copies content and permission bits only
    # Make it writable so we can modify it
    os.chmod(dst, 0o644)


class TestResult(Enum):
    PASS = auto()
    FAIL = auto()
    SKIP = auto()
    ERROR = auto()


@dataclass
class TestCase:
    name: str
    operation: str
    args: list[str]
    result: TestResult = TestResult.SKIP
    error_message: str = ""
    goblin_size: int = 0
    apple_size: int = 0
    diff_offset: Optional[int] = None


@dataclass
class FileTestResult:
    path: Path
    test_cases: list[TestCase] = field(default_factory=list)
    is_fat: bool = False
    install_name: Optional[str] = None
    rpaths: list[str] = field(default_factory=list)
    dylibs: list[str] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for tc in self.test_cases if tc.result == TestResult.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for tc in self.test_cases if tc.result == TestResult.FAIL)

    @property
    def skipped(self) -> int:
        return sum(1 for tc in self.test_cases if tc.result == TestResult.SKIP)

    @property
    def errors(self) -> int:
        return sum(1 for tc in self.test_cases if tc.result == TestResult.ERROR)


def random_string(length: int = 16) -> str:
    """Generate a random string for test paths."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def random_path() -> str:
    """Generate a random dylib-like path."""
    components = [
        "@rpath",
        "@executable_path",
        "@loader_path",
        "/usr/lib",
        "/usr/local/lib",
        "/opt/homebrew/lib",
    ]
    base = random.choice(components)
    subpath = "/".join(random_string(8) for _ in range(random.randint(1, 3)))
    name = f"lib{random_string(8)}.dylib"
    return f"{base}/{subpath}/{name}"


def get_macho_info(path: Path) -> dict:
    """Get information about a Mach-O binary using otool."""
    info = {
        "install_name": None,
        "rpaths": [],
        "dylibs": [],
        "is_fat": False,
    }

    # Check if it's a fat binary
    try:
        result = subprocess.run(
            ["lipo", "-info", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if "Architectures in the fat file" in result.stdout:
            info["is_fat"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Get load commands
    try:
        result = subprocess.run(
            ["otool", "-l", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return info

        lines = result.stdout.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line == "cmd LC_ID_DYLIB":
                # Find the name
                for j in range(i, min(i + 10, len(lines))):
                    if "name " in lines[j]:
                        name = lines[j].split("name ")[1].split(" (offset")[0].strip()
                        info["install_name"] = name
                        break

            elif line == "cmd LC_RPATH":
                for j in range(i, min(i + 10, len(lines))):
                    if "path " in lines[j]:
                        path_val = (
                            lines[j].split("path ")[1].split(" (offset")[0].strip()
                        )
                        info["rpaths"].append(path_val)
                        break

            elif line in (
                "cmd LC_LOAD_DYLIB",
                "cmd LC_LOAD_WEAK_DYLIB",
                "cmd LC_REEXPORT_DYLIB",
                "cmd LC_LAZY_LOAD_DYLIB",
            ):
                for j in range(i, min(i + 10, len(lines))):
                    if "name " in lines[j]:
                        name = lines[j].split("name ")[1].split(" (offset")[0].strip()
                        info["dylibs"].append(name)
                        break

            i += 1

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return info


def get_entitlements(path: Path) -> Optional[str]:
    """Get entitlements from a binary as XML string, or None if no entitlements."""
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", "-", "--xml", str(path)],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.decode("utf-8", errors="replace")
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def get_codesign_flags(path: Path) -> tuple[bool, bool, bool]:
    """
    Get code signature flags from a binary.

    Returns: (has_signature, is_adhoc, is_linker_signed)
    """
    try:
        result = subprocess.run(
            ["codesign", "-d", "-v", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False, False, False

        output = result.stderr  # codesign outputs to stderr
        has_sig = "CodeDirectory" in output
        is_adhoc = "adhoc" in output.lower()
        is_linker_signed = "linker-signed" in output.lower()

        return has_sig, is_adhoc, is_linker_signed
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, False, False


def create_binary_with_entitlements(
    base_binary: Path, output_path: Path, entitlements: dict
) -> bool:
    """
    Create a copy of a binary and sign it with the given entitlements.

    Returns True if successful.
    """
    import plistlib

    try:
        # Copy the base binary
        safe_copy(base_binary, output_path)

        # Create entitlements plist
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.plist', delete=False) as f:
            plistlib.dump(entitlements, f)
            ent_path = f.name

        try:
            # Sign with entitlements
            result = subprocess.run(
                ["codesign", "-s", "-", "--entitlements", ent_path, "-f", str(output_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        finally:
            os.unlink(ent_path)
    except Exception:
        return False


def get_code_signature_info(path: Path) -> dict:
    """Get detailed code signature info from a binary."""
    info = {
        "has_signature": False,
        "signature_size": 0,
        "entitlements_size": 0,
        "requirements_size": 0,
        "flags": "",
    }

    # Get signature info via codesign -d -vvv
    try:
        result = subprocess.run(
            ["codesign", "-d", "-vvv", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            output = result.stderr
            info["has_signature"] = True
            info["flags"] = output
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Get LC_CODE_SIGNATURE size via otool
    try:
        result = subprocess.run(
            ["otool", "-l", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            lines = result.stdout.split("\n")
            for i, line in enumerate(lines):
                if "cmd LC_CODE_SIGNATURE" in line:
                    for j in range(i, min(i + 5, len(lines))):
                        if "datasize" in lines[j]:
                            info["signature_size"] = int(lines[j].split()[-1])
                            break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Get entitlements size
    ents = get_entitlements(path)
    if ents:
        info["entitlements_size"] = len(ents)

    return info


def test_codesign_preserve(
    base_binary: Path,
    goblin_tool: Path,
    tmpdir: Path,
    entitlements: dict,
    verbose: bool = False,
) -> TestCase:
    """
    Test goblin's --codesign flag against Apple's codesign --preserve-metadata.

    This creates a binary with entitlements, then signs it with both:
    - goblin's --codesign flag
    - Apple's codesign -f -s - --preserve-metadata=entitlements,requirements

    Verifies the outputs match and entitlements are preserved.
    """
    tc = TestCase(
        name="codesign_preserve",
        operation="codesign",
        args=[],
    )

    # Create test binary with entitlements
    test_binary = tmpdir / "test_codesign_binary"
    if not create_binary_with_entitlements(base_binary, test_binary, entitlements):
        tc.result = TestResult.SKIP
        tc.error_message = "Failed to create binary with entitlements"
        return tc

    # Get original entitlements
    original_ents = get_entitlements(test_binary)
    if not original_ents:
        tc.result = TestResult.SKIP
        tc.error_message = "Binary has no entitlements after signing"
        return tc

    if verbose:
        print(f"    Original entitlements present: {len(original_ents)} bytes")
        orig_sig_info = get_code_signature_info(test_binary)
        print(f"    Original signature size: {orig_sig_info['signature_size']} bytes")

    # Use same filename for both to get identical identifiers
    shared_file = tmpdir / "codesign_test"
    apple_result = tmpdir / "apple_codesign"

    # Run Apple's codesign first
    safe_copy(test_binary, shared_file)
    try:
        result = subprocess.run(
            ["codesign", "-f", "-s", "-", "--preserve-metadata=entitlements,requirements", str(shared_file)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            tc.result = TestResult.SKIP
            tc.error_message = f"Apple codesign failed: {result.stderr.strip()}"
            return tc
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        tc.result = TestResult.SKIP
        tc.error_message = f"Apple codesign failed: {e}"
        return tc

    # Save Apple's result
    shutil.copy(shared_file, apple_result)

    # Run goblin's --codesign
    safe_copy(test_binary, shared_file)
    try:
        result = subprocess.run(
            [str(goblin_tool), "--codesign", str(shared_file)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            tc.result = TestResult.ERROR
            tc.error_message = f"Goblin --codesign failed: {result.stderr.strip()}"
            return tc
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        tc.result = TestResult.ERROR
        tc.error_message = f"Goblin --codesign failed: {e}"
        return tc

    # Check entitlements preserved
    apple_ents = get_entitlements(apple_result)
    goblin_ents = get_entitlements(shared_file)

    if verbose:
        apple_sig_info = get_code_signature_info(apple_result)
        goblin_sig_info = get_code_signature_info(shared_file)
        print(f"    Apple result: size={apple_result.stat().st_size}, sig_size={apple_sig_info['signature_size']}, ents={apple_sig_info['entitlements_size']}")
        print(f"    Goblin result: size={shared_file.stat().st_size}, sig_size={goblin_sig_info['signature_size']}, ents={goblin_sig_info['entitlements_size']}")

    if not apple_ents:
        tc.result = TestResult.SKIP
        tc.error_message = "Apple codesign did not preserve entitlements"
        return tc

    if not goblin_ents:
        tc.result = TestResult.FAIL
        tc.error_message = "Goblin --codesign did not preserve entitlements (Apple did)"
        return tc

    # Compare outputs
    tc.goblin_size = shared_file.stat().st_size
    tc.apple_size = apple_result.stat().st_size

    # For codesign --preserve-metadata comparison, we verify:
    # 1. Both files are the same size (signature fits in same space)
    # 2. Both preserve entitlements
    # 3. Both have valid signatures (codesign -v succeeds)
    # Note: Bit-for-bit equality is not required since Apple generates identifiers
    # differently (appending a hash suffix to the filename)

    if tc.goblin_size != tc.apple_size:
        tc.result = TestResult.FAIL
        tc.error_message = f"Size mismatch: Goblin {tc.goblin_size} vs Apple {tc.apple_size}"
    elif apple_ents != goblin_ents:
        tc.result = TestResult.FAIL
        tc.error_message = f"Entitlements content mismatch"
    else:
        # Verify signature is valid
        try:
            result = subprocess.run(
                ["codesign", "-v", str(shared_file)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                tc.result = TestResult.FAIL
                tc.error_message = f"Goblin signature invalid: {result.stderr.strip()}"
            else:
                tc.result = TestResult.PASS
                if verbose:
                    print(f"    Entitlements preserved, sizes match, signature valid")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            tc.result = TestResult.ERROR
            tc.error_message = f"Failed to verify signature: {e}"

    # Additional debugging for failures
    if tc.result == TestResult.FAIL and verbose:
        # Check if it's a fat binary and show per-arch info
        info = get_macho_info(apple_result)
        if info["is_fat"]:
            print(f"    Fat binary detected - comparing per-architecture:")
            for arch in ["x86_64", "arm64", "arm64e"]:
                try:
                    apple_arch_sig = subprocess.run(
                        ["otool", "-arch", arch, "-l", str(apple_result)],
                        capture_output=True, text=True, timeout=10
                    )
                    goblin_arch_sig = subprocess.run(
                        ["otool", "-arch", arch, "-l", str(shared_file)],
                        capture_output=True, text=True, timeout=10
                    )
                    if apple_arch_sig.returncode == 0:
                        # Extract code sig info
                        for name, output in [("Apple", apple_arch_sig.stdout), ("Goblin", goblin_arch_sig.stdout)]:
                            lines = output.split("\n")
                            for i, line in enumerate(lines):
                                if "cmd LC_CODE_SIGNATURE" in line:
                                    for j in range(i, min(i + 5, len(lines))):
                                        if "datasize" in lines[j]:
                                            print(f"      {arch} {name}: sig_size={lines[j].split()[-1]}")
                                            break
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

        # Show codesign -d output for comparison
        print(f"    Apple codesign -d output:")
        try:
            result = subprocess.run(
                ["codesign", "-d", "-vvv", str(apple_result)],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stderr.split("\n")[:15]:
                print(f"      {line}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        print(f"    Goblin codesign -d output:")
        try:
            result = subprocess.run(
                ["codesign", "-d", "-vvv", str(shared_file)],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stderr.split("\n")[:15]:
                print(f"      {line}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return tc


def test_entitlements_preservation(
    base_binary: Path,
    goblin_tool: Path,
    tmpdir: Path,
    operation: str,
    args: list[str],
    entitlements: dict,
    verbose: bool = False,
) -> TestCase:
    """
    Test that entitlements are preserved when modifying a binary with entitlements.

    This creates a binary with the given entitlements, modifies it with both
    Apple's and goblin's install_name_tool, and verifies:
    1. Both tools preserve the entitlements
    2. The outputs are identical
    """
    tc = TestCase(
        name=f"{operation}_entitlements",
        operation=operation,
        args=args,
    )

    # Create test binary with entitlements
    test_binary = tmpdir / "test_binary_with_entitlements"
    if not create_binary_with_entitlements(base_binary, test_binary, entitlements):
        tc.result = TestResult.SKIP
        tc.error_message = "Failed to create binary with entitlements"
        return tc

    # Get original entitlements
    original_ents = get_entitlements(test_binary)
    if not original_ents:
        tc.result = TestResult.SKIP
        tc.error_message = "Binary has no entitlements after signing"
        return tc

    if verbose:
        print(f"    Original entitlements present: {len(original_ents)} bytes")

    # Run both tools using the same filename (for identical code signatures)
    shared_file = tmpdir / "shared_test"
    apple_result = tmpdir / "apple_with_ents"

    # Run Apple tool first
    apple_ok, apple_err = run_apple_tool(test_binary, shared_file, operation, args)
    if not apple_ok:
        tc.result = TestResult.SKIP
        tc.error_message = f"Apple tool failed: {apple_err}"
        return tc

    # Save Apple's result
    shutil.copy(shared_file, apple_result)
    apple_ents = get_entitlements(apple_result)

    # Run goblin tool on fresh copy with same filename
    goblin_ok, goblin_err = run_goblin_tool(
        goblin_tool, test_binary, shared_file, operation, args
    )
    if not goblin_ok:
        tc.result = TestResult.ERROR
        tc.error_message = f"Goblin tool failed: {goblin_err}"
        return tc

    goblin_ents = get_entitlements(shared_file)

    # Check entitlements preservation
    if not apple_ents:
        if verbose:
            print("    Apple tool did NOT preserve entitlements")
    if not goblin_ents:
        if verbose:
            print("    Goblin tool did NOT preserve entitlements")

    # Both should preserve entitlements (or both should not - match Apple's behavior)
    if bool(apple_ents) != bool(goblin_ents):
        tc.result = TestResult.FAIL
        tc.error_message = (
            f"Entitlements mismatch: Apple {'preserved' if apple_ents else 'removed'}, "
            f"Goblin {'preserved' if goblin_ents else 'removed'}"
        )
        return tc

    # Compare the outputs bit-for-bit
    tc.goblin_size = shared_file.stat().st_size
    tc.apple_size = apple_result.stat().st_size

    match, msg = compare_binaries(shared_file, apple_result, strict=True)
    if match:
        tc.result = TestResult.PASS
        if verbose:
            ents_status = "preserved" if goblin_ents else "removed (matching Apple)"
            print(f"    Entitlements {ents_status}, outputs identical")
    else:
        tc.result = TestResult.FAIL
        tc.error_message = f"Output differs: {msg}"

    return tc


def compare_binaries(path1: Path, path2: Path, strict: bool = False) -> tuple[bool, str]:
    """
    Compare two binary files.

    If strict=True, requires bit-for-bit identical.
    If strict=False, allows some differences (timestamps, padding).
    """
    data1 = path1.read_bytes()
    data2 = path2.read_bytes()

    if data1 == data2:
        return True, "Identical"

    if strict:
        # Find first difference
        for i, (b1, b2) in enumerate(zip(data1, data2)):
            if b1 != b2:
                return False, f"First difference at offset 0x{i:x}: 0x{b1:02x} vs 0x{b2:02x}"
        if len(data1) != len(data2):
            return False, f"Size difference: {len(data1)} vs {len(data2)} bytes"
        return False, "Unknown difference"

    # Non-strict comparison: check structural equivalence
    # Parse both with otool and compare the parsed info
    info1 = get_macho_info(path1)
    info2 = get_macho_info(path2)

    differences = []

    if info1["install_name"] != info2["install_name"]:
        differences.append(
            f"install_name: {info1['install_name']} vs {info2['install_name']}"
        )

    if set(info1["rpaths"]) != set(info2["rpaths"]):
        differences.append(f"rpaths: {info1['rpaths']} vs {info2['rpaths']}")

    if set(info1["dylibs"]) != set(info2["dylibs"]):
        differences.append(f"dylibs: {info1['dylibs']} vs {info2['dylibs']}")

    if differences:
        return False, "; ".join(differences)

    # Structural match but byte differences (likely timestamps/padding)
    size_diff = abs(len(data1) - len(data2))
    return True, f"Structural match (size diff: {size_diff} bytes)"


def run_apple_tool(
    input_path: Path, output_path: Path, operation: str, args: list[str]
) -> tuple[bool, str]:
    """Run Apple's install_name_tool."""
    cmd = ["install_name_tool"]

    if operation == "change_id":
        cmd.extend(["-id", args[0]])
    elif operation == "change_dylib":
        cmd.extend(["-change", args[0], args[1]])
    elif operation == "add_rpath":
        cmd.extend(["-add_rpath", args[0]])
    elif operation == "delete_rpath":
        cmd.extend(["-delete_rpath", args[0]])
    elif operation == "change_rpath":
        cmd.extend(["-rpath", args[0], args[1]])
    else:
        return False, f"Unknown operation: {operation}"

    # Copy input to output first
    safe_copy(input_path, output_path)

    cmd.append(str(output_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or "Unknown error"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, "install_name_tool not found"


def run_goblin_tool(
    goblin_path: Path,
    input_path: Path,
    output_path: Path,
    operation: str,
    args: list[str],
) -> tuple[bool, str]:
    """Run goblin's install_name_tool."""
    cmd = [str(goblin_path)]

    if operation == "change_id":
        cmd.extend(["-id", args[0]])
    elif operation == "change_dylib":
        cmd.extend(["-change", args[0], args[1]])
    elif operation == "add_rpath":
        cmd.extend(["-add_rpath", args[0]])
    elif operation == "delete_rpath":
        cmd.extend(["-delete_rpath", args[0]])
    elif operation == "change_rpath":
        cmd.extend(["-rpath", args[0], args[1]])
    else:
        return False, f"Unknown operation: {operation}"

    # Copy input to output first (goblin tool modifies in place)
    safe_copy(input_path, output_path)

    cmd.append(str(output_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or "Unknown error"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, f"Goblin tool not found at {goblin_path}"


def run_single_test(
    dylib_path: Path,
    goblin_tool: Path,
    tmpdir: Path,
    operation: str,
    args: list[str],
    strict: bool = False,
) -> TestCase:
    """Run a single test case comparing Apple and goblin tools.

    In strict mode, uses the same filename for both tools to ensure
    identical code signature identifiers.
    """
    tc = TestCase(name=operation, operation=operation, args=args)

    if strict:
        # Use the same filename for both to get identical code signatures
        test_file = tmpdir / "testfile"
        apple_result = tmpdir / "apple_result"

        # Run Apple tool
        apple_ok, apple_err = run_apple_tool(dylib_path, test_file, operation, args)
        if not apple_ok:
            tc.result = TestResult.SKIP
            tc.error_message = f"Apple tool failed: {apple_err}"
            return tc

        # Save Apple's result
        shutil.copy(test_file, apple_result)

        # Run goblin tool on a fresh copy with the same filename
        goblin_ok, goblin_err = run_goblin_tool(
            goblin_tool, dylib_path, test_file, operation, args
        )
        if not goblin_ok:
            tc.result = TestResult.ERROR
            tc.error_message = f"Goblin tool failed: {goblin_err}"
            return tc

        # Compare
        tc.goblin_size = test_file.stat().st_size
        tc.apple_size = apple_result.stat().st_size
        match, msg = compare_binaries(test_file, apple_result, strict=True)
    else:
        # Non-strict: use separate filenames (faster, no need to save/restore)
        apple_out = tmpdir / f"apple_{operation}"
        goblin_out = tmpdir / f"goblin_{operation}"

        apple_ok, apple_err = run_apple_tool(dylib_path, apple_out, operation, args)
        if not apple_ok:
            tc.result = TestResult.SKIP
            tc.error_message = f"Apple tool failed: {apple_err}"
            return tc

        goblin_ok, goblin_err = run_goblin_tool(
            goblin_tool, dylib_path, goblin_out, operation, args
        )
        if not goblin_ok:
            tc.result = TestResult.ERROR
            tc.error_message = f"Goblin tool failed: {goblin_err}"
            return tc

        tc.goblin_size = goblin_out.stat().st_size
        tc.apple_size = apple_out.stat().st_size
        match, msg = compare_binaries(goblin_out, apple_out, strict=False)

    if match:
        tc.result = TestResult.PASS
    else:
        tc.result = TestResult.FAIL
        tc.error_message = msg

    return tc


def test_file(
    dylib_path: Path,
    goblin_tool: Path,
    operations: list[str],
    strict: bool = False,
    verbose: bool = False,
) -> FileTestResult:
    """Test a single dylib file with various operations."""
    result = FileTestResult(path=dylib_path)

    # Get info about the file
    info = get_macho_info(dylib_path)
    result.is_fat = info["is_fat"]
    result.install_name = info["install_name"]
    result.rpaths = info["rpaths"]
    result.dylibs = info["dylibs"]

    if verbose:
        print(f"  Install name: {result.install_name}")
        print(f"  RPaths: {result.rpaths}")
        print(f"  Is fat: {result.is_fat}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Test change_id (only for dylibs with install name)
        if "change_id" in operations and result.install_name:
            new_id = random_path()
            tc = run_single_test(
                dylib_path, goblin_tool, tmpdir, "change_id", [new_id], strict
            )
            result.test_cases.append(tc)

        # Test change_dylib (only if there are dylibs)
        if "change_dylib" in operations and result.dylibs:
            old_dylib = result.dylibs[0]  # Pick first dylib to change
            new_dylib = random_path()
            tc = run_single_test(
                dylib_path, goblin_tool, tmpdir, "change_dylib", [old_dylib, new_dylib], strict
            )
            result.test_cases.append(tc)

        # Test add_rpath
        if "add_rpath" in operations:
            new_rpath = f"@executable_path/../Frameworks/{random_string(8)}"
            tc = run_single_test(
                dylib_path, goblin_tool, tmpdir, "add_rpath", [new_rpath], strict
            )
            result.test_cases.append(tc)

        # Test delete_rpath (only if there are rpaths)
        if "delete_rpath" in operations and result.rpaths:
            rpath_to_delete = result.rpaths[0]
            tc = run_single_test(
                dylib_path, goblin_tool, tmpdir, "delete_rpath", [rpath_to_delete], strict
            )
            result.test_cases.append(tc)

        # Test change_rpath (only if there are rpaths)
        if "change_rpath" in operations and result.rpaths:
            old_rpath = result.rpaths[0]
            new_rpath = f"@loader_path/../lib/{random_string(8)}"
            tc = run_single_test(
                dylib_path, goblin_tool, tmpdir, "change_rpath", [old_rpath, new_rpath], strict
            )
            result.test_cases.append(tc)

    return result


def test_file_entitlements(
    macho_path: Path,
    goblin_tool: Path,
    operations: list[str],
    verbose: bool = False,
) -> FileTestResult:
    """
    Test entitlements preservation for a single Mach-O file.

    This tests that when modifying a binary with entitlements,
    both Apple's and goblin's tools behave identically.

    Note: Entitlements are typically only embedded in executables, not dylibs.
    Use --include-executables when testing entitlements preservation.
    For dylibs, entitlements tests will be skipped.
    """
    result = FileTestResult(path=macho_path)

    # Get info about the file
    info = get_macho_info(macho_path)
    result.is_fat = info["is_fat"]
    result.install_name = info["install_name"]
    result.rpaths = info["rpaths"]
    result.dylibs = info["dylibs"]

    # Define test entitlements
    test_entitlements = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.client": True,
        "com.apple.security.files.user-selected.read-write": True,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Test change_id with entitlements (only for dylibs with install name)
        if "change_id" in operations and result.install_name:
            new_id = random_path()
            tc = test_entitlements_preservation(
                macho_path, goblin_tool, tmpdir, "change_id", [new_id],
                test_entitlements, verbose
            )
            result.test_cases.append(tc)

        # Test change_dylib with entitlements (only if there are dylibs)
        if "change_dylib" in operations and result.dylibs:
            old_dylib = result.dylibs[0]
            new_dylib = random_path()
            tc = test_entitlements_preservation(
                macho_path, goblin_tool, tmpdir, "change_dylib", [old_dylib, new_dylib],
                test_entitlements, verbose
            )
            result.test_cases.append(tc)

        # Test add_rpath with entitlements
        if "add_rpath" in operations:
            new_rpath = f"@executable_path/../Frameworks/{random_string(8)}"
            tc = test_entitlements_preservation(
                macho_path, goblin_tool, tmpdir, "add_rpath", [new_rpath],
                test_entitlements, verbose
            )
            result.test_cases.append(tc)

        # Test delete_rpath with entitlements (only if there are rpaths)
        if "delete_rpath" in operations and result.rpaths:
            rpath_to_delete = result.rpaths[0]
            tc = test_entitlements_preservation(
                macho_path, goblin_tool, tmpdir, "delete_rpath", [rpath_to_delete],
                test_entitlements, verbose
            )
            result.test_cases.append(tc)

        # Test change_rpath with entitlements (only if there are rpaths)
        if "change_rpath" in operations and result.rpaths:
            old_rpath = result.rpaths[0]
            new_rpath = f"@loader_path/../lib/{random_string(8)}"
            tc = test_entitlements_preservation(
                macho_path, goblin_tool, tmpdir, "change_rpath", [old_rpath, new_rpath],
                test_entitlements, verbose
            )
            result.test_cases.append(tc)

    return result


def is_macho_file(path: Path) -> bool:
    """Check if a file is a Mach-O binary by reading its magic number."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            # Check for Mach-O magic numbers (both endiannesses)
            # MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC, FAT_CIGAM
            macho_magics = [
                b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit)
                b"\xce\xfa\xed\xfe",  # MH_CIGAM (32-bit swapped)
                b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (64-bit)
                b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 (64-bit swapped)
                b"\xca\xfe\xba\xbe",  # FAT_MAGIC (universal)
                b"\xbe\xba\xfe\xca",  # FAT_CIGAM (universal swapped)
                b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64 (universal 64-bit)
                b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64 (universal 64-bit swapped)
            ]
            return magic in macho_magics
    except (IOError, OSError):
        return False


def find_macho_files(
    path: Path, max_files: Optional[int] = None, include_executables: bool = False
) -> list[Path]:
    """Find Mach-O files in a directory or return single file."""
    if path.is_file():
        # Resolve symlinks and check readability
        resolved = path.resolve()
        if resolved.exists() and os.access(resolved, os.R_OK):
            if resolved.suffix == ".dylib" or (include_executables and is_macho_file(resolved)):
                return [resolved]
        return []

    files_found = []
    seen_inodes = set()  # Track inodes to avoid duplicate files via symlinks

    for root, dirs, files in os.walk(path):
        for f in files:
            p = Path(root) / f
            try:
                resolved = p.resolve()
                if not resolved.exists() or not os.access(resolved, os.R_OK):
                    continue

                # Skip duplicates (same file via different symlinks)
                stat_info = resolved.stat()
                inode_key = (stat_info.st_dev, stat_info.st_ino)
                if inode_key in seen_inodes:
                    continue
                seen_inodes.add(inode_key)

                # Check if it's a dylib or (optionally) an executable
                if f.endswith(".dylib"):
                    files_found.append(resolved)
                elif include_executables and is_macho_file(resolved):
                    # Skip .o, .a files and other non-executable Mach-O
                    if not f.endswith((".o", ".a", ".dSYM")):
                        files_found.append(resolved)

                if max_files and len(files_found) >= max_files:
                    return files_found
            except (OSError, IOError):
                pass

    return files_found


# Keep old name for backwards compatibility
def find_dylibs(path: Path, max_files: Optional[int] = None) -> list[Path]:
    """Find all dylib files in a directory or return single file."""
    return find_macho_files(path, max_files, include_executables=False)


def build_goblin_tool(project_root: Path) -> Optional[Path]:
    """Build the goblin install_name_tool example."""
    print("Building goblin install_name_tool...")
    result = subprocess.run(
        ["cargo", "build", "--release", "--example", "install_name_tool", "--features", "codesign"],
        cwd=project_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Failed to build: {result.stderr}")
        return None

    tool_path = project_root / "target" / "release" / "examples" / "install_name_tool"
    if tool_path.exists():
        return tool_path
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Test goblin MachOWriter against Apple's install_name_tool"
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to dylib file or folder containing dylibs",
    )
    parser.add_argument(
        "--goblin-tool",
        type=Path,
        default=None,
        help="Path to goblin's install_name_tool binary",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Maximum number of files to test",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Require bit-for-bit identical output",
    )
    parser.add_argument(
        "--skip-fat",
        action="store_true",
        help="Skip fat/universal binaries",
    )
    parser.add_argument(
        "--include-executables",
        action="store_true",
        help="Also test executable Mach-O files (not just dylibs)",
    )
    parser.add_argument(
        "--operations",
        type=str,
        default="change_id,change_dylib,add_rpath,delete_rpath,change_rpath",
        help="Comma-separated list of operations to test",
    )
    parser.add_argument(
        "--test-entitlements",
        action="store_true",
        help="Test entitlements preservation (creates signed test binaries)",
    )
    parser.add_argument(
        "--test-codesign",
        action="store_true",
        help="Test --codesign flag against Apple's codesign --preserve-metadata",
    )

    args = parser.parse_args()

    # Build or find the goblin tool
    goblin_tool = args.goblin_tool
    if goblin_tool is None:
        # Try to find it relative to this script
        script_dir = Path(__file__).parent
        project_root = script_dir.parent.parent
        goblin_tool = build_goblin_tool(project_root)
        if goblin_tool is None:
            print("Error: Could not build goblin install_name_tool")
            sys.exit(1)

    if not goblin_tool.exists():
        print(f"Error: Goblin tool not found at {goblin_tool}")
        sys.exit(1)

    print(f"Using goblin tool: {goblin_tool}")

    # Find Mach-O files to test
    macho_files = find_macho_files(
        args.path, args.max_files, include_executables=args.include_executables
    )
    if not macho_files:
        file_types = "Mach-O files" if args.include_executables else "dylib files"
        print(f"No {file_types} found in {args.path}")
        sys.exit(1)

    file_types = "Mach-O file(s)" if args.include_executables else "dylib(s)"
    print(f"Found {len(macho_files)} {file_types} to test")

    operations = [op.strip() for op in args.operations.split(",")]
    print(f"Testing operations: {operations}")
    print()

    # Run tests
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_errors = 0

    def process_test_result(result: FileTestResult, prefix: str = "") -> None:
        """Process and print test results, updating totals."""
        nonlocal total_passed, total_failed, total_skipped, total_errors

        for tc in result.test_cases:
            name = f"{prefix}{tc.name}" if prefix else tc.name
            if tc.result == TestResult.PASS:
                total_passed += 1
                if args.verbose:
                    print(f"  PASS: {name}")
            elif tc.result == TestResult.FAIL:
                total_failed += 1
                print(f"  FAIL: {name}")
                print(f"    {tc.error_message}")
                print(f"    Goblin size: {tc.goblin_size}, Apple size: {tc.apple_size}")
            elif tc.result == TestResult.SKIP:
                total_skipped += 1
                if args.verbose:
                    print(f"  SKIP: {name} - {tc.error_message}")
            elif tc.result == TestResult.ERROR:
                total_errors += 1
                print(f"  ERROR: {name}")
                print(f"    {tc.error_message}")

    for i, macho_file in enumerate(macho_files, 1):
        print(f"[{i}/{len(macho_files)}] Testing {macho_file.name}...")

        result = test_file(
            macho_file,
            goblin_tool,
            operations,
            strict=args.strict,
            verbose=args.verbose,
        )

        if args.skip_fat and result.is_fat:
            print(f"  SKIPPED (fat binary)")
            total_skipped += len(operations)
            continue

        process_test_result(result)

        # Also run entitlements tests if requested
        if args.test_entitlements:
            if args.verbose:
                print(f"  Testing entitlements preservation...")
            ent_result = test_file_entitlements(
                macho_file,
                goblin_tool,
                operations,
                verbose=args.verbose,
            )
            process_test_result(ent_result, prefix="entitlements_")

        # Test --codesign flag against Apple's codesign --preserve-metadata
        if args.test_codesign:
            if args.verbose:
                print(f"  Testing --codesign (preserve entitlements)...")
            test_entitlements = {
                "com.apple.security.app-sandbox": True,
                "com.apple.security.network.client": True,
                "com.apple.security.files.user-selected.read-write": True,
            }
            with tempfile.TemporaryDirectory() as tmpdir:
                tc = test_codesign_preserve(
                    macho_file,
                    goblin_tool,
                    Path(tmpdir),
                    test_entitlements,
                    verbose=args.verbose,
                )
                # Create a FileTestResult to use process_test_result
                codesign_result = FileTestResult(path=macho_file)
                codesign_result.test_cases.append(tc)
                process_test_result(codesign_result)

    # Summary
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Passed:  {total_passed}")
    print(f"  Failed:  {total_failed}")
    print(f"  Skipped: {total_skipped}")
    print(f"  Errors:  {total_errors}")
    print()

    if total_failed > 0 or total_errors > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
