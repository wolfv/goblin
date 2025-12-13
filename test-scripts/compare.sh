#!/bin/bash
# Compare patchelf outputs between original C++ patchelf and our Rust implementation
set -e

PATCHELF_ORIG="/home/wolfv/Programs/goblin/patchelf/src/patchelf"
PATCHELF_RUST="/home/wolfv/Programs/goblin/target/debug/examples/patchelf"
TEST_DIR="/home/wolfv/Programs/goblin/tmp/patchelf-compare"

mkdir -p "$TEST_DIR"

# Create a simple test binary with rpath
echo 'int main() { return 0; }' > "$TEST_DIR/test.c"
gcc -o "$TEST_DIR/test_binary" "$TEST_DIR/test.c" -Wl,-rpath,/original/path
chmod +x "$TEST_DIR/test_binary"

echo "=== Original binary ==="
readelf -d "$TEST_DIR/test_binary" | grep -E 'RPATH|RUNPATH' || echo "No RPATH/RUNPATH"

echo ""
echo "=== Testing set-rpath with original patchelf ==="
cp "$TEST_DIR/test_binary" "$TEST_DIR/test_orig"
"$PATCHELF_ORIG" --set-rpath "/new/path" "$TEST_DIR/test_orig"
readelf -d "$TEST_DIR/test_orig" | grep -E 'RPATH|RUNPATH' || echo "No RPATH/RUNPATH"

echo ""
echo "=== Testing set-rpath with Rust patchelf ==="
rm -f "$TEST_DIR/test_rust_out"  # Remove stale file
"$PATCHELF_RUST" set-rpath "$TEST_DIR/test_binary" "$TEST_DIR/test_rust_out" "/new/path"
chmod +x "$TEST_DIR/test_rust_out"
readelf -d "$TEST_DIR/test_rust_out" | grep -E 'RPATH|RUNPATH' || echo "No RPATH/RUNPATH"

echo ""
echo "=== Binary comparison ==="
echo "Original patchelf output size: $(stat -c %s "$TEST_DIR/test_orig")"
echo "Rust patchelf output size: $(stat -c %s "$TEST_DIR/test_rust_out")"

echo ""
echo "=== Checking if binaries are identical ==="
if cmp -s "$TEST_DIR/test_orig" "$TEST_DIR/test_rust_out"; then
    echo "SUCCESS: Binaries are byte-for-byte identical!"
else
    echo "DIFFERENCE: Binaries differ"
    echo ""
    echo "First differences:"
    cmp "$TEST_DIR/test_orig" "$TEST_DIR/test_rust_out" || true
    echo ""
    echo "Hex diff (first 1000 bytes):"
    diff <(xxd "$TEST_DIR/test_orig" | head -100) <(xxd "$TEST_DIR/test_rust_out" | head -100) | head -50 || true
fi

echo ""
echo "=== Verify both outputs execute ==="
chmod +x "$TEST_DIR/test_orig" "$TEST_DIR/test_rust_out"
echo -n "Original patchelf output: "
"$TEST_DIR/test_orig" && echo "OK" || echo "Failed to execute"
echo -n "Rust patchelf output: "
"$TEST_DIR/test_rust_out" && echo "OK" || echo "Failed to execute"
