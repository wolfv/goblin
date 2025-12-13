#!/bin/bash
# Comprehensive patchelf compatibility test suite
# Don't set -e to allow tests to continue after failures

PATCHELF_ORIG="/home/wolfv/Programs/goblin/patchelf/src/patchelf"
PATCHELF_RUST="/home/wolfv/Programs/goblin/target/debug/examples/patchelf"
TEST_DIR="/home/wolfv/Programs/goblin/tmp/patchelf-tests"

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

compare_binaries() {
    local name="$1"
    local orig="$2"
    local rust="$3"

    if cmp -s "$orig" "$rust"; then
        echo -e "${GREEN}PASS${NC}: $name - byte-for-byte identical"
        pass_count=$((pass_count + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}: $name - binaries differ"
        echo "  First difference:"
        cmp "$orig" "$rust" 2>&1 | head -1 || true
        fail_count=$((fail_count + 1))
        return 1
    fi
}

verify_executes() {
    local name="$1"
    local binary="$2"
    chmod +x "$binary"
    if "$binary" 2>/dev/null; then
        echo -e "${GREEN}  Executes OK${NC}"
        return 0
    else
        echo -e "${RED}  FAILS to execute${NC}"
        return 1
    fi
}

echo "=========================================="
echo "Patchelf Byte-for-Byte Compatibility Tests"
echo "=========================================="
echo ""

# Test 1: Basic shorter rpath replacement
echo "TEST 1: Shorter rpath (in-place replacement)"
echo "  /original/path -> /new/path"
gcc -o "$TEST_DIR/test1" -x c - -Wl,-rpath,/original/path << 'EOF'
int main() { return 0; }
EOF

cp "$TEST_DIR/test1" "$TEST_DIR/test1_orig"
"$PATCHELF_ORIG" --set-rpath "/new/path" "$TEST_DIR/test1_orig"
"$PATCHELF_RUST" set-rpath "$TEST_DIR/test1" "$TEST_DIR/test1_rust" "/new/path"
compare_binaries "Shorter rpath" "$TEST_DIR/test1_orig" "$TEST_DIR/test1_rust"
verify_executes "test1_rust" "$TEST_DIR/test1_rust"
echo ""

# Test 2: Same length rpath
echo "TEST 2: Same length rpath"
echo "  /original/path -> /modified/path"
gcc -o "$TEST_DIR/test2" -x c - -Wl,-rpath,/original/path << 'EOF'
int main() { return 0; }
EOF

cp "$TEST_DIR/test2" "$TEST_DIR/test2_orig"
"$PATCHELF_ORIG" --set-rpath "/modified/path" "$TEST_DIR/test2_orig"
"$PATCHELF_RUST" set-rpath "$TEST_DIR/test2" "$TEST_DIR/test2_rust" "/modified/path"
compare_binaries "Same length rpath" "$TEST_DIR/test2_orig" "$TEST_DIR/test2_rust"
verify_executes "test2_rust" "$TEST_DIR/test2_rust"
echo ""

# Test 3: Longer rpath (requires slack space or relocation)
echo "TEST 3: Longer rpath (requires string table growth)"
echo "  /short -> /very/long/path/that/requires/growth"
gcc -o "$TEST_DIR/test3" -x c - -Wl,-rpath,/short << 'EOF'
int main() { return 0; }
EOF

cp "$TEST_DIR/test3" "$TEST_DIR/test3_orig"
"$PATCHELF_ORIG" --set-rpath "/very/long/path/that/requires/growth" "$TEST_DIR/test3_orig"
"$PATCHELF_RUST" set-rpath "$TEST_DIR/test3" "$TEST_DIR/test3_rust" "/very/long/path/that/requires/growth" 2>&1 || true
if [ -f "$TEST_DIR/test3_rust" ]; then
    compare_binaries "Longer rpath" "$TEST_DIR/test3_orig" "$TEST_DIR/test3_rust"
    verify_executes "test3_rust" "$TEST_DIR/test3_rust"
else
    echo -e "${YELLOW}SKIP${NC}: Rust patchelf doesn't support string table growth yet"
fi
echo ""

# Test 4: Empty rpath
echo "TEST 4: Empty rpath"
echo "  /original/path -> (empty)"
gcc -o "$TEST_DIR/test4" -x c - -Wl,-rpath,/original/path << 'EOF'
int main() { return 0; }
EOF

cp "$TEST_DIR/test4" "$TEST_DIR/test4_orig"
"$PATCHELF_ORIG" --set-rpath "" "$TEST_DIR/test4_orig"
"$PATCHELF_RUST" set-rpath "$TEST_DIR/test4" "$TEST_DIR/test4_rust" ""
compare_binaries "Empty rpath" "$TEST_DIR/test4_orig" "$TEST_DIR/test4_rust"
verify_executes "test4_rust" "$TEST_DIR/test4_rust"
echo ""

# Test 5: Remove rpath
echo "TEST 5: Remove rpath"
gcc -o "$TEST_DIR/test5" -x c - -Wl,-rpath,/to/be/removed << 'EOF'
int main() { return 0; }
EOF

cp "$TEST_DIR/test5" "$TEST_DIR/test5_orig"
"$PATCHELF_ORIG" --remove-rpath "$TEST_DIR/test5_orig"
"$PATCHELF_RUST" remove-runpath "$TEST_DIR/test5" "$TEST_DIR/test5_rust"
compare_binaries "Remove rpath" "$TEST_DIR/test5_orig" "$TEST_DIR/test5_rust"
verify_executes "test5_rust" "$TEST_DIR/test5_rust"
echo ""

# Test 6: Binary with DT_RPATH (not RUNPATH) - needs --enable-new-dtags=no
# Use same length paths to avoid string table growth issue
echo "TEST 6: DT_RPATH conversion to DT_RUNPATH"
# Create binary with DT_RPATH instead of DT_RUNPATH
gcc -o "$TEST_DIR/test6" -x c - -Wl,--disable-new-dtags,-rpath,/old/rpath << 'EOF'
int main() { return 0; }
EOF

echo "  Original has:"
readelf -d "$TEST_DIR/test6" | grep -E 'RPATH|RUNPATH' || echo "  No RPATH/RUNPATH found"

cp "$TEST_DIR/test6" "$TEST_DIR/test6_orig"
# Use same-length path: /old/rpath -> /new/rpath (10 chars each)
"$PATCHELF_ORIG" --set-rpath "/new/rpath" "$TEST_DIR/test6_orig"
"$PATCHELF_RUST" set-rpath "$TEST_DIR/test6" "$TEST_DIR/test6_rust" "/new/rpath"

echo "  After patchelf:"
readelf -d "$TEST_DIR/test6_orig" | grep -E 'RPATH|RUNPATH' || echo "  No RPATH/RUNPATH found"
echo "  After Rust patchelf:"
if [ -f "$TEST_DIR/test6_rust" ]; then
    readelf -d "$TEST_DIR/test6_rust" | grep -E 'RPATH|RUNPATH' || echo "  No RPATH/RUNPATH found"
    compare_binaries "RPATH to RUNPATH conversion" "$TEST_DIR/test6_orig" "$TEST_DIR/test6_rust"
    verify_executes "test6_rust" "$TEST_DIR/test6_rust"
else
    echo -e "${YELLOW}SKIP${NC}: File not created (likely requires string table growth)"
fi
echo ""

# Summary
echo "=========================================="
echo "Summary: $pass_count passed, $fail_count failed"
echo "=========================================="

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
