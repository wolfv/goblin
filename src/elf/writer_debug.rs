//! Debugging utilities for ELF writer
//!
//! This module provides debugging tools to help diagnose issues with ELF writing,
//! especially for section relocation.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Debug information about a section
#[derive(Debug, Clone)]
pub struct SectionDebugInfo {
    pub index: usize,
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub type_: u32,
    pub flags: u64,
    pub addr: u64,
}

/// Debug information about a program header
#[derive(Debug, Clone)]
pub struct ProgramHeaderDebugInfo {
    pub index: usize,
    pub type_: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
    pub align: u64,
}

/// Compares two byte slices and returns differences
pub fn compare_bytes(a: &[u8], b: &[u8], context: &str) -> Vec<String> {
    let mut diffs = Vec::new();
    let min_len = a.len().min(b.len());

    // Check length difference
    if a.len() != b.len() {
        diffs.push(format!(
            "{}: Length mismatch: {} vs {} bytes",
            context,
            a.len(),
            b.len()
        ));
    }

    // Find byte differences
    let mut diff_count = 0;
    let mut last_diff = None;
    for i in 0..min_len {
        if a[i] != b[i] {
            if diff_count < 10 {
                // Only report first 10 differences
                diffs.push(format!(
                    "{}: Byte diff at offset 0x{:x}: 0x{:02x} vs 0x{:02x}",
                    context, i, a[i], b[i]
                ));
            }
            diff_count += 1;
            last_diff = Some(i);
        }
    }

    if diff_count > 10 {
        diffs.push(format!(
            "{}: ... and {} more differences (last at 0x{:x})",
            context,
            diff_count - 10,
            last_diff.unwrap()
        ));
    }

    if diff_count == 0 && a.len() == b.len() {
        diffs.push(format!("{}: ✓ Identical", context));
    }

    diffs
}

/// Generates a hex dump of a byte range
pub fn hex_dump(data: &[u8], offset: usize, length: usize, label: &str) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("=== {} ===", label));

    let start = offset.min(data.len());
    let end = (offset + length).min(data.len());

    for (i, chunk) in data[start..end].chunks(16).enumerate() {
        let addr = start + i * 16;
        let mut line = format!("{:08x}: ", addr);

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                line.push_str(" ");
            }
            line.push_str(&format!("{:02x} ", byte));
        }

        // Padding if less than 16 bytes
        for _ in chunk.len()..16 {
            line.push_str("   ");
        }

        line.push_str(" |");

        // ASCII representation
        for byte in chunk {
            if *byte >= 32 && *byte <= 126 {
                line.push(*byte as char);
            } else {
                line.push('.');
            }
        }

        line.push('|');
        lines.push(line);
    }

    lines
}

/// Validates ELF structure
pub fn validate_elf_structure(data: &[u8]) -> Vec<String> {
    let mut issues = Vec::new();

    if data.len() < 64 {
        issues.push("File too small to be valid ELF".to_string());
        return issues;
    }

    // Check ELF magic
    if &data[0..4] != b"\x7fELF" {
        issues.push("Invalid ELF magic number".to_string());
    } else {
        issues.push("✓ Valid ELF magic".to_string());
    }

    // Check class
    let class = data[4];
    match class {
        1 => issues.push("✓ ELF32".to_string()),
        2 => issues.push("✓ ELF64".to_string()),
        _ => issues.push(format!("✗ Invalid ELF class: {}", class)),
    }

    // Check endianness
    let endian = data[5];
    match endian {
        1 => issues.push("✓ Little endian".to_string()),
        2 => issues.push("✓ Big endian".to_string()),
        _ => issues.push(format!("✗ Invalid endianness: {}", endian)),
    }

    issues
}

/// Extracts section names from shstrtab
pub fn get_section_name(data: &[u8], shstrtab_offset: usize, name_offset: usize) -> String {
    let start = shstrtab_offset + name_offset;
    if start >= data.len() {
        return format!("<invalid offset 0x{:x}>", name_offset);
    }

    let mut end = start;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }

    String::from_utf8_lossy(&data[start..end]).to_string()
}

/// Debug macro for conditional logging
#[macro_export]
macro_rules! debug_log {
    ($enabled:expr, $($arg:tt)*) => {
        if $enabled {
            eprintln!("[DEBUG] {}", format!($($arg)*));
        }
    };
}
