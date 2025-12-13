// Debug tool to analyze ELF writer behavior
// Usage: cargo run --example debug_relocation <input> <new-rpath>

use goblin::elf::Elf;
use goblin::elf::writer::ElfWriter;
use goblin::elf::writer_debug;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <input-elf> <new-rpath>", args[0]);
        eprintln!();
        eprintln!("This tool provides detailed debugging output for ELF modifications.");
        std::process::exit(1);
    }

    let input_path = &args[1];
    let new_rpath = &args[2];

    println!("=== ELF Writer Debug Tool ===\n");
    println!("Input: {}", input_path);
    println!("New RPATH: {}\n", new_rpath);

    // Read and parse
    println!("Step 1: Reading input file...");
    let data = fs::read(input_path)?;
    println!("  File size: {} bytes", data.len());

    println!("\nStep 2: Validating ELF structure...");
    let validation = writer_debug::validate_elf_structure(&data);
    for issue in &validation {
        println!("  {}", issue);
    }

    println!("\nStep 3: Parsing ELF...");
    let elf = Elf::parse(&data)?;
    println!("  ✓ Parsed successfully");
    println!("  Architecture: {}-bit", if elf.is_64 { 64 } else { 32 });
    println!(
        "  Endianness: {}",
        if elf.little_endian { "little" } else { "big" }
    );
    println!("  Program headers: {}", elf.program_headers.len());
    println!("  Section headers: {}", elf.section_headers.len());

    // Show current RPATH/RUNPATH
    println!("\nStep 4: Current dynamic paths:");
    if let Some(ref dynamic) = elf.dynamic {
        let mut found = false;
        for entry in &dynamic.dyns {
            if entry.d_tag == goblin::elf::dynamic::DT_RPATH {
                if let Some(path) = elf.dynstrtab.get_at(entry.d_val as usize) {
                    println!("  RPATH: {}", path);
                    found = true;
                }
            } else if entry.d_tag == goblin::elf::dynamic::DT_RUNPATH {
                if let Some(path) = elf.dynstrtab.get_at(entry.d_val as usize) {
                    println!("  RUNPATH: {}", path);
                    found = true;
                }
            }
        }
        if !found {
            println!("  (none)");
        }
    }

    // Show dynamic string table info
    println!("\nStep 5: Dynamic string table info:");
    if let Some(ref dynamic) = elf.dynamic {
        println!("  Offset: 0x{:x}", dynamic.info.strtab);
        println!("  Size: {} bytes", dynamic.info.strsz);

        // Find section header for dynstr
        for (idx, section) in elf.section_headers.iter().enumerate() {
            if section.sh_type == goblin::elf::section_header::SHT_STRTAB
                && section.sh_offset as usize == dynamic.info.strtab
            {
                println!("  Section index: {}", idx);
                println!("  Section name offset: {}", section.sh_name);
                break;
            }
        }
    }

    println!("\nStep 6: Creating writer...");
    let mut writer = ElfWriter::new(&data, &elf)?;
    println!("  ✓ Writer created");

    println!("\nStep 7: Calculating space requirements...");
    let old_size = if let Some(ref dynamic) = elf.dynamic {
        dynamic.info.strsz
    } else {
        0
    };
    let new_size = old_size + new_rpath.len() + 1; // +1 for null terminator
    let growth = new_size.saturating_sub(old_size);

    println!("  Old string table: {} bytes", old_size);
    println!(
        "  New string needed: {} bytes ({})",
        new_rpath.len() + 1,
        new_rpath
    );
    println!("  Growth required: {} bytes", growth);

    // Check slack space
    println!("\nStep 8: Checking for slack space...");
    // We'll need to add a method to expose this
    println!("  (Use readelf to manually check section offsets)");

    println!("\nStep 9: Modifying RUNPATH...");
    writer.set_runpath(new_rpath)?;
    println!("  ✓ Modification applied");

    println!("\nStep 10: Writing output...");
    let output = writer.write()?;
    println!("  ✓ Output generated: {} bytes", output.len());

    let output_path = format!("{}.debug", input_path);
    fs::write(&output_path, &output)?;
    println!("  ✓ Saved to: {}", output_path);

    // Validate output
    println!("\nStep 11: Validating output...");
    let output_validation = writer_debug::validate_elf_structure(&output);
    for issue in &output_validation {
        println!("  {}", issue);
    }

    // Try to parse output
    println!("\nStep 12: Parsing output ELF...");
    match Elf::parse(&output) {
        Ok(output_elf) => {
            println!("  ✓ Output parses successfully");

            // Check RUNPATH was set
            if let Some(ref dynamic) = output_elf.dynamic {
                for entry in &dynamic.dyns {
                    if entry.d_tag == goblin::elf::dynamic::DT_RUNPATH {
                        if let Some(path) = output_elf.dynstrtab.get_at(entry.d_val as usize) {
                            println!("  ✓ New RUNPATH: {}", path);
                            if path == new_rpath {
                                println!("  ✓ RUNPATH matches expected value");
                            } else {
                                println!("  ✗ RUNPATH mismatch!");
                                println!("    Expected: {}", new_rpath);
                                println!("    Got: {}", path);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("  ✗ Failed to parse output: {}", e);
            println!("\n  This indicates the output is corrupted!");
        }
    }

    // Compare input and output
    println!("\nStep 13: Comparing input vs output...");
    let size_diff = output.len() as i64 - data.len() as i64;
    if size_diff == 0 {
        println!("  Same size: {} bytes", output.len());
    } else {
        println!(
            "  Size changed: {} -> {} bytes ({:+} bytes)",
            data.len(),
            output.len(),
            size_diff
        );
    }

    // Show hex dump around dynstr
    if let Some(ref dynamic) = elf.dynamic {
        println!("\nStep 14: Hex dump of dynamic string table area:");
        let offset = dynamic.info.strtab;
        let size = dynamic.info.strsz.min(256); // Limit to 256 bytes

        println!("\n--- Original ---");
        for line in writer_debug::hex_dump(&data, offset, size, "Original .dynstr") {
            println!("{}", line);
        }

        println!("\n--- Modified ---");
        for line in writer_debug::hex_dump(&output, offset, size, "Modified .dynstr") {
            println!("{}", line);
        }
    }

    println!("\n=== Debug Complete ===");
    println!("\nNext steps:");
    println!("  1. Check output with: readelf -d {}", output_path);
    println!(
        "  2. Compare sections: readelf -S {} vs readelf -S {}",
        input_path, output_path
    );
    println!(
        "  3. Try to execute: chmod +x {} && {}",
        output_path, output_path
    );
    println!(
        "  4. Compare with patchelf: patchelf --set-rpath {} {} --output {}.patchelf",
        new_rpath, input_path, input_path
    );

    Ok(())
}
