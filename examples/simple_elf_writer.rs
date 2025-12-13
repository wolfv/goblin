// This example demonstrates the basic usage of the ELF writer API
//
// Usage:
//   cargo run --example simple_elf_writer <input> <output> <new_runpath>
//
// Example:
//   cargo run --example simple_elf_writer /bin/ls /tmp/ls_modified /custom/lib/path

use goblin::elf::Elf;
use goblin::elf::writer::ElfWriter;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: {} <input> <output> <new_runpath>", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} ./binary ./binary.modified /new/lib/path", args[0]);
        std::process::exit(1);
    }

    let input_path = &args[1];
    let output_path = &args[2];
    let new_runpath = &args[3];

    println!("Reading: {}", input_path);
    let data = fs::read(input_path)?;

    println!("Parsing ELF...");
    let elf = Elf::parse(&data)?;

    println!("Creating writer...");
    let mut writer = ElfWriter::new(&data, &elf)?;

    // Print current RUNPATH if it exists
    if let Some(ref dynamic) = elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == goblin::elf::dynamic::DT_RUNPATH {
                if let Some(runpath) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    println!("Current RUNPATH: {}", runpath);
                }
            } else if dyn_entry.d_tag == goblin::elf::dynamic::DT_RPATH {
                if let Some(rpath) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    println!("Current RPATH: {}", rpath);
                }
            }
        }
    }

    println!("Setting RUNPATH to: {}", new_runpath);
    writer.set_runpath(new_runpath)?;

    println!("Writing modified binary to: {}", output_path);
    let output = writer.write()?;
    fs::write(output_path, output)?;

    println!("Done! Binary modified successfully.");
    println!();
    println!("Verify with: readelf -d {}", output_path);

    Ok(())
}
