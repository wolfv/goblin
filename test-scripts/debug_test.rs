use goblin::elf::Elf;
use goblin::elf::writer::ElfWriter;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read("/tmp/claude/patchelf-compare/test_binary")?;
    let elf = Elf::parse(&data)?;

    println!("Original dynstrtab around offset 0x28:");
    let strtab_offset = elf.dynamic.as_ref().unwrap().info.strtab;
    let strtab_size = elf.dynamic.as_ref().unwrap().info.strsz;
    println!("  strtab_offset: 0x{:x}", strtab_offset);
    println!("  strtab_size: {}", strtab_size);

    // Print bytes 0x28-0x40 of dynstrtab
    for i in 0x28..0x40 {
        print!("{:02x} ", data[strtab_offset + i]);
    }
    println!();

    // Print as string
    let s = std::str::from_utf8(&data[strtab_offset + 0x28..strtab_offset + 0x37]).unwrap();
    println!("  String at 0x28: {:?}", s);

    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_rpath("/new/path")?;

    let output = writer.write()?;

    println!("\nAfter modification:");
    // Print bytes 0x28-0x40 of dynstrtab in output
    for i in 0x28..0x40 {
        print!("{:02x} ", output[strtab_offset + i]);
    }
    println!();

    // Also show as chars
    for i in 0x28..0x40 {
        let b = output[strtab_offset + i];
        if b >= 0x20 && b < 0x7f {
            print!("{} ", b as char);
        } else {
            print!(". ");
        }
    }
    println!();

    fs::write("/tmp/claude/patchelf-compare/test_debug_out", output)?;

    Ok(())
}
