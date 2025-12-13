//! A patchelf-like CLI tool using goblin's ELF rewriting capabilities
//!
//! This is used for testing byte-for-byte compatibility with patchelf.

use goblin::elf::rewrite::ElfMut;
use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} [options] <elf-file>", args[0]);
        eprintln!("Options:");
        eprintln!("  --print-interpreter     Print current interpreter");
        eprintln!("  --set-interpreter PATH  Set new interpreter");
        eprintln!("  --print-rpath           Print current RPATH");
        eprintln!("  --print-runpath         Print current RUNPATH");
        eprintln!("  --set-rpath PATH        Set new RPATH");
        eprintln!("  --set-runpath PATH      Set new RUNPATH");
        eprintln!("  --print-needed          Print needed libraries");
        eprintln!("  --add-needed LIB        Add needed library");
        eprintln!("  --remove-needed LIB     Remove needed library");
        eprintln!("  --replace-needed OLD=NEW Replace needed library");
        eprintln!("  --output FILE           Write to FILE instead of modifying in place");
        std::process::exit(1);
    }

    let mut input_file: Option<PathBuf> = None;
    let mut output_file: Option<PathBuf> = None;
    let mut operations: Vec<Operation> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--print-interpreter" => {
                operations.push(Operation::PrintInterpreter);
            }
            "--set-interpreter" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--set-interpreter requires an argument");
                    std::process::exit(1);
                }
                operations.push(Operation::SetInterpreter(args[i].clone()));
            }
            "--print-rpath" => {
                operations.push(Operation::PrintRpath);
            }
            "--print-runpath" => {
                operations.push(Operation::PrintRunpath);
            }
            "--set-rpath" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--set-rpath requires an argument");
                    std::process::exit(1);
                }
                operations.push(Operation::SetRpath(args[i].clone()));
            }
            "--set-runpath" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--set-runpath requires an argument");
                    std::process::exit(1);
                }
                operations.push(Operation::SetRunpath(args[i].clone()));
            }
            "--print-needed" => {
                operations.push(Operation::PrintNeeded);
            }
            "--add-needed" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--add-needed requires an argument");
                    std::process::exit(1);
                }
                operations.push(Operation::AddNeeded(args[i].clone()));
            }
            "--remove-needed" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--remove-needed requires an argument");
                    std::process::exit(1);
                }
                operations.push(Operation::RemoveNeeded(args[i].clone()));
            }
            "--replace-needed" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--replace-needed requires an argument (OLD=NEW)");
                    std::process::exit(1);
                }
                let parts: Vec<&str> = args[i].splitn(2, '=').collect();
                if parts.len() != 2 {
                    eprintln!("--replace-needed argument must be OLD=NEW");
                    std::process::exit(1);
                }
                operations.push(Operation::ReplaceNeeded(
                    parts[0].to_string(),
                    parts[1].to_string(),
                ));
            }
            "--output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--output requires an argument");
                    std::process::exit(1);
                }
                output_file = Some(PathBuf::from(&args[i]));
            }
            arg if !arg.starts_with('-') => {
                if input_file.is_some() {
                    eprintln!("Multiple input files specified");
                    std::process::exit(1);
                }
                input_file = Some(PathBuf::from(arg));
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let input_file = match input_file {
        Some(f) => f,
        None => {
            eprintln!("No input file specified");
            std::process::exit(1);
        }
    };

    // Read the ELF file
    let data = match fs::read(&input_file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", input_file.display(), e);
            std::process::exit(1);
        }
    };

    let mut elf = match ElfMut::parse(&data) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error parsing ELF: {}", e);
            std::process::exit(1);
        }
    };

    let mut modified = false;

    // Execute operations
    for op in operations {
        match op {
            Operation::PrintInterpreter => {
                if let Some(interp) = elf.get_interpreter() {
                    println!("{}", interp);
                }
            }
            Operation::SetInterpreter(path) => {
                if let Err(e) = elf.set_interpreter(&path) {
                    eprintln!("Error setting interpreter: {}", e);
                    std::process::exit(1);
                }
                modified = true;
            }
            Operation::PrintRpath => {
                if let Ok(paths) = elf.get_rpath() {
                    if !paths.is_empty() {
                        println!("{}", paths.join(":"));
                    }
                }
            }
            Operation::PrintRunpath => {
                if let Ok(paths) = elf.get_runpath() {
                    if !paths.is_empty() {
                        println!("{}", paths.join(":"));
                    }
                }
            }
            Operation::SetRpath(path) => {
                if let Err(e) = elf.set_rpath(&path) {
                    eprintln!("Error setting rpath: {}", e);
                    std::process::exit(1);
                }
                modified = true;
            }
            Operation::SetRunpath(path) => {
                if let Err(e) = elf.set_runpath(&path) {
                    eprintln!("Error setting runpath: {}", e);
                    std::process::exit(1);
                }
                modified = true;
            }
            Operation::PrintNeeded => {
                if let Ok(libs) = elf.get_needed() {
                    for lib in libs {
                        println!("{}", lib);
                    }
                }
            }
            Operation::AddNeeded(lib) => {
                if let Err(e) = elf.add_needed(&[lib.as_str()]) {
                    eprintln!("Error adding needed: {}", e);
                    std::process::exit(1);
                }
                modified = true;
            }
            Operation::RemoveNeeded(lib) => {
                if let Err(e) = elf.remove_needed(&[lib.as_str()]) {
                    eprintln!("Error removing needed: {}", e);
                    std::process::exit(1);
                }
                modified = true;
            }
            Operation::ReplaceNeeded(old, new) => {
                if let Err(e) = elf.replace_needed(&[(&old, &new)]) {
                    eprintln!("Error replacing needed: {}", e);
                    std::process::exit(1);
                }
                modified = true;
            }
        }
    }

    // Write output if modified
    if modified {
        let output = match elf.write() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Error writing ELF: {}", e);
                std::process::exit(1);
            }
        };

        let output_path = output_file.as_ref().unwrap_or(&input_file);
        if let Err(e) = fs::write(output_path, output) {
            eprintln!("Error writing {}: {}", output_path.display(), e);
            std::process::exit(1);
        }
    }
}

enum Operation {
    PrintInterpreter,
    SetInterpreter(String),
    PrintRpath,
    PrintRunpath,
    SetRpath(String),
    SetRunpath(String),
    PrintNeeded,
    AddNeeded(String),
    RemoveNeeded(String),
    ReplaceNeeded(String, String),
}
