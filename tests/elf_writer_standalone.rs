// Standalone integration tests for ELF writer
// These tests do not require patchelf and validate goblin's writer independently

use goblin::elf::Elf;
use goblin::elf::dynamic::*;
use goblin::elf::writer::ElfWriter;
use std::fs;
use std::process::Command;

/// Test helper to create a test binary
fn create_test_binary(name: &str, rpath: &str) -> Result<String, Box<dyn std::error::Error>> {
    let source = format!("/tmp/test_{}.c", name);
    let binary = format!("/tmp/test_{}", name);

    fs::write(
        &source,
        r#"
#include <stdio.h>
int main() {
    printf("Test binary\n");
    return 0;
}
"#,
    )?;

    let output = Command::new("gcc")
        .args(&["-o", &binary, &source, &format!("-Wl,-rpath,{}", rpath)])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Failed to compile: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(binary)
}

/// Get RUNPATH from ELF binary
fn get_runpath(data: &[u8]) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let elf = Elf::parse(data)?;

    if let Some(ref dynamic) = elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == DT_RUNPATH {
                if let Some(path) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    return Ok(Some(path.to_string()));
                }
            } else if dyn_entry.d_tag == DT_RPATH {
                if let Some(path) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    return Ok(Some(path.to_string()));
                }
            }
        }
    }

    Ok(None)
}

#[test]
fn test_set_runpath_shorter() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("runpath_short_sa", "/original/long/path")?;
    let output_path = format!("{}.modified", input);

    // Read and modify
    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_runpath("/short")?;
    let output = writer.write()?;
    fs::write(&output_path, &output)?;

    // Verify the path was changed
    let new_runpath = get_runpath(&output)?.expect("RUNPATH should exist");
    assert_eq!(new_runpath, "/short");

    // Verify binary still parses
    let _ = Elf::parse(&output)?;

    println!("✓ test_set_runpath_shorter: RUNPATH changed from /original/long/path to /short");

    Ok(())
}

#[test]
fn test_set_runpath_same_length() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("runpath_same_sa", "/original/path")?;
    let output_path = format!("{}.modified", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_runpath("/another/path")?;
    let output = writer.write()?;
    fs::write(&output_path, &output)?;

    let new_runpath = get_runpath(&output)?.expect("RUNPATH should exist");
    assert_eq!(new_runpath, "/another/path");

    let _ = Elf::parse(&output)?;

    println!("✓ test_set_runpath_same_length: RUNPATH changed to /another/path");

    Ok(())
}

#[test]
fn test_set_runpath_with_slack() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("runpath_slack_sa", "/short")?;
    let output_path = format!("{}.modified", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;

    // Get original string table size for comparison
    let original_strtab_size = if let Some(ref dynamic) = elf.dynamic {
        dynamic
            .dyns
            .iter()
            .find(|e| e.d_tag == DT_STRSZ)
            .map(|e| e.d_val as usize)
            .unwrap_or(0)
    } else {
        0
    };

    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_runpath("/usr/local/lib")?;
    let output = writer.write()?;
    fs::write(&output_path, &output)?;

    let new_runpath = get_runpath(&output)?.expect("RUNPATH should exist");
    assert_eq!(new_runpath, "/usr/local/lib");

    let _ = Elf::parse(&output)?;

    println!(
        "✓ test_set_runpath_with_slack: RUNPATH changed to /usr/local/lib (original strtab: {} bytes)",
        original_strtab_size
    );

    Ok(())
}

#[test]
fn test_remove_runpath() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("remove_runpath_sa", "/some/path")?;
    let output_path = format!("{}.modified", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;

    // Verify it has RUNPATH before
    assert!(get_runpath(&data)?.is_some());

    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.remove_runpath()?;
    let output = writer.write()?;
    fs::write(&output_path, &output)?;

    // Verify RUNPATH was removed
    let new_runpath = get_runpath(&output)?;
    assert!(new_runpath.is_none(), "RUNPATH should be removed");

    let _ = Elf::parse(&output)?;

    println!("✓ test_remove_runpath: RUNPATH successfully removed");

    Ok(())
}

#[test]
fn test_execution_after_modification() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("exec_test_sa", "/original")?;
    let output_path = format!("{}.modified", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_runpath("/new/path")?;
    let output = writer.write()?;
    fs::write(&output_path, &output)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&output_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&output_path, perms)?;
    }

    // Try to execute
    let result = Command::new(&output_path).output()?;

    if !result.status.success() {
        return Err(format!(
            "Modified binary failed to execute: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }

    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("Test binary"));

    println!("✓ test_execution_after_modification: Modified binary executes successfully");

    Ok(())
}

#[test]
fn test_rpath_to_runpath_conversion() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("rpath_convert_sa", "/test/path")?;
    let output_path = format!("{}.modified", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.rpath_to_runpath()?;
    let output = writer.write()?;
    fs::write(&output_path, &output)?;

    // Verify conversion happened
    let elf_out = Elf::parse(&output)?;
    if let Some(ref dynamic) = elf_out.dynamic {
        let has_runpath = dynamic.dyns.iter().any(|e| e.d_tag == DT_RUNPATH);
        let has_rpath = dynamic.dyns.iter().any(|e| e.d_tag == DT_RPATH);

        assert!(has_runpath, "Should have RUNPATH after conversion");
        assert!(!has_rpath, "Should not have RPATH after conversion");
    }

    println!("✓ test_rpath_to_runpath_conversion: Successfully converted RPATH to RUNPATH");

    Ok(())
}

#[test]
fn test_multiple_modifications() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("multi_mod_sa", "/original/path")?;
    let output_path = format!("{}.modified", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;

    // Multiple modifications
    writer.set_runpath("/first/path")?;
    writer.set_soname("libtest.so.1")?;

    let output = writer.write()?;
    fs::write(&output_path, &output)?;

    // Verify both changes
    let elf_out = Elf::parse(&output)?;
    let runpath = get_runpath(&output)?.expect("RUNPATH should exist");
    assert_eq!(runpath, "/first/path");

    // Verify SONAME
    if let Some(ref dynamic) = elf_out.dynamic {
        let soname = dynamic
            .dyns
            .iter()
            .find(|e| e.d_tag == DT_SONAME)
            .and_then(|e| elf_out.dynstrtab.get_at(e.d_val as usize));
        assert_eq!(soname, Some("libtest.so.1"));
    }

    println!("✓ test_multiple_modifications: Multiple modifications applied successfully");

    Ok(())
}
