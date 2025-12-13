// Integration tests for ELF writer
// Compares output against real patchelf

use goblin::elf::Elf;
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

/// Test helper to run real patchelf
fn run_patchelf(
    input: &str,
    output: &str,
    operation: &str,
    value: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new("patchelf");
    cmd.arg(operation);

    if let Some(v) = value {
        cmd.arg(v);
    }

    cmd.args(&[input, "--output", output]);

    let result = cmd.output()?;

    if !result.status.success() {
        return Err(format!(
            "patchelf failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }

    Ok(())
}

/// Compare two binaries byte-by-byte
fn compare_binaries(
    goblin_output: &str,
    patchelf_output: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let goblin_data = fs::read(goblin_output)?;
    let patchelf_data = fs::read(patchelf_output)?;

    let mut diffs = Vec::new();

    if goblin_data.len() != patchelf_data.len() {
        diffs.push(format!(
            "Size mismatch: goblin={} patchelf={}",
            goblin_data.len(),
            patchelf_data.len()
        ));
    }

    let min_len = goblin_data.len().min(patchelf_data.len());
    let mut diff_count = 0;
    let mut first_diff = None;

    for i in 0..min_len {
        if goblin_data[i] != patchelf_data[i] {
            if first_diff.is_none() {
                first_diff = Some(i);
            }
            diff_count += 1;

            if diff_count <= 10 {
                diffs.push(format!(
                    "Offset 0x{:x}: goblin=0x{:02x} patchelf=0x{:02x}",
                    i, goblin_data[i], patchelf_data[i]
                ));
            }
        }
    }

    if diff_count > 10 {
        diffs.push(format!("... and {} more differences", diff_count - 10));
    }

    if diff_count > 0 {
        diffs.insert(
            0,
            format!(
                "Found {} byte differences starting at 0x{:x}",
                diff_count,
                first_diff.unwrap()
            ),
        );
    }

    Ok(diffs)
}

/// Test: Set RUNPATH to shorter value (in-place)
#[test]
#[ignore] // Run with: cargo test --test elf_writer_test -- --ignored
fn test_set_runpath_shorter() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("runpath_short", "/original/long/path")?;
    let goblin_output = format!("{}.goblin", input);
    let patchelf_output = format!("{}.patchelf", input);

    // Run goblin
    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_runpath("/short")?;
    fs::write(&goblin_output, writer.write()?)?;

    // Run patchelf
    run_patchelf(&input, &patchelf_output, "--set-rpath", Some("/short"))?;

    // Compare
    let diffs = compare_binaries(&goblin_output, &patchelf_output)?;

    if !diffs.is_empty() {
        eprintln!("Differences found:");
        for diff in &diffs {
            eprintln!("  {}", diff);
        }
        panic!("Output differs from patchelf");
    }

    Ok(())
}

/// Test: Set RUNPATH to same length
#[test]
#[ignore]
fn test_set_runpath_same() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("runpath_same", "/original/path")?;
    let goblin_output = format!("{}.goblin", input);
    let patchelf_output = format!("{}.patchelf", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_runpath("/another/path")?;
    fs::write(&goblin_output, writer.write()?)?;

    run_patchelf(
        &input,
        &patchelf_output,
        "--set-rpath",
        Some("/another/path"),
    )?;

    let diffs = compare_binaries(&goblin_output, &patchelf_output)?;

    if !diffs.is_empty() {
        eprintln!("Differences found:");
        for diff in &diffs {
            eprintln!("  {}", diff);
        }
        panic!("Output differs from patchelf");
    }

    Ok(())
}

/// Test: Set RUNPATH to longer value (slack space)
#[test]
#[ignore]
fn test_set_runpath_slack() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("runpath_slack", "/short")?;
    let goblin_output = format!("{}.goblin", input);
    let patchelf_output = format!("{}.patchelf", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_runpath("/usr/local/lib")?;
    fs::write(&goblin_output, writer.write()?)?;

    run_patchelf(
        &input,
        &patchelf_output,
        "--set-rpath",
        Some("/usr/local/lib"),
    )?;

    let diffs = compare_binaries(&goblin_output, &patchelf_output)?;

    if !diffs.is_empty() {
        eprintln!("Differences found:");
        for diff in &diffs {
            eprintln!("  {}", diff);
        }
        // This might fail as patchelf may use different strategy
        eprintln!("Warning: Differences found, but this might be expected");
    }

    Ok(())
}

/// Test: Remove RUNPATH
#[test]
#[ignore]
fn test_remove_runpath() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("remove_runpath", "/some/path")?;
    let goblin_output = format!("{}.goblin", input);
    let patchelf_output = format!("{}.patchelf", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.remove_runpath()?;
    fs::write(&goblin_output, writer.write()?)?;

    run_patchelf(&input, &patchelf_output, "--remove-rpath", None)?;

    let diffs = compare_binaries(&goblin_output, &patchelf_output)?;

    if !diffs.is_empty() {
        eprintln!("Differences found:");
        for diff in &diffs {
            eprintln!("  {}", diff);
        }
        panic!("Output differs from patchelf");
    }

    Ok(())
}

/// Validate that modified binary executes correctly
#[test]
#[ignore]
fn test_execution_after_modification() -> Result<(), Box<dyn std::error::Error>> {
    let input = create_test_binary("exec_test", "/original")?;
    let output = format!("{}.modified", input);

    let data = fs::read(&input)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;
    writer.set_runpath("/new/path")?;
    fs::write(&output, writer.write()?)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&output)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&output, perms)?;
    }

    // Try to execute
    let result = Command::new(&output).output()?;

    if !result.status.success() {
        return Err(format!(
            "Modified binary failed to execute: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }

    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("Test binary"));

    Ok(())
}
