//! ELF rewriting module - patchelf-compatible ELF modification
//!
//! This module provides the ability to modify ELF files in ways similar to patchelf:
//! - Set interpreter path
//! - Set/modify RPATH/RUNPATH
//! - Add/remove needed libraries
//!
//! The goal is byte-for-byte identical output to patchelf.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp;
use scroll::{ctx::SizeWith, Pread, Pwrite};

use crate::container::{Container, Ctx};
use crate::elf::dynamic::{
    Dyn, DT_GNU_HASH, DT_HASH, DT_JMPREL, DT_NEEDED, DT_NULL, DT_RELA, DT_RELASZ,
    DT_REL, DT_RELSZ, DT_RPATH, DT_RUNPATH, DT_STRSZ, DT_STRTAB, DT_SYMTAB, DT_VERDEF,
    DT_VERNEED, DT_VERSYM,
};
use crate::elf::header::{Header, EM_AARCH64, EM_FAKE_ALPHA,
    EM_IA_64, EM_LOONGARCH, EM_MIPS, EM_PPC, EM_PPC64, EM_SPARC, EM_SPARCV9, ET_DYN, ET_EXEC};
use crate::elf::program_header::{
    ProgramHeader, PF_R, PF_W, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_NOTE, PT_PHDR,
};
use crate::elf::section_header::{SectionHeader, SHT_NOTE, SHT_NOBITS, SHT_PROGBITS};
use crate::error::{Error, Result};

/// Page size configuration for different architectures
pub struct PageSize;

impl PageSize {
    /// Get the page size for a given machine type
    pub fn for_machine(machine: u16) -> u64 {
        match machine {
            EM_FAKE_ALPHA | EM_IA_64 | EM_MIPS | EM_PPC | EM_PPC64 | EM_AARCH64 | EM_LOONGARCH => {
                0x10000
            } // 64KB
            EM_SPARC | EM_SPARCV9 => 0x2000, // 8KB (Solaris compat)
            _ => 0x1000,                      // 4KB default
        }
    }
}

/// Round up a value to a multiple of alignment
#[inline]
pub fn round_up(n: u64, m: u64) -> u64 {
    if m == 0 {
        n
    } else {
        ((n + m - 1) / m) * m
    }
}

/// Get section alignment based on ELF class (4 for 32-bit, 8 for 64-bit)
#[inline]
fn section_alignment(ctx: Ctx) -> u64 {
    match ctx.container {
        Container::Little => 4, // 32-bit
        Container::Big => 8,    // 64-bit
    }
}

/// A mutable ELF structure for modification
///
/// This is the main type for ELF modification operations. It owns the file
/// contents and tracks modifications to sections before writing them out.
pub struct ElfMut {
    /// The mutable file contents
    pub contents: Vec<u8>,
    /// ELF header
    pub header: Header,
    /// Program headers
    pub program_headers: Vec<ProgramHeader>,
    /// Section headers
    pub section_headers: Vec<SectionHeader>,
    /// Section header string table
    shstrtab: Vec<u8>,
    /// Map of section name -> replacement contents
    replaced_sections: BTreeMap<String, Vec<u8>>,
    /// Context for serialization (container type + endianness)
    ctx: Ctx,
    /// Whether changes have been made
    changed: bool,
    /// Original section indices before sorting (old_idx -> new_idx mapping)
    section_index_map: Vec<usize>,
}

impl ElfMut {
    /// Parse an ELF file from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header: Header = data.pread(0)?;
        let ctx = Ctx {
            le: header.endianness()?,
            container: header.container()?,
        };

        let program_headers = ProgramHeader::parse(
            data,
            header.e_phoff as usize,
            header.e_phnum as usize,
            ctx,
        )?;

        let section_headers = SectionHeader::parse(
            data,
            header.e_shoff as usize,
            header.e_shnum as usize,
            ctx,
        )?;

        // Read section header string table
        let shstrtab = if header.e_shstrndx > 0 && (header.e_shstrndx as usize) < section_headers.len() {
            let shdr = &section_headers[header.e_shstrndx as usize];
            let offset = shdr.sh_offset as usize;
            let size = shdr.sh_size as usize;
            if offset + size <= data.len() {
                data[offset..offset + size].to_vec()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        // Initialize section index map as identity
        let section_index_map: Vec<usize> = (0..section_headers.len()).collect();

        Ok(ElfMut {
            contents: data.to_vec(),
            header,
            program_headers,
            section_headers,
            shstrtab,
            replaced_sections: BTreeMap::new(),
            ctx,
            changed: false,
            section_index_map,
        })
    }

    /// Get the current interpreter path, if any
    pub fn get_interpreter(&self) -> Option<String> {
        self.find_section(".interp").ok().map(|shdr| {
            let offset = shdr.sh_offset as usize;
            let size = shdr.sh_size as usize;
            if offset + size <= self.contents.len() && size > 0 {
                // Exclude null terminator
                let end = offset + size - 1;
                String::from_utf8_lossy(&self.contents[offset..end]).to_string()
            } else {
                String::new()
            }
        })
    }

    /// Set the interpreter path
    ///
    /// Like patchelf, this always performs a full section rewrite (no in-place updates)
    /// to ensure byte-for-byte compatibility.
    pub fn set_interpreter(&mut self, new_interp: &str) -> Result<()> {
        // Check if current interpreter matches - return early if so (like patchelf)
        if let Some(current) = self.get_interpreter() {
            if current == new_interp {
                return Ok(());
            }
        }

        // Always use section replacement (matching patchelf behavior)
        let new_size = new_interp.len() + 1;
        let section = self.replace_section(".interp", new_size)?;
        section[..new_interp.len()].copy_from_slice(new_interp.as_bytes());
        section[new_interp.len()] = 0;

        self.changed = true;
        Ok(())
    }

    /// Get the current RPATH entries
    pub fn get_rpath(&self) -> Result<Vec<String>> {
        self.get_rpath_or_runpath(DT_RPATH)
    }

    /// Get the current RUNPATH entries
    pub fn get_runpath(&self) -> Result<Vec<String>> {
        self.get_rpath_or_runpath(DT_RUNPATH)
    }

    fn get_rpath_or_runpath(&self, tag: u64) -> Result<Vec<String>> {
        let dynstr_shdr = self.find_section(".dynstr")?;
        let dynstr_offset = dynstr_shdr.sh_offset as usize;
        let dynstr_size = dynstr_shdr.sh_size as usize;

        if dynstr_offset + dynstr_size > self.contents.len() {
            return Ok(vec![]);
        }

        let dynstr = &self.contents[dynstr_offset..dynstr_offset + dynstr_size];

        let dynamic_shdr = self.find_section(".dynamic")?;
        let dyn_entries = self.read_dynamic_entries(&dynamic_shdr)?;

        for entry in &dyn_entries {
            if entry.d_tag == tag {
                let str_offset = entry.d_val as usize;
                if str_offset < dynstr.len() {
                    let s = self.get_string_at(dynstr, str_offset);
                    return Ok(s.split(':').map(|p| p.to_string()).collect());
                }
            }
        }

        Ok(vec![])
    }

    /// Set the RUNPATH (preferred over RPATH)
    pub fn set_runpath(&mut self, new_path: &str) -> Result<()> {
        self.set_rpath_impl(new_path, false)
    }

    /// Set the RPATH (deprecated, use set_runpath unless needed)
    pub fn set_rpath(&mut self, new_path: &str) -> Result<()> {
        self.set_rpath_impl(new_path, true)
    }

    fn set_rpath_impl(&mut self, new_path: &str, force_rpath: bool) -> Result<()> {
        let tag = if force_rpath { DT_RPATH } else { DT_RUNPATH };
        let other_tag = if force_rpath { DT_RUNPATH } else { DT_RPATH };

        let dynstr_shdr = self.find_section(".dynstr")?;
        let dynamic_shdr = self.find_section(".dynamic")?;

        // Read existing dynamic entries
        let mut dyn_entries = self.read_dynamic_entries(&dynamic_shdr)?;

        // Find existing rpath/runpath entry
        let existing_idx = dyn_entries.iter().position(|e| e.d_tag == tag || e.d_tag == other_tag);

        // Get current rpath string offset and size if it exists
        let current_str_info = existing_idx.map(|idx| {
            let entry = &dyn_entries[idx];
            let str_offset = entry.d_val as usize;
            let dynstr_offset = dynstr_shdr.sh_offset as usize;
            let dynstr = &self.contents[dynstr_offset..dynstr_offset + dynstr_shdr.sh_size as usize];
            let current_str = self.get_string_at(dynstr, str_offset);
            (str_offset, current_str.len())
        });

        // Check if we can update in place
        if let Some((str_offset, current_len)) = current_str_info {
            if new_path.len() <= current_len {
                // Update in place
                let dynstr_offset = dynstr_shdr.sh_offset as usize;
                let target_offset = dynstr_offset + str_offset;

                // Write new path
                self.contents[target_offset..target_offset + new_path.len()]
                    .copy_from_slice(new_path.as_bytes());

                // Null-terminate and pad with zeros
                for i in new_path.len()..=current_len {
                    self.contents[target_offset + i] = 0;
                }

                // Update tag if needed (e.g., converting RPATH to RUNPATH)
                if let Some(idx) = existing_idx {
                    if dyn_entries[idx].d_tag != tag {
                        dyn_entries[idx].d_tag = tag;
                        self.write_dynamic_entries(&dynamic_shdr, &dyn_entries)?;
                    }
                }

                self.changed = true;
                return Ok(());
            }
        }

        // Need to extend .dynstr
        let old_dynstr_size = dynstr_shdr.sh_size as usize;
        let new_str_offset = old_dynstr_size;
        let new_dynstr_size = old_dynstr_size + new_path.len() + 1;

        // Replace .dynstr with extended version
        let new_dynstr = self.replace_section(".dynstr", new_dynstr_size)?;

        // Copy existing content (already done by replace_section)
        // Append new path
        new_dynstr[new_str_offset..new_str_offset + new_path.len()]
            .copy_from_slice(new_path.as_bytes());
        new_dynstr[new_str_offset + new_path.len()] = 0;

        // Update or add dynamic entry
        if let Some(idx) = existing_idx {
            dyn_entries[idx].d_tag = tag;
            dyn_entries[idx].d_val = new_str_offset as u64;
        } else {
            // Need to add new entry - find DT_NULL and insert before it
            if let Some(null_idx) = dyn_entries.iter().position(|e| e.d_tag == DT_NULL) {
                dyn_entries.insert(
                    null_idx,
                    Dyn {
                        d_tag: tag,
                        d_val: new_str_offset as u64,
                    },
                );
                // Need to grow .dynamic section
                let dyn_entry_size = Dyn::size_with(&self.ctx);
                let new_dynamic_size = dynamic_shdr.sh_size as usize + dyn_entry_size;
                let _ = self.replace_section(".dynamic", new_dynamic_size)?;
            }
        }

        // Mark dynamic section as replaced so entries get written during rewrite
        self.write_dynamic_entries_to_replaced(&dyn_entries)?;

        self.changed = true;
        Ok(())
    }

    /// Get list of needed libraries
    pub fn get_needed(&self) -> Result<Vec<String>> {
        let dynstr_shdr = self.find_section(".dynstr")?;
        let dynstr_offset = dynstr_shdr.sh_offset as usize;
        let dynstr_size = dynstr_shdr.sh_size as usize;

        if dynstr_offset + dynstr_size > self.contents.len() {
            return Ok(vec![]);
        }

        let dynstr = &self.contents[dynstr_offset..dynstr_offset + dynstr_size];

        let dynamic_shdr = self.find_section(".dynamic")?;
        let dyn_entries = self.read_dynamic_entries(&dynamic_shdr)?;

        let mut needed = Vec::new();
        for entry in &dyn_entries {
            if entry.d_tag == DT_NEEDED {
                let str_offset = entry.d_val as usize;
                if str_offset < dynstr.len() {
                    needed.push(self.get_string_at(dynstr, str_offset));
                }
            }
        }

        Ok(needed)
    }

    /// Add needed library dependencies
    pub fn add_needed(&mut self, libs: &[&str]) -> Result<()> {
        if libs.is_empty() {
            return Ok(());
        }

        let dynstr_shdr = self.find_section(".dynstr")?;
        let dynamic_shdr = self.find_section(".dynamic")?;

        // Calculate space needed in dynstr
        let total_str_len: usize = libs.iter().map(|s| s.len() + 1).sum();
        let old_dynstr_size = dynstr_shdr.sh_size as usize;
        let new_dynstr_size = old_dynstr_size + total_str_len;

        // Extend dynstr
        let new_dynstr = self.replace_section(".dynstr", new_dynstr_size)?;

        // Add strings and collect offsets
        let mut string_offsets = Vec::new();
        let mut pos = old_dynstr_size;
        for lib in libs {
            new_dynstr[pos..pos + lib.len()].copy_from_slice(lib.as_bytes());
            new_dynstr[pos + lib.len()] = 0;
            string_offsets.push(pos as u64);
            pos += lib.len() + 1;
        }

        // Read and modify dynamic entries
        let mut dyn_entries = self.read_dynamic_entries(&dynamic_shdr)?;

        // Find DT_NULL position
        let null_idx = dyn_entries
            .iter()
            .position(|e| e.d_tag == DT_NULL)
            .ok_or_else(|| Error::Malformed("No DT_NULL in dynamic section".to_string()))?;

        // Insert new DT_NEEDED entries before DT_NULL
        for &offset in string_offsets.iter().rev() {
            dyn_entries.insert(
                null_idx,
                Dyn {
                    d_tag: DT_NEEDED,
                    d_val: offset,
                },
            );
        }

        // Grow .dynamic section
        let dyn_entry_size = Dyn::size_with(&self.ctx);
        let new_dynamic_size = dyn_entries.len() * dyn_entry_size;
        let _ = self.replace_section(".dynamic", new_dynamic_size)?;

        // Write dynamic entries
        self.write_dynamic_entries_to_replaced(&dyn_entries)?;

        self.changed = true;
        Ok(())
    }

    /// Remove needed library dependencies
    pub fn remove_needed(&mut self, libs: &[&str]) -> Result<()> {
        if libs.is_empty() {
            return Ok(());
        }

        let dynstr_shdr = self.find_section(".dynstr")?;
        let dynstr_offset = dynstr_shdr.sh_offset as usize;
        let dynstr_size = dynstr_shdr.sh_size as usize;

        if dynstr_offset + dynstr_size > self.contents.len() {
            return Err(Error::Malformed("Invalid dynstr section".to_string()));
        }

        let dynstr = self.contents[dynstr_offset..dynstr_offset + dynstr_size].to_vec();

        let dynamic_shdr = self.find_section(".dynamic")?;
        let mut dyn_entries = self.read_dynamic_entries(&dynamic_shdr)?;

        // Filter out matching DT_NEEDED entries
        let lib_set: alloc::collections::BTreeSet<&str> = libs.iter().copied().collect();
        dyn_entries.retain(|entry| {
            if entry.d_tag != DT_NEEDED {
                return true;
            }
            let str_offset = entry.d_val as usize;
            if str_offset >= dynstr.len() {
                return true;
            }
            let name = self.get_string_at(&dynstr, str_offset);
            !lib_set.contains(name.as_str())
        });

        // Write back (keeping same size, zeroing removed entries)
        self.write_dynamic_entries_to_replaced(&dyn_entries)?;

        self.changed = true;
        Ok(())
    }

    /// Replace needed library dependencies
    pub fn replace_needed(&mut self, replacements: &[(&str, &str)]) -> Result<()> {
        if replacements.is_empty() {
            return Ok(());
        }

        let repl_map: BTreeMap<&str, &str> = replacements.iter().copied().collect();

        let dynstr_shdr = self.find_section(".dynstr")?;
        let dynstr_offset = dynstr_shdr.sh_offset as usize;
        let dynstr_size = dynstr_shdr.sh_size as usize;

        if dynstr_offset + dynstr_size > self.contents.len() {
            return Err(Error::Malformed("Invalid dynstr section".to_string()));
        }

        let dynstr = self.contents[dynstr_offset..dynstr_offset + dynstr_size].to_vec();

        let dynamic_shdr = self.find_section(".dynamic")?;
        let mut dyn_entries = self.read_dynamic_entries(&dynamic_shdr)?;

        // Find which libraries need replacement and calculate new string space
        let mut libs_to_add = Vec::new();
        for entry in &dyn_entries {
            if entry.d_tag == DT_NEEDED {
                let str_offset = entry.d_val as usize;
                if str_offset < dynstr.len() {
                    let name = self.get_string_at(&dynstr, str_offset);
                    if let Some(&new_name) = repl_map.get(name.as_str()) {
                        if new_name.len() > name.len() {
                            libs_to_add.push(new_name);
                        }
                    }
                }
            }
        }

        // Extend dynstr if needed
        let additional_len: usize = libs_to_add.iter().map(|s| s.len() + 1).sum();
        let mut new_string_offsets: BTreeMap<&str, u64> = BTreeMap::new();

        if additional_len > 0 {
            let new_dynstr_size = dynstr_size + additional_len;
            let new_dynstr = self.replace_section(".dynstr", new_dynstr_size)?;

            let mut pos = dynstr_size;
            for lib in &libs_to_add {
                new_string_offsets.insert(lib, pos as u64);
                new_dynstr[pos..pos + lib.len()].copy_from_slice(lib.as_bytes());
                new_dynstr[pos + lib.len()] = 0;
                pos += lib.len() + 1;
            }
        }

        // Update dynamic entries
        for entry in &mut dyn_entries {
            if entry.d_tag == DT_NEEDED {
                let str_offset = entry.d_val as usize;
                if str_offset < dynstr.len() {
                    let name = self.get_string_at(&dynstr, str_offset);
                    if let Some(&new_name) = repl_map.get(name.as_str()) {
                        if let Some(&new_offset) = new_string_offsets.get(new_name) {
                            entry.d_val = new_offset;
                        } else if new_name.len() <= name.len() {
                            // Can update in place
                            let target = dynstr_offset + str_offset;
                            self.contents[target..target + new_name.len()]
                                .copy_from_slice(new_name.as_bytes());
                            for i in new_name.len()..name.len() {
                                self.contents[target + i] = 0;
                            }
                        }
                    }
                }
            }
        }

        self.write_dynamic_entries_to_replaced(&dyn_entries)?;
        self.changed = true;
        Ok(())
    }

    /// Write the modified ELF back, applying all pending changes
    pub fn write(&mut self) -> Result<Vec<u8>> {
        if !self.changed && self.replaced_sections.is_empty() {
            return Ok(self.contents.clone());
        }

        // Rewrite sections if needed (this also rewrites headers)
        if !self.replaced_sections.is_empty() {
            self.rewrite_sections()?;
            // Write headers after section rewriting
            self.write_headers()?;
        }
        // For in-place changes (no section replacement), we don't need to rewrite headers

        Ok(self.contents.clone())
    }

    // ==================== Internal Methods ====================

    /// Find a section by name
    fn find_section(&self, name: &str) -> Result<SectionHeader> {
        for (idx, shdr) in self.section_headers.iter().enumerate() {
            if let Some(section_name) = self.get_section_name(idx) {
                if section_name == name {
                    return Ok(shdr.clone());
                }
            }
        }
        Err(Error::Malformed(format!("Section '{}' not found", name)))
    }

    /// Find a section index by name
    fn find_section_idx(&self, name: &str) -> Option<usize> {
        for (idx, _) in self.section_headers.iter().enumerate() {
            if let Some(section_name) = self.get_section_name(idx) {
                if section_name == name {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Get section name from string table
    fn get_section_name(&self, idx: usize) -> Option<String> {
        let shdr = self.section_headers.get(idx)?;
        let name_offset = shdr.sh_name as usize;
        if name_offset < self.shstrtab.len() {
            Some(self.get_string_at(&self.shstrtab, name_offset))
        } else {
            None
        }
    }

    /// Get a null-terminated string from a byte slice
    fn get_string_at(&self, data: &[u8], offset: usize) -> String {
        if offset >= data.len() {
            return String::new();
        }
        let end = data[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(data.len());
        String::from_utf8_lossy(&data[offset..end]).to_string()
    }

    /// Replace a section with new content
    fn replace_section(&mut self, name: &str, new_size: usize) -> Result<&mut Vec<u8>> {
        let shdr = self.find_section(name)?;

        // Get existing content or create from file
        let existing = if let Some(data) = self.replaced_sections.get(name) {
            data.clone()
        } else {
            let offset = shdr.sh_offset as usize;
            let size = shdr.sh_size as usize;
            if offset + size <= self.contents.len() {
                self.contents[offset..offset + size].to_vec()
            } else {
                vec![0; size]
            }
        };

        // Resize to new size (preserving existing content up to min)
        let mut new_content = vec![0u8; new_size];
        let copy_len = cmp::min(existing.len(), new_size);
        new_content[..copy_len].copy_from_slice(&existing[..copy_len]);

        self.replaced_sections.insert(name.to_string(), new_content);
        Ok(self.replaced_sections.get_mut(name).unwrap())
    }

    /// Read dynamic entries from a section
    fn read_dynamic_entries(&self, shdr: &SectionHeader) -> Result<Vec<Dyn>> {
        let data = if let Some(name) = self.find_section_name_by_header(shdr) {
            if let Some(replaced) = self.replaced_sections.get(&name) {
                replaced.as_slice()
            } else {
                let offset = shdr.sh_offset as usize;
                let size = shdr.sh_size as usize;
                &self.contents[offset..offset + size]
            }
        } else {
            let offset = shdr.sh_offset as usize;
            let size = shdr.sh_size as usize;
            &self.contents[offset..offset + size]
        };

        let dyn_size = Dyn::size_with(&self.ctx);
        let count = data.len() / dyn_size;
        let mut entries = Vec::with_capacity(count);

        let mut pos = 0;
        for _ in 0..count {
            let dyn_entry: Dyn = data.pread_with(pos, self.ctx)?;
            let is_null = dyn_entry.d_tag == DT_NULL;
            entries.push(dyn_entry);
            if is_null {
                break;
            }
            pos += dyn_size;
        }

        Ok(entries)
    }

    /// Find section name by matching header
    fn find_section_name_by_header(&self, target: &SectionHeader) -> Option<String> {
        for (idx, shdr) in self.section_headers.iter().enumerate() {
            if shdr.sh_offset == target.sh_offset && shdr.sh_size == target.sh_size {
                return self.get_section_name(idx);
            }
        }
        None
    }

    /// Write dynamic entries back to section in contents
    fn write_dynamic_entries(&mut self, shdr: &SectionHeader, entries: &[Dyn]) -> Result<()> {
        let dyn_size = Dyn::size_with(&self.ctx);
        let offset = shdr.sh_offset as usize;

        for (i, entry) in entries.iter().enumerate() {
            let pos = offset + i * dyn_size;
            self.contents.pwrite_with(entry.clone(), pos, self.ctx)?;
        }

        Ok(())
    }

    /// Write dynamic entries to the replaced sections map
    fn write_dynamic_entries_to_replaced(&mut self, entries: &[Dyn]) -> Result<()> {
        let ctx = self.ctx;
        let dyn_size = Dyn::size_with(&ctx);
        let total_size = entries.len() * dyn_size;

        // Get or create the .dynamic replacement
        let dynamic_data = self.replace_section(".dynamic", total_size)?;

        for (i, entry) in entries.iter().enumerate() {
            let pos = i * dyn_size;
            dynamic_data.pwrite_with(entry.clone(), pos, ctx)?;
        }

        Ok(())
    }

    /// Rewrite sections - main entry point for applying modifications
    fn rewrite_sections(&mut self) -> Result<()> {
        match self.header.e_type {
            ET_DYN => self.rewrite_sections_library(),
            ET_EXEC => self.rewrite_sections_executable(),
            _ => Err(Error::Malformed(format!(
                "Unsupported ELF type for rewriting: {}",
                self.header.e_type
            ))),
        }
    }

    /// Rewrite sections for shared libraries (append at end)
    ///
    /// Matches patchelf's rewriteSectionsLibrary() behavior:
    /// 1. Replace sections that are "in the way" of the program header table
    /// 2. Normalize note segments BEFORE updating section offsets
    /// 3. Calculate new section positions
    /// 4. Add PT_LOAD for new region
    /// 5. Write all replaced sections at new positions
    fn rewrite_sections_library(&mut self) -> Result<()> {
        let page_size = PageSize::for_machine(self.header.e_machine);
        let section_align = section_alignment(self.ctx);

        // Find first page and maximum virtual address
        let mut max_vaddr: u64 = 0;
        let mut max_phdr_align = page_size;

        for phdr in &self.program_headers {
            let end = phdr.p_vaddr.saturating_add(phdr.p_memsz);
            if end > max_vaddr {
                max_vaddr = end;
            }
            if phdr.p_align > max_phdr_align {
                max_phdr_align = phdr.p_align;
            }
        }

        // Count SHT_NOTE sections for potential PHT growth
        let num_notes = self.section_headers.iter()
            .filter(|s| s.sh_type == SHT_NOTE)
            .count();

        // Calculate PHT size (pessimistically assuming we might add phdrs for notes + 1 more)
        let ehdr_size = Header::size_with(&self.ctx) as u64;
        let phdr_entry_size = ProgramHeader::size_with(&self.ctx) as u64;
        let pht_size = round_up(
            ehdr_size + (self.program_headers.len() + num_notes + 1) as u64 * phdr_entry_size,
            section_align
        );

        // Replace sections that are "in the way" (like patchelf does)
        // This is critical for note segment normalization to work
        self.replace_sections_in_the_way(pht_size)?;

        // Normalize note segments BEFORE updating section offsets
        // This uses the ORIGINAL section offsets to find which sections are in which PT_NOTE
        self.normalize_note_segments()?;

        // Sort section headers by offset before placement
        self.sort_section_headers();

        // Calculate maximum alignment from program headers and replaced sections
        let mut max_align = max_phdr_align;
        for name in self.replaced_sections.keys() {
            if let Some(idx) = self.find_section_idx(name) {
                let align = self.section_headers[idx].sh_addralign;
                if align > 1 {
                    max_align = max_align.max(align);
                }
            }
        }

        // Round up start address to alignment
        let start_addr = round_up(max_vaddr, max_align);

        // Round file offset to alignment for new section data
        let start_offset = round_up(self.contents.len() as u64, max_align);

        // Binutils quirk: add 1 byte padding (for compatibility with older readelf)
        let binutils_quirk_padding = 1u64;

        // Calculate space needed for replaced sections only (NOT including SHT)
        let sections_space: u64 = self.replaced_sections.iter().map(|(name, content)| {
            let align = self.find_section_idx(name)
                .map(|idx| self.section_headers[idx].sh_addralign.max(1))
                .unwrap_or(section_align);
            round_up(content.len() as u64, align)
        }).sum();

        // Resize file for new sections only
        let new_size = start_offset + sections_space + binutils_quirk_padding;
        self.contents.resize(new_size as usize, 0);

        // Keep section header table at original location (like patchelf does)
        // The SHT is typically at the end of the original file, before our new region

        // Calculate and update section positions (starting right at start_offset, no SHT reservation)
        let mut cur_offset = start_offset;
        let mut cur_addr = start_addr;

        // Clone keys to avoid borrow issues
        let section_names: Vec<String> = self.replaced_sections.keys().cloned().collect();

        for name in &section_names {
            if let Some(idx) = self.find_section_idx(name) {
                let shdr = &mut self.section_headers[idx];
                let align = shdr.sh_addralign.max(1);

                // Align offset and address
                cur_offset = round_up(cur_offset, align);
                cur_addr = round_up(cur_addr, align);

                // Get content size
                let content_size = self.replaced_sections.get(name)
                    .map(|c| c.len() as u64)
                    .unwrap_or(shdr.sh_size);

                // Update section header with NEW positions
                shdr.sh_offset = cur_offset;
                shdr.sh_addr = cur_addr;
                shdr.sh_size = content_size;

                cur_offset += content_size;
                cur_addr += content_size;
            }
        }

        // Create PT_LOAD segment for new data
        self.add_or_extend_pt_load(start_offset, start_addr, cur_offset - start_offset + binutils_quirk_padding, cur_addr - start_addr)?;

        // Write the section contents
        for name in &section_names {
            if let (Some(idx), Some(content)) = (self.find_section_idx(name), self.replaced_sections.get(name)) {
                let offset = self.section_headers[idx].sh_offset as usize;
                self.contents[offset..offset + content.len()].copy_from_slice(content);
            }
        }

        // Rewrite headers - this will sync PT_NOTE segments with updated section headers
        self.rewrite_headers()?;

        Ok(())
    }

    /// Replace sections that are "in the way" of the program header table
    ///
    /// Like patchelf: sections whose offsets are <= PHT size need to be moved
    /// so they don't overlap with the potentially growing PHT.
    fn replace_sections_in_the_way(&mut self, pht_size: u64) -> Result<()> {
        #[cfg(feature = "debug_rewrite")]
        eprintln!("replace_sections_in_the_way: pht_size=0x{:x}", pht_size);

        // Collect sections to replace (skip section 0 which is NULL)
        let mut sections_to_replace: Vec<(String, usize)> = Vec::new();

        for (i, shdr) in self.section_headers.iter().enumerate().skip(1) {
            if shdr.sh_offset <= pht_size {
                if let Some(name) = self.get_section_name(i) {
                    // Skip if already replaced
                    if !self.replaced_sections.contains_key(&name) {
                        // Check if this section can be replaced (not SHT_PROGBITS except .interp)
                        if self.can_replace_section(i) {
                            #[cfg(feature = "debug_rewrite")]
                            eprintln!("  Will replace: {} (offset=0x{:x}, type={})",
                                name, shdr.sh_offset, shdr.sh_type);
                            sections_to_replace.push((name, shdr.sh_size as usize));
                        } else {
                            #[cfg(feature = "debug_rewrite")]
                            eprintln!("  Skip (can't replace): {} (offset=0x{:x}, type={})",
                                name, shdr.sh_offset, shdr.sh_type);
                        }
                    } else {
                        #[cfg(feature = "debug_rewrite")]
                        eprintln!("  Skip (already replaced): {}", name);
                    }
                }
            }
        }

        #[cfg(feature = "debug_rewrite")]
        eprintln!("Replacing {} sections", sections_to_replace.len());

        // Replace the sections
        for (name, size) in sections_to_replace {
            let _ = self.replace_section(&name, size)?;
        }

        #[cfg(feature = "debug_rewrite")]
        eprintln!("replaced_sections now has {} entries", self.replaced_sections.len());

        Ok(())
    }

    /// Check if a section can be safely replaced/moved
    fn can_replace_section(&self, idx: usize) -> bool {
        let shdr = &self.section_headers[idx];
        let name = self.get_section_name(idx).unwrap_or_default();

        // .interp is special - it CAN be replaced even though it's PROGBITS
        if name == ".interp" {
            return true;
        }

        // PROGBITS and NOBITS sections generally can't be moved (contain absolute addresses)
        if shdr.sh_type == SHT_PROGBITS || shdr.sh_type == SHT_NOBITS {
            return false;
        }

        true
    }

    /// Rewrite sections for executables (in-place from start, shift if needed)
    fn rewrite_sections_executable(&mut self) -> Result<()> {
        // For now, use the library strategy for executables too
        // The shifting strategy is more complex and can be added later
        self.rewrite_sections_library()
    }

    /// Add or extend a PT_LOAD segment to cover new data
    fn add_or_extend_pt_load(&mut self, file_offset: u64, vaddr: u64, file_size: u64, mem_size: u64) -> Result<()> {
        let page_size = PageSize::for_machine(self.header.e_machine);

        // Try to find an existing PT_LOAD that can be extended
        let mut found = false;
        for phdr in &mut self.program_headers {
            if phdr.p_type == PT_LOAD {
                let end_offset = phdr.p_offset + phdr.p_filesz;
                let end_vaddr = phdr.p_vaddr + phdr.p_memsz;

                // Check if new data immediately follows this segment
                if end_offset <= file_offset && end_vaddr <= vaddr {
                    let gap_offset = file_offset - end_offset;
                    let gap_vaddr = vaddr - end_vaddr;

                    // If gaps are small enough, extend this segment
                    if gap_offset < page_size && gap_vaddr < page_size {
                        phdr.p_filesz = file_offset + file_size - phdr.p_offset;
                        phdr.p_memsz = vaddr + mem_size - phdr.p_vaddr;
                        found = true;
                        break;
                    }
                }
            }
        }

        // If no suitable segment found, create a new one
        if !found {
            let new_phdr = ProgramHeader {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_W,
                p_offset: file_offset,
                p_vaddr: vaddr,
                p_paddr: vaddr,
                p_filesz: file_size,
                p_memsz: mem_size,
                p_align: page_size,
            };
            self.program_headers.push(new_phdr);
            self.header.e_phnum = self.program_headers.len() as u16;
        }

        Ok(())
    }

    /// Normalize note segments (split multi-section PT_NOTE)
    ///
    /// Like patchelf: Only does work if any SHT_NOTE section has been replaced.
    /// This breaks up PT_NOTE segments containing multiple SHT_NOTE sections to
    /// avoid having to deal with moving multiple sections together if one of
    /// them has to be replaced.
    fn normalize_note_segments(&mut self) -> Result<()> {
        // Check if any note section was replaced (matching patchelf's check)
        let replaced_note = self.replaced_sections.keys().any(|name| {
            if let Some(idx) = self.find_section_idx(name) {
                self.section_headers[idx].sh_type == SHT_NOTE
            } else {
                false
            }
        });

        if !replaced_note {
            return Ok(());
        }

        // Find PT_NOTE segments that cover multiple SHT_NOTE sections
        let mut new_phdrs = Vec::new();
        let mut to_modify: Vec<(usize, ProgramHeader)> = Vec::new();

        for (i, phdr) in self.program_headers.iter().enumerate() {
            if phdr.p_type != PT_NOTE {
                continue;
            }

            let start_off = phdr.p_offset;
            let end_off = phdr.p_offset + phdr.p_filesz;

            // Check if this segment is empty (no sections within it)
            let empty = !self.section_headers.iter().any(|shdr| {
                shdr.sh_offset >= start_off && shdr.sh_offset < end_off
            });
            if empty {
                continue;
            }

            // Find SHT_NOTE sections within this segment
            let mut note_sections: Vec<(usize, u64, u64, u64)> = Vec::new(); // (idx, offset, size, align)
            for (j, shdr) in self.section_headers.iter().enumerate() {
                if shdr.sh_type == SHT_NOTE
                    && shdr.sh_offset >= start_off
                    && shdr.sh_offset < end_off
                {
                    note_sections.push((j, shdr.sh_offset, shdr.sh_size, shdr.sh_addralign.max(1)));
                }
            }

            // Sort by offset
            note_sections.sort_by_key(|&(_, off, _, _)| off);

            if note_sections.len() <= 1 {
                continue;
            }

            // Build new phdrs for each note section (like patchelf)
            let mut first = true;
            for (idx, offset, size, _align) in note_sections {
                let shdr = &self.section_headers[idx];
                let new_phdr = ProgramHeader {
                    p_type: PT_NOTE,
                    p_flags: phdr.p_flags,
                    p_offset: offset,
                    p_vaddr: phdr.p_vaddr + (offset - start_off),
                    p_paddr: phdr.p_paddr + (offset - start_off),
                    p_filesz: size,
                    p_memsz: size,
                    p_align: shdr.sh_addralign,
                };

                if first {
                    // Replace the original phdr
                    to_modify.push((i, new_phdr));
                    first = false;
                } else {
                    // Add new phdr
                    new_phdrs.push(new_phdr);
                }
            }
        }

        // Apply modifications to existing phdrs
        for (i, new_phdr) in to_modify {
            self.program_headers[i] = new_phdr;
        }

        // Add new phdrs at the end
        self.program_headers.extend(new_phdrs);
        self.header.e_phnum = self.program_headers.len() as u16;

        Ok(())
    }

    /// Sort section headers by offset
    fn sort_section_headers(&mut self) {
        // Create index map before sorting
        let mut indices: Vec<usize> = (0..self.section_headers.len()).collect();
        indices.sort_by_key(|&i| self.section_headers[i].sh_offset);

        // Create old->new mapping
        let mut new_to_old: Vec<usize> = vec![0; self.section_headers.len()];
        for (new_idx, &old_idx) in indices.iter().enumerate() {
            new_to_old[new_idx] = old_idx;
        }

        // Sort section headers
        let mut sorted = vec![SectionHeader::default(); self.section_headers.len()];
        for (new_idx, &old_idx) in indices.iter().enumerate() {
            sorted[new_idx] = self.section_headers[old_idx].clone();
        }
        self.section_headers = sorted;

        // Update shstrndx if needed
        for (new_idx, &old_idx) in indices.iter().enumerate() {
            if old_idx == self.header.e_shstrndx as usize {
                self.header.e_shstrndx = new_idx as u16;
                break;
            }
        }

        // Store mapping for symbol table updates
        self.section_index_map = new_to_old;
    }

    /// Rewrite all headers after section modifications
    fn rewrite_headers(&mut self) -> Result<()> {
        // Sort program headers (PT_PHDR first, then by p_paddr)
        self.program_headers.sort_by(|a, b| {
            if a.p_type == PT_PHDR {
                return core::cmp::Ordering::Less;
            }
            if b.p_type == PT_PHDR {
                return core::cmp::Ordering::Greater;
            }
            a.p_paddr.cmp(&b.p_paddr)
        });

        // Update program headers to match section changes
        self.sync_program_headers()?;

        // Update dynamic section entries
        self.update_dynamic_section()?;

        Ok(())
    }

    /// Synchronize program headers with section changes
    fn sync_program_headers(&mut self) -> Result<()> {
        // Pre-fetch section info to avoid borrow issues
        let interp_info = self.find_section(".interp").ok().map(|s| (s.sh_offset, s.sh_addr, s.sh_size));
        let dynamic_info = self.find_section(".dynamic").ok().map(|s| (s.sh_offset, s.sh_addr, s.sh_size));
        let phdr_offset = self.header.e_phoff;
        let ctx = self.ctx;
        let phdr_count = self.program_headers.len() as u64;
        let phdr_entry_size = ProgramHeader::size_with(&ctx) as u64;

        // Collect NOTE section info for PT_NOTE updates
        // Each PT_NOTE segment covers a single SHT_NOTE section after normalization
        let note_sections: Vec<(u64, u64, u64, u64)> = self.section_headers.iter()
            .filter(|s| s.sh_type == SHT_NOTE)
            .map(|s| (s.sh_offset, s.sh_addr, s.sh_size, s.sh_addralign))
            .collect();

        // Track which note sections have been matched to PT_NOTE segments
        let mut note_idx = 0;

        for phdr in &mut self.program_headers {
            match phdr.p_type {
                PT_INTERP => {
                    if let Some((offset, addr, size)) = interp_info {
                        phdr.p_offset = offset;
                        phdr.p_vaddr = addr;
                        phdr.p_paddr = addr;
                        phdr.p_filesz = size;
                        phdr.p_memsz = size;
                    }
                }
                PT_DYNAMIC => {
                    if let Some((offset, addr, size)) = dynamic_info {
                        phdr.p_offset = offset;
                        phdr.p_vaddr = addr;
                        phdr.p_paddr = addr;
                        phdr.p_filesz = size;
                        phdr.p_memsz = size;
                    }
                }
                PT_PHDR => {
                    phdr.p_offset = phdr_offset;
                    phdr.p_filesz = phdr_count * phdr_entry_size;
                    phdr.p_memsz = phdr.p_filesz;
                }
                PT_NOTE => {
                    // Update PT_NOTE to match corresponding SHT_NOTE section
                    if note_idx < note_sections.len() {
                        let (offset, addr, size, align) = note_sections[note_idx];
                        phdr.p_offset = offset;
                        phdr.p_vaddr = addr;
                        phdr.p_paddr = addr;
                        phdr.p_filesz = size;
                        phdr.p_memsz = size;
                        phdr.p_align = align;
                        note_idx += 1;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Update dynamic section entries to reflect new section addresses
    fn update_dynamic_section(&mut self) -> Result<()> {
        let dynamic_shdr = match self.find_section(".dynamic") {
            Ok(shdr) => shdr,
            Err(_) => return Ok(()), // No dynamic section
        };

        let mut dyn_entries = self.read_dynamic_entries(&dynamic_shdr)?;
        let mut modified = false;

        for entry in &mut dyn_entries {
            match entry.d_tag {
                DT_STRTAB => {
                    if let Ok(shdr) = self.find_section(".dynstr") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_STRSZ => {
                    if let Ok(shdr) = self.find_section(".dynstr") {
                        entry.d_val = shdr.sh_size;
                        modified = true;
                    }
                }
                DT_SYMTAB => {
                    if let Ok(shdr) = self.find_section(".dynsym") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_HASH => {
                    if let Ok(shdr) = self.find_section(".hash") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_GNU_HASH => {
                    if let Ok(shdr) = self.find_section(".gnu.hash") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_JMPREL => {
                    // Try .rela.plt first, then .rel.plt
                    if let Ok(shdr) = self.find_section(".rela.plt") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    } else if let Ok(shdr) = self.find_section(".rel.plt") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_RELA => {
                    if let Ok(shdr) = self.find_section(".rela.dyn") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_RELASZ => {
                    if let Ok(shdr) = self.find_section(".rela.dyn") {
                        entry.d_val = shdr.sh_size;
                        modified = true;
                    }
                }
                DT_REL => {
                    if let Ok(shdr) = self.find_section(".rel.dyn") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_RELSZ => {
                    if let Ok(shdr) = self.find_section(".rel.dyn") {
                        entry.d_val = shdr.sh_size;
                        modified = true;
                    }
                }
                DT_VERNEED => {
                    if let Ok(shdr) = self.find_section(".gnu.version_r") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_VERSYM => {
                    if let Ok(shdr) = self.find_section(".gnu.version") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                DT_VERDEF => {
                    if let Ok(shdr) = self.find_section(".gnu.version_d") {
                        entry.d_val = shdr.sh_addr;
                        modified = true;
                    }
                }
                _ => {}
            }
        }

        if modified {
            self.write_dynamic_entries_to_replaced(&dyn_entries)?;
        }

        Ok(())
    }

    /// Write ELF header to contents
    fn write_headers(&mut self) -> Result<()> {
        // Write ELF header
        self.contents.pwrite_with(self.header.clone(), 0, self.ctx.le)?;

        // Write program headers
        let phdr_offset = self.header.e_phoff as usize;
        let phdr_size = ProgramHeader::size_with(&self.ctx);

        for (i, phdr) in self.program_headers.iter().enumerate() {
            let offset = phdr_offset + i * phdr_size;
            if offset + phdr_size <= self.contents.len() {
                self.contents.pwrite_with(phdr.clone(), offset, self.ctx)?;
            }
        }

        // Write section headers
        let shdr_offset = self.header.e_shoff as usize;
        let shdr_size = SectionHeader::size_with(&self.ctx);

        for (i, shdr) in self.section_headers.iter().enumerate() {
            let offset = shdr_offset + i * shdr_size;
            if offset + shdr_size <= self.contents.len() {
                self.contents.pwrite_with(shdr.clone(), offset, self.ctx)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_up() {
        assert_eq!(round_up(0, 4), 0);
        assert_eq!(round_up(1, 4), 4);
        assert_eq!(round_up(4, 4), 4);
        assert_eq!(round_up(5, 4), 8);
        assert_eq!(round_up(100, 64), 128);
    }

    #[test]
    fn test_page_size() {
        assert_eq!(PageSize::for_machine(EM_AARCH64), 0x10000);
        assert_eq!(PageSize::for_machine(EM_SPARC), 0x2000);
        assert_eq!(PageSize::for_machine(0x3E), 0x1000); // x86_64
    }
}
