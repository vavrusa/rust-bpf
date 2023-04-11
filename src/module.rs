use crate::Prog;
use byteorder::{LittleEndian, ReadBytesExt};
use goblin::elf::{sym, Elf};
use std::collections::HashMap;
use std::io::{Cursor, Error, ErrorKind};
use std::os::unix::io::RawFd;

const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;

#[derive(Debug)]
pub struct Program {
    fd: RawFd,
    pub kind: u32,
    pub prog: Prog,
}

impl Drop for Program {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Program {
    pub fn attach_filter(&self, fd: RawFd) -> Result<(), Error> {
        crate::attach_filter_fd(fd, self.fd)
    }
}

#[derive(Debug, Default)]
pub struct Module {
    pub programs: HashMap<String, Program>,
    pub maps: HashMap<String, crate::Map>,
    pub license: String,
    pub version: u32,
}

impl Module {
    pub fn parse(code: &[u8]) -> Result<Self, Error> {
        let mut module = Self::default();

        let obj =
            Elf::parse(code).map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;

        let mut map_symbols = HashMap::new();
        let mut programs = HashMap::new();
        for (shndx, section) in obj.section_headers.iter().enumerate() {
            let section_name = obj
                .shdr_strtab
                .get_at(section.sh_name)
                .ok_or(Error::from(ErrorKind::InvalidData))?;
            let section_end = (section.sh_offset + section.sh_size) as usize;
            let data = &code[section.sh_offset as usize..section_end];
            match section_name {
                "license" => {
                    let cstr = std::ffi::CStr::from_bytes_with_nul(data)
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?;
                    module.license = cstr.to_string_lossy().to_string();
                }
                "version" => {
                    let mut rdr = Cursor::new(data);
                    module.version = rdr.read_u32::<LittleEndian>()?;
                }
                "maps" => {
                    for (stndx, sym) in obj
                        .syms
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| s.st_shndx == shndx && s.st_bind() == sym::STB_GLOBAL)
                    {
                        let name = obj
                            .strtab
                            .get_at(sym.st_name)
                            .ok_or(Error::from(ErrorKind::InvalidData))?;
                        let def =
                            crate::MapDefinition::parse(name, &data[sym.st_value as usize..])?;
                        let map = crate::Map::new(def).map_err(|e| {
                            Error::new(e.kind(), format!("failed to load map: {}", e))
                        })?;
                        map_symbols.insert(stndx, map.get_fd().clone());
                        module.maps.insert(name.to_string(), map);
                    }
                }
                "socketfilters" => {
                    for sym in obj
                        .syms
                        .iter()
                        .filter(|s| s.st_shndx == shndx && s.st_bind() == sym::STB_GLOBAL)
                    {
                        let name = obj
                            .strtab
                            .get_at(sym.st_name)
                            .ok_or(Error::from(ErrorKind::InvalidData))?;
                        programs.insert(name, (shndx, BPF_PROG_TYPE_SOCKET_FILTER, data));
                    }
                }
                _ => {}
            }
        }

        // Load programs
        for (name, (shndx, kind, data)) in programs.into_iter() {
            let mut data = data.to_vec();

            // Relocate program
            for rel in obj
                .shdr_relocs
                .iter()
                .filter(|(shdr, _)| {
                    obj.section_headers
                        .get(*shdr)
                        .map(|s| s.sh_info == shndx as u32)
                        .unwrap_or(false)
                })
                .map(|(_, rels)| rels.iter())
                .flatten()
            {
                let fd = map_symbols
                    .get(&rel.r_sym)
                    .ok_or(Error::from(ErrorKind::InvalidData))?;
                let insn = &mut data[rel.r_offset as usize..];
                insn[1] |= BPF_PSEUDO_MAP_FD << 4;
                insn[4..8].copy_from_slice(&fd.to_le_bytes());
            }

            // Load program
            let prog = Prog::parse(&data)?;
            let fd = module
                .load_program(name, kind, &prog)
                .map_err(|e| Error::new(e.kind(), format!("failed to load program: {}", e)))?;
            module
                .programs
                .insert(name.to_string(), Program { fd, kind, prog });
        }

        Ok(module)
    }

    fn load_program(&mut self, name: &str, kind: u32, prog: &Prog) -> Result<RawFd, Error> {
        let mut log_buf = [0u8; 65_536];
        match crate::prog_load(
            &prog,
            name,
            kind,
            &self.license,
            self.version,
            0,
            &mut log_buf,
        ) {
            Ok(fd) => Ok(fd),
            Err(e) => Err(e),
        }
    }
}
