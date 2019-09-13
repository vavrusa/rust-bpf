use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Error, ErrorKind};
use std::os::raw::c_void;
use std::os::unix::io::RawFd;

#[repr(C)]
#[derive(Debug)]
pub struct MapDefinition {
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

impl MapDefinition {
    pub fn parse(name: &str, code: &[u8]) -> Result<Self, Error> {
        let mut rdr = Cursor::new(code);
        Ok(MapDefinition {
            name: name.to_string(),
            map_type: rdr.read_u32::<LittleEndian>()?,
            key_size: rdr.read_u32::<LittleEndian>()?,
            value_size: rdr.read_u32::<LittleEndian>()?,
            max_entries: rdr.read_u32::<LittleEndian>()?,
            map_flags: rdr.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
pub struct Map {
    fd: RawFd,
    pub kind: MapDefinition,
}

impl Map {
    pub fn new(kind: MapDefinition) -> Result<Self, Error> {
        let fd = crate::create_map(&kind)?;
        Ok(Self { fd, kind })
    }

    pub fn insert<K: Sized, V: Sized>(&self, key: &K, value: &V) -> Result<(), Error> {
        let key_ptr = to_checked_ptr(key, self.kind.key_size as usize)?;
        let value_ptr = to_checked_ptr(value, self.kind.value_size as usize)?;
        crate::update_elem(self.fd, key_ptr, value_ptr, 0)
    }

    pub fn get<K: Sized, V: Sized>(&self, key: &K) -> Result<V, Error> {
        let key_ptr = to_checked_ptr(key, self.kind.key_size as usize)?;
        let mut val: V = unsafe { std::mem::zeroed() };
        let _ = crate::lookup_elem(self.fd, key_ptr, &mut val as *mut _ as *mut c_void)?;
        Ok(val)
    }

    pub fn delete<K: Sized>(&self, key: &K) -> Result<(), Error> {
        let key_ptr = to_checked_ptr(key, self.kind.key_size as usize)?;
        crate::delete_elem(self.fd, key_ptr)
    }

    pub fn get_fd(&self) -> &RawFd {
        &self.fd
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn to_checked_ptr<V: Sized>(v: &V, expected_len: usize) -> Result<*const c_void, Error> {
    if std::mem::size_of::<V>() == expected_len {
        Ok(v as *const _ as *const c_void)
    } else {
        Err(ErrorKind::InvalidInput.into())
    }
}
