use byteorder::{LittleEndian, ReadBytesExt};
use libc::ENOENT;
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

    pub fn keys<K: Sized + Clone>(&self, key: K) -> Keys<K> {
        Keys {
            fd: self.fd,
            key,
            max: self.kind.max_entries as usize,
        }
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

// The iterator may not work as expected, as the current key may be
// evicted, then a call with a non exist key will reset the loop to
// the beginning. The max field is to prevent dead loop under this
// situation.
pub struct Keys<K: Sized> {
    fd: RawFd,
    key: K,
    max: usize,
}

// Clone is needed as otherwise the previous item can not be
// referenced.
impl<K: Sized + Clone> Iterator for Keys<K> {
    type Item = Result<K, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.max = self.max.checked_sub(1)?;

        let mut next_key: K = unsafe { std::mem::zeroed() };
        match crate::get_next_key(
            self.fd,
            &self.key as *const _ as *const c_void,
            &mut next_key as *mut _ as *mut c_void,
        ) {
            Ok(_) => {
                self.key = next_key;
                return Some(Ok(self.key.clone()));
            }
            Err(e) if e.kind() == Error::from_raw_os_error(ENOENT).kind() => {
                return None;
            }
            Err(e) => {
                return Some(Err(e));
            }
        }
    }
}
