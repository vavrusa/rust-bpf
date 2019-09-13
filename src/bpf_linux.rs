use byteorder::{LittleEndian, ReadBytesExt};
use libc::{self, c_int, c_uint, c_void, setsockopt, socklen_t, SOL_SOCKET};
use std::io::Cursor;
use std::io::{Error, ErrorKind};
use std::mem::{forget, size_of_val};
use std::os::unix::io::RawFd;
use std::ptr::null;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Op {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl Op {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Op {
        Op {
            code: code,
            jt: jt,
            jf: jf,
            k: k,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Prog {
    len: c_ushort,
    filter: *mut Op,
}

impl Drop for Prog {
    fn drop(&mut self) {
        unsafe {
            let len = self.len as usize;
            let ptr = self.filter;
            Vec::from_raw_parts(ptr, len, len);
        }
    }
}

impl Prog {
    pub fn new(ops: Vec<Op>) -> Prog {
        let mut ops = ops.into_boxed_slice();
        let len = ops.len();
        let ptr = ops.as_mut_ptr();

        forget(ops);

        Prog {
            len: len as _,
            filter: ptr,
        }
    }

    pub fn parse(code: &[u8]) -> Result<Prog, Error> {
        if code.len() % std::mem::size_of::<Op>() != 0 {
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut rdr = Cursor::new(code);
        let mut insns = Vec::with_capacity(code.len() / std::mem::size_of::<Op>());
        while rdr.position() < code.len() as u64 {
            let op = Op::new(
                rdr.read_u16::<LittleEndian>()?,
                rdr.read_u8()?,
                rdr.read_u8()?,
                rdr.read_u32::<LittleEndian>()?,
            );
            insns.push(op);
        }

        Ok(Prog::new(insns))
    }

    pub fn len(&self) -> usize {
        self.insns.len() * std::mem::size_of::<Op>()
    }
}

const SO_ATTACH_FILTER: c_int = 26;
const SO_DETACH_FILTER: c_int = 27;
const SO_LOCK_FILTER: c_int = 44;
const SO_ATTACH_BPF: c_int = 50;

#[macro_export]
macro_rules! bpfprog {
    ($count:expr, $($code:tt $jt:tt $jf:tt $k:tt),*) => {
        {
            let mut ops = Vec::with_capacity($count);
            $(ops.push(bpf::Op::new($code, $jt, $jf, $k));)*
            bpf::Prog::new(ops)
        }
    }
}

pub fn attach_filter_fd(fd: RawFd, prog_fd: RawFd) -> Result<(), Error> {
    match unsafe {
        setsockopt(
            fd as c_int,
            SOL_SOCKET,
            SO_ATTACH_BPF,
            &prog_fd as *const _ as *const c_void,
            size_of_val(&prog_fd) as socklen_t,
        )
    } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub fn attach_filter(fd: RawFd, prog: Prog) -> Result<(), Error> {
    match unsafe {
        setsockopt(
            fd as c_int,
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const _ as *const c_void,
            size_of_val(&prog) as socklen_t,
        )
    } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub fn detach_filter(fd: RawFd) -> Result<(), Error> {
    match unsafe { setsockopt(fd as c_int, SOL_SOCKET, SO_DETACH_FILTER, null(), 0) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub fn lock_filter(fd: RawFd) -> Result<(), Error> {
    let one: c_int = 1;
    match unsafe {
        setsockopt(
            fd as c_int,
            SOL_SOCKET,
            SO_LOCK_FILTER,
            &one as *const _ as *const c_void,
            size_of_val(&one) as socklen_t,
        )
    } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub fn create_map(map: &crate::MapDefinition) -> Result<RawFd, Error> {
    let name = std::ffi::CString::new(map.name.clone()).unwrap();
    match unsafe {
        bpf_sys::bcc_create_map(
            map.map_type,
            name.as_ptr(),
            map.key_size as c_int,
            map.value_size as c_int,
            map.max_entries as c_int,
            0,
        )
    } {
        -1 => Err(Error::last_os_error()),
        fd => Ok(fd.into()),
    }
}

pub fn update_elem(
    fd: RawFd,
    key: *const c_void,
    value: *const c_void,
    flags: u64,
) -> Result<(), Error> {
    match unsafe { bpf_sys::bpf_update_elem(fd, key as *mut _, value as *mut _, flags) } {
        -1 => Err(Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn lookup_elem(fd: RawFd, key: *const c_void, value: *mut c_void) -> Result<(), Error> {
    match unsafe { bpf_sys::bpf_lookup_elem(fd, key as *mut _, value) } {
        -1 => Err(Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn delete_elem(fd: RawFd, key: *const c_void) -> Result<(), Error> {
    match unsafe { bpf_sys::bpf_delete_elem(fd, key as *mut _) } {
        -1 => Err(Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn prog_load(
    prog: &Prog,
    name: &str,
    kind: u32,
    license: &str,
    kern_version: c_uint,
    log_level: c_int,
    log: &mut [u8],
) -> Result<RawFd, Error> {
    let name = std::ffi::CString::new(name).unwrap();
    let license = std::ffi::CString::new(license).unwrap();
    match unsafe {
        bpf_sys::bcc_prog_load(
            kind.into(),
            name.as_ptr(),
            prog.insns.as_ptr() as *const _,
            prog.len() as c_int,
            license.as_ptr(),
            kern_version,
            log_level,
            log.as_mut_ptr() as *mut _,
            log.len() as c_uint,
        )
    } {
        -1 => Err(Error::last_os_error()),
        fd => Ok(fd.into()),
    }
}
