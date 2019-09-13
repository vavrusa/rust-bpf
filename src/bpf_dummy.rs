use std::io::Error;
use std::os::raw::{c_int, c_uint, c_void};
use std::os::unix::io::RawFd;

#[derive(Debug)]
pub struct Prog;

impl Prog {
    #[allow(unused_variables)]
    pub fn parse(code: &[u8]) -> Result<Self, Error> {
        Ok(Prog {})
    }
}

#[macro_export]
macro_rules! bpfprog {
    ($count:expr, $($code:tt $jt:tt $jf:tt $k:tt),*) => {
        bpf::Prog
    };
}

#[allow(unused_variables)]
pub fn attach_filter_fd(fd: RawFd, prog_fd: RawFd) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn attach_filter(fd: RawFd, prog: Prog) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn detach_filter(fd: RawFd) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn lock_filter(fd: RawFd) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn create_map(map: &crate::MapDefinition) -> Result<RawFd, Error> {
    Ok(0)
}

#[allow(unused_variables)]
pub fn update_elem(
    fd: RawFd,
    key: *const c_void,
    val: *const c_void,
    flags: u64,
) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn lookup_elem(fd: RawFd, key: *const c_void, val: *mut c_void) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn delete_elem(fd: RawFd, key: *const c_void) -> Result<(), Error> {
    Ok(())
}

#[allow(unused_variables)]
pub fn prog_load(
    prog: &Prog,
    name: &str,
    kind: u32,
    license: &str,
    kern_version: c_uint,
    log_level: c_int,
    log: &mut [u8],
) -> Result<RawFd, Error> {
    Ok(RawFd::default())
}
