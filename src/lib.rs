#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

#[cfg(target_os = "linux")]
pub use bpf_linux::*;
#[cfg(target_os = "linux")]
#[macro_use]
mod bpf_linux;

#[cfg(not(target_os = "linux"))]
pub use bpf_dummy::*;
#[cfg(not(target_os = "linux"))]
#[macro_use]
mod bpf_dummy;

mod map;
pub use map::*;

#[cfg(feature = "module")]
mod module;
#[cfg(feature = "module")]
pub use module::*;
