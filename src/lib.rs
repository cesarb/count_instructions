#![no_std]

extern crate std;

#[cfg(target_os = "linux")]
mod linux;

pub type Address = libc::c_ulong;

#[derive(Debug)]
pub struct Instruction {
    address: Address,
}

impl Instruction {
    #[inline]
    fn new(address: Address) -> Self {
        Self { address }
    }

    #[inline]
    pub fn address(&self) -> Address {
        self.address
    }
}

#[inline]
pub fn count_instructions<F, T, C>(f: F, counter: C) -> std::io::Result<T>
where
    F: FnOnce() -> T,
    C: FnMut(&Instruction) + Send,
{
    count_instructions_impl(f, counter)
}

#[cfg(target_os = "linux")]
use linux::count_instructions as count_instructions_impl;

#[cfg(not(target_os = "linux"))]
fn count_instructions_impl<F, T, C>(_f: F, _counter: C) -> std::io::Result<T>
where
    F: FnOnce() -> T,
    C: FnMut(&Instruction) + Send,
{
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "instruction tracing not implemented for this platform",
    ))
}
