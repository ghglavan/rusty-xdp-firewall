use crate::errors::*;
use crate::xdp_attacher::*;
use libbpf_sys::*;

use std::ffi::CStr;

pub type ProgFD = i32;

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct BpfProgram {
    pub(crate) bpf_prog: *mut bpf_program,
}

impl BpfProgram {
    pub fn get_fd(&self) -> Result<ProgFD> {
        let fd = unsafe { bpf_program__fd(self.bpf_prog) };

        if fd <= 0 {
            bail!(ErrorKind::InvalidProgFD);
        }

        Ok(fd)
    }

    pub fn set_ifindex(&mut self, ifindex: i32) {
        unsafe { bpf_program__set_ifindex(self.bpf_prog, ifindex as u32) }
    }

    pub fn get_title_not_owned(&self) -> Result<&str> {
        Ok(unsafe { CStr::from_ptr(bpf_program__title(self.bpf_prog, false)).to_str()? })
    }

    pub fn get_title_owned(&self) -> Result<String> {
        Ok(self.get_title_not_owned()?.to_owned())
    }

    pub fn get_attacher(&self) -> Result<XdpAttacher> {
        if !unsafe { bpf_program__is_xdp(self.bpf_prog) } {
            bail!(ErrorKind::ProgNotXdp);
        }

        Ok(XdpAttacher {
            bpf_prog: self,
            ifindex: 0,
            flags: 0,
        })
    }
}
