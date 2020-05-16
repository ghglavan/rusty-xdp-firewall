use crate::xdp_attacher::*;
use libbpf_sys::*;

use std::ffi::CStr;

pub type ProgFD = i32;

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct BpfProgram {
    pub(crate) bpf_prog: *mut bpf_program,
}

unsafe impl Send for BpfProgram {}
unsafe impl Sync for BpfProgram {}

impl BpfProgram {
    pub fn get_fd(&self) -> Result<ProgFD, String> {
        let fd = unsafe { bpf_program__fd(self.bpf_prog) };

        if fd <= 0 {
            bail!(format!("error getting program fd: {}", fd));
        }

        Ok(fd)
    }

    pub fn set_ifindex(&mut self, ifindex: i32) {
        unsafe { bpf_program__set_ifindex(self.bpf_prog, ifindex as u32) }
    }

    pub fn get_title_not_owned(&self) -> Result<&str, String> {
        Ok(unsafe {
            CStr::from_ptr(bpf_program__title(self.bpf_prog, false))
                .to_str()
                .map_err(|e| format!("error getting program title: {}", e))?
        })
    }

    pub fn get_title_owned(&self) -> Result<String, String> {
        Ok(self.get_title_not_owned()?.to_owned())
    }

    pub fn get_attacher(&self) -> Result<XdpAttacher, String> {
        if !unsafe { bpf_program__is_xdp(self.bpf_prog) } {
            bail!("error getting the attacher: program is not xdp");
        }

        Ok(XdpAttacher {
            bpf_prog: self,
            ifindex: 0,
            flags: 0,
        })
    }
}
