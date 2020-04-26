use crate::program::*;
use libbpf_sys::*;

use std::ffi::CString;

use libc::{if_nametoindex, EEXIST};
use nix::errno;

#[derive(Clone, Copy)]
pub struct XdpAttacher<'a> {
    pub(crate) bpf_prog: &'a BpfProgram,
    pub(crate) ifindex: i32,
    pub(crate) flags: u32,
}

impl<'a> XdpAttacher<'a> {
    pub fn with_if(&mut self, ifname: &str) -> Result<&mut Self, String> {
        let c_ifname = CString::new(ifname)
            .map_err(|e| format!("error converting ifname {} to cstring: {}", ifname, e))?;

        let ifindex = unsafe { if_nametoindex(c_ifname.as_ptr() as *const i8) };

        if ifindex == 0 {
            bail!(format!("invalid interface {}: {}", ifname, errno::errno()));
        }

        self.ifindex = ifindex as i32;
        Ok(self)
    }

    pub fn update_if_noexist(&mut self) -> &mut Self {
        self.flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
        self
    }

    pub fn in_skb_mode(&mut self) -> &mut Self {
        self.flags &= !XDP_FLAGS_MODES;
        self.flags |= XDP_FLAGS_SKB_MODE;
        self
    }

    pub fn in_drv_mode(&mut self) -> &mut Self {
        self.flags &= !XDP_FLAGS_MODES;
        self.flags |= XDP_FLAGS_DRV_MODE;
        self
    }

    pub fn in_hw_mode(&mut self) -> &mut Self {
        self.flags &= !XDP_FLAGS_MODES;
        self.flags |= XDP_FLAGS_HW_MODE;
        self
    }

    pub fn attach(&mut self) -> Result<&mut Self, String> {
        let mut err =
            unsafe { bpf_set_link_xdp_fd(self.ifindex, self.bpf_prog.get_fd()?, self.flags) };

        if -err == EEXIST as i32 && (self.flags & XDP_FLAGS_UPDATE_IF_NOEXIST) == 0 {
            let mut l_flags = self.flags & !XDP_FLAGS_MODES;
            l_flags |= if (self.flags & XDP_FLAGS_SKB_MODE) != 0 {
                XDP_FLAGS_DRV_MODE
            } else {
                XDP_FLAGS_SKB_MODE
            };

            err = unsafe { bpf_set_link_xdp_fd(self.ifindex, -1, l_flags) };
            if err == 0 {
                err = unsafe {
                    bpf_set_link_xdp_fd(self.ifindex, self.bpf_prog.get_fd()?, self.flags)
                };
            }
        }
        if err != 0 {
            bail!(format!(
                "error attaching program {}: {}",
                self.bpf_prog.get_title_owned().unwrap(),
                err
            ));
        }

        Ok(self)
    }

    pub fn detach(&mut self) -> Result<&mut Self, String> {
        let err = unsafe { bpf_set_link_xdp_fd(self.ifindex, -1, self.flags) };
        if err != 0 {
            bail!(format!(
                "error detaching program {}: {}",
                self.bpf_prog.get_title_owned().unwrap(),
                err
            ));
        }
        Ok(self)
    }
}
