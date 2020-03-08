pub(crate) use libbpf_sys::*;
use std::ffi::{CStr, CString};

use crate::errors::*;
use crate::program::*;

#[derive(Debug)]
pub struct BpfObject {
    bpf_obj: *mut bpf_object,
    first_prog_fd: i32,
}

impl BpfObject {
    pub fn get_name(&self) -> Result<String> {
        unsafe {
            let s = bpf_object__name(self.bpf_obj);
            Ok(CStr::from_ptr(s as *mut i8).to_str()?.to_owned())
        }
    }

    pub fn get_progs_names(&self) -> Vec<String> {
        self.programs()
            .map(|prog| prog.get_title_owned().unwrap())
            .collect()
    }

    pub fn get_prog_by_name(&self, name: &str) -> Result<BpfProgram> {
        let prog = unsafe {
            bpf_object__find_program_by_title(self.bpf_obj, CString::new(name).unwrap().as_ptr())
        };

        if prog == std::ptr::null_mut() {
            bail!(ErrorKind::InvalidProgName(name.to_string()));
        }

        Ok(BpfProgram { bpf_prog: prog })
    }

    pub fn programs(&self) -> BpfPrograms {
        BpfPrograms {
            bpf_obj: self,
            bpf_prog_current: None,
        }
    }

    fn next_prog(&self, bpf_prog_o: Option<BpfProgram>) -> Option<BpfProgram> {
        if None == bpf_prog_o {
            let prog = unsafe { bpf_program__next(std::ptr::null_mut(), self.bpf_obj) };

            if prog == std::ptr::null_mut() {
                return None;
            }

            return Some(BpfProgram { bpf_prog: prog });
        }

        let next = unsafe { bpf_program__next(bpf_prog_o.unwrap().bpf_prog, self.bpf_obj) };

        if next == std::ptr::null_mut() {
            return None;
        }

        return Some(BpfProgram { bpf_prog: next });
    }
}

pub struct BpfPrograms<'a> {
    bpf_obj: &'a BpfObject,
    bpf_prog_current: Option<BpfProgram>,
}

impl<'a> Iterator for BpfPrograms<'a> {
    type Item = BpfProgram;
    fn next(&mut self) -> Option<BpfProgram> {
        let next = self.bpf_obj.next_prog(self.bpf_prog_current);
        self.bpf_prog_current = next;
        self.bpf_prog_current
    }
}

#[derive(Debug)]
pub struct BpfObjectLoader {
    attr: bpf_prog_load_attr,
}

impl BpfObjectLoader {
    pub fn new() -> Self {
        BpfObjectLoader {
            attr: bpf_prog_load_attr::default(),
        }
    }

    pub fn with_prog_type(mut self, prog_type: bpf_prog_type) -> Self {
        self.attr.prog_type = prog_type;
        self
    }

    pub fn with_file_name(mut self, file_name: &str) -> Self {
        let s = CString::new(file_name.to_owned()).unwrap();
        self.attr.file = s.into_raw();
        self
    }

    pub fn with_expected_attach_type(mut self, ex_att_type: bpf_attach_type) -> Self {
        self.attr.expected_attach_type = ex_att_type;
        self
    }

    pub fn with_log_level(mut self, log_level: i32) -> Self {
        self.attr.log_level = log_level;
        self
    }

    pub fn with_prog_flags(mut self, prog_flags: i32) -> Self {
        self.attr.prog_flags = prog_flags;
        self
    }

    pub fn with_ifindex(mut self, ifindex: i32) -> Self {
        self.attr.ifindex = ifindex;
        self
    }

    pub fn load(self) -> Result<BpfObject> {
        let obj: *mut bpf_object = std::ptr::null_mut();
        let first_prog_fd = -1;

        let err = unsafe {
            bpf_prog_load_xattr(
                &self.attr as *const bpf_prog_load_attr,
                &obj as *const *mut bpf_object as *mut *mut bpf_object,
                &first_prog_fd as *const i32 as *mut i32,
            )
        };

        if err != 0 {
            bail!(ErrorKind::LoadXAttrFailed(err));
        }

        Ok(BpfObject {
            bpf_obj: obj,
            first_prog_fd: first_prog_fd,
        })
    }
}
