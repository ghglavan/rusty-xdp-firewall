pub(crate) use libbpf_sys::*;
use std::ffi::{CStr, CString};

use crate::map::*;
use crate::program::*;

#[derive(Debug)]
pub struct BpfObject {
    bpf_obj: *mut bpf_object,
    first_prog_fd: i32,
}

unsafe impl Send for BpfObject {}
unsafe impl Sync for BpfObject {}

impl Drop for BpfObject {
    fn drop(&mut self) {
        self.unload();
    }
}

impl BpfObject {
    pub fn get_name(&self) -> Result<String, String> {
        unsafe {
            let s = bpf_object__name(self.bpf_obj);
            Ok(CStr::from_ptr(s as *mut i8)
                .to_str()
                .map_err(|e| format!("error getting object name: {}", e))?
                .to_owned())
        }
    }

    pub fn get_progs_names(&self) -> Vec<String> {
        self.programs()
            .map(|prog| get_prog_name_raw(&prog).unwrap().to_string())
            .collect()
    }

    pub fn get_maps_names(&self) -> Vec<String> {
        self.maps()
            .map(|m| get_map_name_raw(&m).unwrap().to_string())
            .collect()
    }

    pub fn get_prog_by_name(&self, name: &str) -> Result<BpfProgram, String> {
        let prog = unsafe {
            bpf_object__find_program_by_title(self.bpf_obj, CString::new(name).unwrap().as_ptr())
        };

        if prog == std::ptr::null_mut() {
            bail!(format!("error getting program by name. name: {}", name));
        }

        Ok(BpfProgram { bpf_prog: prog })
    }

    pub fn get_map_by_name(&self, name: &str) -> Result<BpfMap, String> {
        let map: *mut bpf_map = unsafe {
            bpf_object__find_map_by_name(self.bpf_obj, CString::new(name).unwrap().as_ptr())
        };

        if map == std::ptr::null_mut() {
            bail!(format!("error getting map by name. name: {}", name))
        }

        BpfMap::new(map)
    }

    pub fn pin_maps(&self, path: &str) -> Result<(), String> {
        let ret =
            unsafe { bpf_object__pin_maps(self.bpf_obj, CString::new(path).unwrap().as_ptr()) };

        if ret != 0 {
            bail!(format!("Error pinning maps: {}", ret));
        }

        Ok(())
    }

    pub fn unpin_maps(&self, path: &str) -> Result<(), String> {
        let ret =
            unsafe { bpf_object__unpin_maps(self.bpf_obj, CString::new(path).unwrap().as_ptr()) };

        if ret != 0 {
            bail!(format!("Error unpinning maps: {}", ret));
        }

        Ok(())
    }

    pub fn programs(&self) -> BpfPrograms {
        BpfPrograms {
            bpf_obj: self,
            bpf_prog_current: None,
        }
    }

    pub fn maps(&self) -> BpfMaps {
        BpfMaps {
            bpf_obj: self,
            bpf_map_current: None,
        }
    }

    fn next_map(&self, bpf_map_o: Option<*const bpf_map>) -> Option<*const bpf_map> {
        if None == bpf_map_o {
            let map = unsafe { bpf_map__next(std::ptr::null_mut(), self.bpf_obj) };

            if map == std::ptr::null_mut() {
                return None;
            }

            return Some(map);
        }

        let next = unsafe { bpf_map__next(bpf_map_o.unwrap(), self.bpf_obj) };

        if next == std::ptr::null_mut() {
            return None;
        }

        return Some(next);
    }

    fn next_prog(&self, bpf_prog_o: Option<*mut bpf_program>) -> Option<*mut bpf_program> {
        if None == bpf_prog_o {
            let prog = unsafe { bpf_program__next(std::ptr::null_mut(), self.bpf_obj) };

            if prog == std::ptr::null_mut() {
                return None;
            }

            return Some(prog);
        }

        let next = unsafe { bpf_program__next(bpf_prog_o.unwrap(), self.bpf_obj) };

        if next == std::ptr::null_mut() {
            return None;
        }

        return Some(next);
    }

    pub fn unload(&mut self) {
        unsafe { bpf_object__unload(self.bpf_obj) };
    }
}

pub struct BpfMaps<'a> {
    bpf_obj: &'a BpfObject,
    bpf_map_current: Option<*const bpf_map>,
}

impl<'a> Iterator for BpfMaps<'a> {
    type Item = *const bpf_map;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.bpf_obj.next_map(self.bpf_map_current);
        self.bpf_map_current = next;
        self.bpf_map_current
    }
}

pub struct BpfPrograms<'a> {
    bpf_obj: &'a BpfObject,
    bpf_prog_current: Option<*mut bpf_program>,
}

impl<'a> Iterator for BpfPrograms<'a> {
    type Item = *mut bpf_program;
    fn next(&mut self) -> Option<Self::Item> {
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

    pub fn load(self) -> Result<BpfObject, String> {
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
            bail!(format!("error loading xattr: {}", err));
        }

        Ok(BpfObject {
            bpf_obj: obj,
            first_prog_fd: first_prog_fd,
        })
    }
}
