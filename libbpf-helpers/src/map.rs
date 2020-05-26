pub(crate) use libbpf_sys::*;
use std::ffi::{CStr, CString};

use std::iter::Iterator;

pub fn get_map_name_raw(map: &*const bpf_map) -> Result<&str, String> {
    Ok(unsafe {
        CStr::from_ptr(bpf_map__name(*map))
            .to_str()
            .map_err(|e| format!("error getting map name: {}", e))?
    })
}

pub type MapFDRaw = i32;

#[derive(Debug)]
pub struct BpfMap {
    pub(crate) bpf_map: *mut bpf_map,
    pub(crate) key_size: usize,
    pub(crate) value_size: usize,
}

unsafe impl Send for BpfMap {}
unsafe impl Sync for BpfMap {}

impl BpfMap {
    pub fn new(m: *mut bpf_map) -> Result<BpfMap, String> {
        let map_def = unsafe { bpf_map__def(m) };
        if map_def == std::ptr::null() {
            return Err("error getting map_def".to_string());
        }

        let key_size = unsafe { (*map_def).key_size } as usize;

        let value_size = unsafe { (*map_def).value_size } as usize;

        Ok(BpfMap {
            bpf_map: m,
            key_size,
            value_size,
        })
    }

    pub fn get_fd(&self) -> Result<BpfMapFd, String> {
        let fd = unsafe { bpf_map__fd(self.bpf_map) };

        if fd < 0 {
            bail!(format!("error getting fd: {}", fd));
        }

        Ok(BpfMapFd {
            inner_fd: fd,
            key_size: self.key_size,
            value_size: self.value_size,
        })
    }

    pub fn get_fd_raw(&self) -> Result<MapFDRaw, String> {
        Ok(self.get_fd()?.inner_fd)
    }

    pub fn get_map_type(&self) -> Result<bpf_map_type, String> {
        let map_def = unsafe { bpf_map__def(self.bpf_map) };
        if map_def == std::ptr::null() {
            return Err("error getting map_def".to_string());
        }
        unsafe { return Ok((*map_def).type_) }
    }

    pub fn get_name(&self) -> Result<&str, String> {
        Ok(unsafe {
            CStr::from_ptr(bpf_map__name(self.bpf_map))
                .to_str()
                .map_err(|e| format!("error getting map name: {}", e))?
        })
    }

    pub fn pin(&self, path: &str) -> Result<(), String> {
        let ret = unsafe { bpf_map__pin(self.bpf_map, CString::new(path).unwrap().as_ptr()) };

        if ret != 0 {
            bail!(format!("Error pinning map: {}", ret));
        }

        Ok(())
    }

    pub fn unpin(&self, path: &str) -> Result<(), String> {
        let ret = unsafe { bpf_map__unpin(self.bpf_map, CString::new(path).unwrap().as_ptr()) };

        if ret != 0 {
            bail!(format!("Error unpinning map: {}", ret));
        }

        Ok(())
    }

    pub fn get_btf_key_type_id(&self) -> u32 {
        unsafe { bpf_map__btf_key_type_id(self.bpf_map) }
    }

    pub fn get_btf_value_type_id(&self) -> u32 {
        unsafe { bpf_map__btf_value_type_id(self.bpf_map) }
    }

    pub fn reuse_fd(&self, map_fd: BpfMapFd) -> Result<(), String> {
        let ret = unsafe { bpf_map__reuse_fd(self.bpf_map, map_fd.inner_fd) };

        if ret != 0 {
            bail!(format!("error reusing map : {}", ret))
        }

        Ok(())
    }

    pub fn resize(&self, max_entries: u32) -> Result<(), String> {
        let ret = unsafe { bpf_map__resize(self.bpf_map, max_entries) };

        if ret != 0 {
            bail!(format!("error resizing map : {}", ret))
        }

        Ok(())
    }
}

pub struct BpfMapFd {
    inner_fd: MapFDRaw,
    pub(crate) key_size: usize,
    pub(crate) value_size: usize,
}

impl BpfMapFd {
    pub fn get_fd_raw(&self) -> MapFDRaw {
        self.inner_fd
    }

    pub fn from_pinned_map(path: &str, key_size: usize, value_size: usize) -> Result<Self, String> {
        let fd = unsafe { bpf_obj_get(CString::new(path).unwrap().as_ptr()) };

        if fd < 0 {
            bail!(format!("error getting obj fd from {}: {}", path, fd));
        }

        Ok(BpfMapFd {
            inner_fd: fd,
            key_size,
            value_size,
        })
    }

    //flags: BPF_ANY, BPF_EXIST, BPF_NO_EXIST, BFP_F_LOCK
    pub fn update_elem(
        &mut self,
        key: &Vec<u8>,
        value: &Vec<u8>,
        flags: u32,
    ) -> Result<(), String> {
        if key.len() < self.key_size {
            bail!(format!(
                "wronng key size: expected {} got {}",
                self.key_size,
                key.len()
            ))
        }
        if value.len() < self.value_size {
            bail!(format!(
                "wronng value size: expected {} got {}",
                self.value_size,
                value.len()
            ))
        }

        let k = key.as_slice();
        let v = value.as_slice();

        let ret = unsafe {
            bpf_map_update_elem(
                self.inner_fd,
                k.as_ptr() as *const u8 as *const core::ffi::c_void,
                v.as_ptr() as *const u8 as *const core::ffi::c_void,
                flags as u64,
            )
        };

        if ret != 0 {
            bail!(format!("error updating element"))
        }

        Ok(())
    }

    pub fn lookup_elem_flags(&self, key: &Vec<u8>, flags: u32) -> Result<Vec<u8>, String> {
        if key.len() < self.key_size {
            bail!(format!(
                "wronng key size: expected {} got {}",
                self.key_size,
                key.len()
            ))
        }
        let vc: Vec<u8> = vec![0 as u8; self.value_size];
        let v = vc.as_slice();
        let k = key.as_slice();
        let ret = unsafe {
            bpf_map_lookup_elem_flags(
                self.inner_fd,
                k.as_ptr() as *const u8 as *const core::ffi::c_void,
                v.as_ptr() as *const u8 as *mut core::ffi::c_void,
                flags as u64,
            )
        };

        if ret != 0 {
            bail!(format!("error looking up for elem with flags {}", flags));
        }

        Ok(v.to_vec())
    }

    pub fn lookup_elem(&self, key: &Vec<u8>) -> Result<Vec<u8>, String> {
        self.lookup_elem_flags(key, BPF_ANY)
    }

    pub fn lookup_and_delete_elem(&mut self, key: &Vec<u8>) -> Result<Vec<u8>, String> {
        if key.len() < self.key_size {
            bail!(format!(
                "wronng key size: expected {} got {}",
                self.key_size,
                key.len()
            ))
        }
        let vc: Vec<u8> = vec![0 as u8; self.value_size];
        let v = vc.as_slice();
        let k = key.as_slice();
        let ret = unsafe {
            bpf_map_lookup_and_delete_elem(
                self.inner_fd,
                k.as_ptr() as *const u8 as *const core::ffi::c_void,
                v.as_ptr() as *const u8 as *mut core::ffi::c_void,
            )
        };

        if ret != 0 {
            bail!("error looking up and deleting element")
        }

        Ok(v.to_vec())
    }

    pub fn delete_elem(&mut self, key: &Vec<u8>) -> Result<(), String> {
        if key.len() < self.key_size {
            bail!(format!(
                "wronng key size: expected {} got {}",
                self.key_size,
                key.len()
            ))
        }
        let k = key.as_slice();
        let ret = unsafe {
            bpf_map_delete_elem(
                self.inner_fd,
                k.as_ptr() as *const u8 as *const core::ffi::c_void,
            )
        };

        if ret != 0 {
            bail!("error deleting element")
        }

        Ok(())
    }

    pub fn freeze(&self) -> Result<(), String> {
        if unsafe { bpf_map_freeze(self.inner_fd) < 0 } {
            bail!("error freezing")
        }

        Ok(())
    }

    pub fn keys(&self) -> MapKeys {
        MapKeys {
            map_fd: self.inner_fd,
            key_size: self.key_size,
            current_key: None,
            unused_key: vec![0 as u8; self.key_size],
        }
    }
}

pub struct MapKeys {
    map_fd: i32,
    key_size: usize,
    current_key: Option<Vec<u8>>,
    unused_key: Vec<u8>,
}

impl Iterator for MapKeys {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Vec<u8>> {
        if let Some(k) = &self.current_key {
            let vnext: Vec<u8> = vec![0 as u8; self.key_size];
            let next = vnext.as_slice();
            let key = k.as_slice();
            let ret = unsafe {
                bpf_map_get_next_key(
                    self.map_fd,
                    key.as_ptr() as *const u8 as *const core::ffi::c_void,
                    next.as_ptr() as *const u8 as *mut core::ffi::c_void,
                )
            };

            if ret != 0 {
                return None;
            }

            self.current_key = Some(next.to_vec());
            return self.current_key.clone();
        };

        let vnext: Vec<u8> = vec![0 as u8; self.key_size];
        let next = vnext.as_slice();
        let k = self.unused_key.as_slice();
        let ret = unsafe {
            bpf_map_get_next_key(
                self.map_fd,
                k.as_ptr() as *const u8 as *const core::ffi::c_void,
                next.as_ptr() as *const u8 as *mut core::ffi::c_void,
            )
        };

        if ret != 0 {
            return None;
        }

        self.current_key = Some(next.to_vec());
        self.current_key.clone()
    }
}

pub struct BpfMapCreator {
    attrs: bpf_create_map_attr,
    key_size: usize,
    value_size: usize,
}

macro_rules! fn_with_u32_arg {
    ($name:ident, $x:ident) => {
        pub fn $name(&mut self, $x: __u32) -> &mut Self {
            self.attrs.$x = $x;
            self
        }
    };
}

impl BpfMapCreator {
    pub fn new(key_size: usize, value_size: usize) -> Self {
        BpfMapCreator {
            attrs: bpf_create_map_attr::default(),
            key_size,
            value_size,
        }
    }

    pub fn with_name(&mut self, name: &str) -> &mut Self {
        let s = CString::new(name.to_owned()).unwrap();
        self.attrs.name = s.into_raw();
        self
    }

    fn_with_u32_arg!(with_flags, map_flags);
    fn_with_u32_arg!(with_max_entries, max_entries);
    fn_with_u32_arg!(with_numa_node, numa_node);
    fn_with_u32_arg!(with_btf_fd, btf_fd);
    fn_with_u32_arg!(with_btf_key_type_id, btf_key_type_id);
    fn_with_u32_arg!(with_btf_value_type_id, btf_value_type_id);
    fn_with_u32_arg!(with_map_ifindex, map_ifindex);
    //fn_with_u32_arg!(with_inner_map_fd, inner_map_fd);

    pub fn with_type(&mut self, map_type: bpf_map_type) -> &mut Self {
        self.attrs.map_type = map_type;
        self
    }

    pub fn create(&mut self) -> Result<BpfMapFd, String> {
        self.attrs.key_size = self.key_size as u32;
        self.attrs.value_size = self.value_size as u32;
        let fd = unsafe { bpf_create_map_xattr(&self.attrs as *const bpf_create_map_attr) };

        if fd < 0 {
            bail!("error creating map")
        }

        Ok(BpfMapFd {
            inner_fd: fd,
            key_size: self.key_size,
            value_size: self.value_size,
        })
    }
}
