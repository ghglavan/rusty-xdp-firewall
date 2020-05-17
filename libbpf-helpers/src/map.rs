pub(crate) use libbpf_sys::*;
use std::ffi::{CStr, CString};

use std::iter::Iterator;

#[derive(Debug)]
pub struct BpfMap<K, V> {
    pub(crate) bpf_map: *mut bpf_map,
    pub(crate) _k: std::marker::PhantomData<K>,
    pub(crate) _v: std::marker::PhantomData<V>,
}

pub fn get_name_raw(map: &*const bpf_map) -> Result<&str, String> {
    Ok(unsafe {
        CStr::from_ptr(bpf_map__name(*map))
            .to_str()
            .map_err(|e| format!("error getting map name: {}", e))?
    })
}

pub type MapFDRaw = i32;

impl<K, V> BpfMap<K, V> {
    pub fn get_fd(&self) -> Result<BpfMapFd<K, V>, String> {
        let fd = unsafe { bpf_map__fd(self.bpf_map) };

        if fd < 0 {
            bail!(format!("error getting fd: {}", fd));
        }

        Ok(BpfMapFd {
            inner_fd: fd,
            _k: std::marker::PhantomData,
            _v: std::marker::PhantomData,
        })
    }

    pub fn get_fd_raw(&self) -> Result<MapFDRaw, String> {
        Ok(self.get_fd()?.inner_fd)
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

    pub fn reuse_fd(&self, map_fd: BpfMapFd<K, V>) -> Result<(), String> {
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

pub struct BpfMapFd<K, V> {
    inner_fd: MapFDRaw,
    _k: std::marker::PhantomData<K>,
    _v: std::marker::PhantomData<V>,
}

impl<K, V> BpfMapFd<K, V> {
    pub fn get_fd_raw(&self) -> MapFDRaw {
        self.inner_fd
    }

    pub fn from_pinned_map(path: &str) -> Result<Self, String> {
        let fd = unsafe { bpf_obj_get(CString::new(path).unwrap().as_ptr()) };

        if fd < 0 {
            bail!(format!("error getting obj fd from {}: {}", path, fd));
        }

        Ok(BpfMapFd {
            inner_fd: fd,
            _k: std::marker::PhantomData,
            _v: std::marker::PhantomData,
        })
    }

    //flags: BPF_ANY, BPF_EXIST, BPF_NO_EXIST, BFP_F_LOCK
    pub fn update_elem(&mut self, key: &K, value: &V, flags: u32) -> Result<(), String> {
        let ret = unsafe {
            bpf_map_update_elem(
                self.inner_fd,
                key as *const K as *const core::ffi::c_void,
                value as *const V as *const core::ffi::c_void,
                flags as u64,
            )
        };

        if ret != 0 {
            bail!(format!("error updating element"))
        }

        Ok(())
    }

    pub fn lookup_elem_flags(&self, key: &K, flags: u32) -> Result<V, String> {
        let v: V = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            bpf_map_lookup_elem_flags(
                self.inner_fd,
                key as *const K as *const core::ffi::c_void,
                &v as *const V as *mut core::ffi::c_void,
                flags as u64,
            )
        };

        if ret != 0 {
            bail!(format!("error looking up for elem with flags {}", flags));
        }

        Ok(v)
    }

    pub fn lookup_elem(&self, key: &K) -> Result<V, String> {
        self.lookup_elem_flags(key, BPF_ANY)
    }

    pub fn lookup_and_delete_elem(&mut self, key: &K) -> Result<V, String> {
        let v: V = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            bpf_map_lookup_and_delete_elem(
                self.inner_fd,
                key as *const K as *const core::ffi::c_void,
                &v as *const V as *mut core::ffi::c_void,
            )
        };

        if ret != 0 {
            bail!("error looking up and deleting element")
        }

        Ok(v)
    }

    pub fn delete_elem(&mut self, key: &K) -> Result<(), String> {
        let ret = unsafe {
            bpf_map_delete_elem(self.inner_fd, key as *const K as *const core::ffi::c_void)
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

    pub fn keys(&self, unused_key: K) -> MapKeys<K> {
        MapKeys {
            map_fd: self.inner_fd,
            current_key: None,
            unused_key,
        }
    }
}

pub struct MapKeys<K> {
    map_fd: i32,
    current_key: Option<K>,
    unused_key: K,
}

impl<K: Copy> Iterator for MapKeys<K> {
    type Item = K;
    fn next(&mut self) -> Option<K> {
        if let Some(k) = &self.current_key {
            let next: K = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                bpf_map_get_next_key(
                    self.map_fd,
                    k as *const K as *const core::ffi::c_void,
                    &next as *const K as *mut core::ffi::c_void,
                )
            };

            if ret != 0 {
                return None;
            }

            self.current_key = Some(next);
            return self.current_key;
        };

        let next: K = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            bpf_map_get_next_key(
                self.map_fd,
                &self.unused_key as *const K as *const core::ffi::c_void,
                &next as *const K as *mut core::ffi::c_void,
            )
        };

        if ret != 0 {
            return None;
        }

        self.current_key = Some(next);
        self.current_key
    }
}

pub struct BpfMapCreator<K, V> {
    attrs: bpf_create_map_attr,
    _k: std::marker::PhantomData<K>,
    _v: std::marker::PhantomData<V>,
}

macro_rules! fn_with_u32_arg {
    ($name:ident, $x:ident) => {
        pub fn $name(&mut self, $x: __u32) -> &mut Self {
            self.attrs.$x = $x;
            self
        }
    };
}

impl<K, V> BpfMapCreator<K, V> {
    pub fn new() -> Self {
        BpfMapCreator {
            attrs: bpf_create_map_attr::default(),
            _k: std::marker::PhantomData,
            _v: std::marker::PhantomData,
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

    pub fn create(&mut self) -> Result<BpfMapFd<K, V>, String> {
        self.attrs.key_size = std::mem::size_of::<K>() as u32;
        self.attrs.value_size = std::mem::size_of::<V>() as u32;
        let fd = unsafe { bpf_create_map_xattr(&self.attrs as *const bpf_create_map_attr) };

        if fd < 0 {
            bail!("error creating map")
        }

        Ok(BpfMapFd {
            inner_fd: fd,
            _k: std::marker::PhantomData,
            _v: std::marker::PhantomData,
        })
    }
}
