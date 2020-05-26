#[macro_use]
extern crate error_chain;
pub mod map;
pub mod object;
pub mod program;
pub mod xdp_attacher;
pub use libbpf_sys as raw_libbpf;

#[cfg(test)]
mod tests {
    #[test]
    fn test_empty_object() {
        assert!(crate::object::BpfObjectLoader::new().load().is_err());
    }

    #[test]
    fn test_valid_object() {
        assert!(crate::object::BpfObjectLoader::new()
            .with_file_name("../objs/hello_prog.o")
            .with_prog_type(crate::object::BPF_PROG_TYPE_XDP)
            .load()
            .is_ok())
    }

    #[test]
    fn test_obj_get_name() {
        let obj = crate::object::BpfObjectLoader::new()
            .with_file_name("../objs/hello_prog.o")
            .with_prog_type(crate::object::BPF_PROG_TYPE_XDP)
            .load();
        assert!(obj.is_ok());

        let obj = obj.unwrap();
        let name = obj.get_name();

        assert!(name.is_ok());
        assert!(name.unwrap() == "hello_prog".to_string());
    }

    #[test]
    fn test_obj_get_progs_names() {
        let obj = crate::object::BpfObjectLoader::new()
            .with_file_name("../objs/hello_prog.o")
            .with_prog_type(crate::object::BPF_PROG_TYPE_XDP)
            .load();
        assert!(obj.is_ok());

        let obj = obj.unwrap();
        let progs_names = obj.get_progs_names();

        assert!(progs_names == vec!["xdp"]);
    }

    #[test]
    fn test_prog_title_valid() {
        let obj = crate::object::BpfObjectLoader::new()
            .with_file_name("../objs/hello_prog.o")
            .with_prog_type(crate::object::BPF_PROG_TYPE_XDP)
            .load();
        assert!(obj.is_ok());
        let obj = obj.unwrap();

        let prog = obj.get_prog_by_name("xdp");
        assert!(prog.is_ok());

        let prog = prog.unwrap();
        let prog_name = prog.get_title_not_owned();
        assert!(prog_name.is_ok());

        let prog_name = prog_name.unwrap();
        assert!(prog_name == "xdp");
    }

    #[test]
    fn test_pin_map() {
        let object = crate::object::BpfObjectLoader::new()
            .with_file_name("../objs/hello_prog.o")
            .with_prog_type(crate::map::BPF_PROG_TYPE_XDP)
            .load();
        assert!(object.is_ok());
        let object = object.unwrap();
        let map = object.get_map_by_name("xdp_test_map");
        assert!(map.is_ok());
        let map = map.unwrap();

        let maps_path = "/sys/fs/bpf/xdp_test_map";

        assert!(map.pin(maps_path).is_ok());
        assert!(map.unpin(maps_path).is_ok());
    }

    #[test]
    fn test_prog_title_invalid() {
        let obj = crate::object::BpfObjectLoader::new()
            .with_file_name("../objs/hello_prog.o")
            .with_prog_type(crate::object::BPF_PROG_TYPE_XDP)
            .load();
        assert!(obj.is_ok());
        let obj = obj.unwrap();

        let prog = obj.get_prog_by_name("bogus");
        assert!(prog.is_err())
    }

    #[test]
    fn test_map_create() {
        let m = crate::map::BpfMapCreator::new(1, 1)
            .with_name("m")
            .with_type(crate::raw_libbpf::BPF_MAP_TYPE_ARRAY)
            .with_max_entries(100)
            .create();

        assert!(m.is_ok())
    }

    #[test]
    fn test_hash_map_ops() {
        let m = crate::map::BpfMapCreator::new(1, 1)
            .with_name("m")
            .with_type(crate::raw_libbpf::BPF_MAP_TYPE_HASH)
            .with_max_entries(100)
            .create();

        assert!(m.is_ok());
        let mut m = m.unwrap();
        let mut k = vec![10 as u8];
        let mut v = vec![3 as u8];
        assert!(m.update_elem(&k, &v, crate::raw_libbpf::BPF_ANY).is_ok());
        assert!(m.update_elem(&k, &k, crate::raw_libbpf::BPF_EXIST).is_ok());
        assert!(m
            .update_elem(&k, &v, crate::raw_libbpf::BPF_NOEXIST)
            .is_err());

        k = vec![1 as u8];
        assert!(m
            .update_elem(&k, &v, crate::raw_libbpf::BPF_NOEXIST)
            .is_ok());
        k = vec![2 as u8];
        v = vec![7 as u8];
        assert!(m
            .update_elem(&k, &v, crate::raw_libbpf::BPF_NOEXIST)
            .is_ok());

        let l = m.lookup_elem(&k);
        assert!(l.is_ok());
        assert!(l.unwrap() == vec![7 as u8]);

        let l = m.lookup_elem_flags(&k, crate::raw_libbpf::BPF_EXIST);
        assert!(l.is_err());

        let l = m.lookup_elem_flags(&k, crate::raw_libbpf::BPF_NOEXIST);
        assert!(l.is_err());

        //lookup_and_delete_elem is not worky with hash maps

        let l = m.delete_elem(&k);
        assert!(l.is_ok());

        let mut v = m.keys().collect::<Vec<Vec<u8>>>();
        v.sort();
        assert!(v == vec![vec![1 as u8], vec![10 as u8]]);
    }

    #[test]
    fn test_array_map_ops() {
        let m = crate::map::BpfMapCreator::new(1, 1)
            .with_name("array_m")
            .with_type(crate::raw_libbpf::BPF_MAP_TYPE_ARRAY)
            .with_max_entries(100)
            .create();

        assert!(m.is_ok());

        let mut m = m.unwrap();
        let k = vec![10 as u8];
        let v = vec![3 as u8];

        assert!(m.update_elem(&k, &v, crate::raw_libbpf::BPF_ANY).is_ok());
    }

    #[test]
    fn test_map_bpf_f_lock() {
        let object = crate::object::BpfObjectLoader::new()
            .with_file_name("../objs/hello_prog.o")
            .with_prog_type(crate::map::BPF_PROG_TYPE_XDP)
            .load();
        assert!(object.is_ok());
        let object = object.unwrap();
        let map = object.get_map_by_name("xdp_test_map");
        assert!(map.is_ok());
        let map = map.unwrap();
        let m = map.get_fd();
        assert!(m.is_ok());
        let m = m.unwrap();

        let k = vec![0 as u8; 4];
        let l = m.lookup_elem_flags(&k, crate::raw_libbpf::BPF_F_LOCK);
        assert!(l.is_ok());
    }
}
