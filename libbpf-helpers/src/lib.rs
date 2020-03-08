#[macro_use]
pub extern crate error_chain;
pub mod errors;
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
        let m = crate::map::BpfMapCreator::<u32, u32>::new()
            .with_name("m")
            .with_type(crate::raw_libbpf::BPF_MAP_TYPE_ARRAY)
            .with_max_entries(100)
            .create();

        assert!(m.is_ok())
    }

    #[test]
    fn test_map_ops() {
        let m = crate::map::BpfMapCreator::<u32, u32>::new()
            .with_name("m")
            .with_type(crate::raw_libbpf::BPF_MAP_TYPE_HASH)
            .with_max_entries(100)
            .create();

        assert!(m.is_ok());
        let m = m.unwrap();
        let mut k = 10_u32;
        let mut v = 3_u32;
        assert!(m.update_elem(&k, &v, crate::raw_libbpf::BPF_ANY).is_ok());
        assert!(m.update_elem(&k, &k, crate::raw_libbpf::BPF_EXIST).is_ok());
        assert!(m
            .update_elem(&k, &v, crate::raw_libbpf::BPF_NOEXIST)
            .is_err());

        k = 1;
        assert!(m
            .update_elem(&k, &v, crate::raw_libbpf::BPF_NOEXIST)
            .is_ok());
        k = 2;
        v = 7;
        assert!(m
            .update_elem(&k, &v, crate::raw_libbpf::BPF_NOEXIST)
            .is_ok());

        let l = m.lookup_elem(&k);
        assert!(l.is_ok());
        assert!(l.unwrap() == 7);

        let l = m.lookup_elem_flags(&k, crate::raw_libbpf::BPF_EXIST);
        assert!(l.is_err());

        let l = m.lookup_elem_flags(&k, crate::raw_libbpf::BPF_NOEXIST);
        assert!(l.is_err());

        // not supported in 5.0 (the version that im testing with right now)
        // let k = 1;
        // let l = m.lookup_and_delete_elem(&k);

        //BPF_F_LOCK not supported in 5.0

        let l = m.delete_elem(&k);
        assert!(l.is_ok());

        let unused_key = 0_u32;
        let mut v = m.keys(unused_key).collect::<Vec<u32>>();
        v.sort();
        assert!(v == vec![1, 10]);
    }
}
