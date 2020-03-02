#[macro_use]
pub extern crate error_chain;
pub mod errors;
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
}
