fn errno_to_str<'a>(err: i32) -> &'a str {
    unsafe {
        std::ffi::CStr::from_ptr(libc::strerror(err))
            .to_str()
            .unwrap()
    }
}

error_chain! {
    foreign_links {
        Io(::std::io::Error);
        FFIString(::std::ffi::IntoStringError);
        FFINul(::std::ffi::NulError);
        UTF(::std::str::Utf8Error);
    }

    errors {
        LoadXAttrFailed(en: i32, file: String) {
            description("bpf_prog_load_xattr failed")
            display("bpf_prog_load_xattr for {} failed with: '{}'", file, self::errno_to_str(*en))
        }

        InvalidInterface(en: i32, ifname: String) {
            description("invalid interface")
            display("interface {} could not be converted to index: {}", ifname, self::errno_to_str(*en))
        }

        InvalidProgName(name: String) {
            description("program name not found")
            display("could not find a program with name {}", name)
        }

        InvalidProgFD {
            description("use of invalid program fd")
            display("could not get program fd")
        }

        InvalidUtf8Str(s: String) {
            description("could not convert to utf8")
            display("error converting to utf8: {}", s)
        }

        XdpAttachFailed(en: i32, prog_name: String) {
            description("could not attach xdp")
            display("error attaching xdp program {}: {}", prog_name, self::errno_to_str(*en))
        }

        XdpDetachFailed(en: i32, prog_name: String) {
            description("could not detach xdp")
            display("error detaching xdp program {}: {}", prog_name, self::errno_to_str(*en))
        }

        ProgNotXdp {
            description("bpf program is not xdp")
            display("this bpf program is not")
        }
    }
}
