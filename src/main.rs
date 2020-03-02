extern crate libbpf_helpers;

#[macro_use]
use libbpf_helpers::error_chain::*;
use libbpf_helpers::errors::*;
use libbpf_helpers::object::*;
use libbpf_helpers::program::*;
use libbpf_helpers::raw_libbpf::*;

fn run() -> Result<()> {
    let object = BpfObjectLoader::new()
        .with_file_name("objs/hello_prog.o")
        .with_prog_type(BPF_PROG_TYPE_XDP)
        .load()?;

    object
        .programs()
        .for_each(|prog| println!("got program: {}", prog.get_title_owned().unwrap()));

    let xdp = object.get_prog_by_name("xdp")?;
    xdp.get_attacher()?
        .with_if("lo")?
        .update_if_noexist()
        .in_skb_mode()
        .detach()?
        .attach()?;
    println!("xdp program attached to lo");
    Ok(())
}

quick_main!(run);
