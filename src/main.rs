extern crate libbpf_helpers;

#[macro_use]
use libbpf_helpers::object::*;
use libbpf_helpers::program::*;
use libbpf_helpers::raw_libbpf::*;

fn main() -> Result<(), String> {
    let object1 = BpfObjectLoader::new()
        .with_file_name("objs/main_module.o")
        .with_prog_type(BPF_PROG_TYPE_XDP)
        .load()?;

    object1
        .programs()
        .for_each(|prog| println!("object 1 got program: {}", prog.get_title_owned().unwrap()));

    let object2 = BpfObjectLoader::new()
        .with_file_name("objs/tail_call.o")
        .with_prog_type(BPF_PROG_TYPE_XDP)
        .load()?;

    object2
        .programs()
        .for_each(|prog| println!("object 2 got program {}", prog.get_title_owned().unwrap()));

    let first_prog = object1.get_prog_by_name("xdp_tail_call0")?;
    let second_prog = object2.get_prog_by_name("xdp_tail_call1")?;

    let mut prog_maps1 = object1
        .get_map_by_name::<u32, u32>("xdp_progs_map")?
        .get_fd()?;

    let k = 0_u32;

    prog_maps1.update_elem(&k, &(second_prog.get_fd()? as u32), BPF_ANY)?;

    let prog_maps2 = object2.get_map_by_name::<u32, u32>("xdp_progs_map")?;

    prog_maps2.reuse_fd(prog_maps1)?;

    // let prog_1 = object.get_prog_by_name("xdp_tail_call_1")?;
    // let prog_2 = object.get_prog_by_name("xdp_tail_call_2")?;
    // let mut prog_maps = object
    //     .get_map_by_name::<u32, u32>("xdp_progs_map")?
    //     .get_fd()?;

    // let k = 0_u32;

    // prog_maps.update_elem(&k, &(prog_2.get_fd()? as u32), BPF_ANY)?;

    first_prog
        .get_attacher()?
        .with_if("lo")?
        .update_if_noexist()
        .in_skb_mode()
        .detach()?
        .attach()?;

    println!("xdp program attached to lo");

    while true {}
    Ok(())
}
