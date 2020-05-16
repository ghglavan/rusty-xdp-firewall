extern crate libbpf_helpers;
extern crate rusty_firewall;
use rusty_firewall::*;

use libbpf_helpers::object::*;
use libbpf_helpers::program::*;
use libbpf_helpers::raw_libbpf::*;

extern crate tokio;
use tokio::net::TcpListener;
use tokio::prelude::*;

use clap::clap_app;
use std::net::SocketAddr;

#[macro_use]
extern crate log;

use env_logger::Env;
use std::collections::HashMap;

#[macro_use]
extern crate lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref LOADED_OBJS: Mutex<HashMap<String, BpfObject>> = Mutex::new(HashMap::new());
    static ref LOADED_PROGS: Mutex<HashMap<String, BpfProgram>> = Mutex::new(HashMap::new());
}

fn serialize_result(r: &CommandResult) -> Result<String, serde_json::Error> {
    serde_json::to_string(r)
}

fn load_program(name: &str, path: &str) -> CommandResult {
    let object = BpfObjectLoader::new()
        .with_file_name(path)
        .with_prog_type(BPF_PROG_TYPE_XDP)
        .load();

    match object {
        Ok(o) => {
            LOADED_OBJS.lock().unwrap().insert(name.to_string(), o);
            CommandResult::Ok
        }
        Err(e) => CommandResult::Error(format!(
            "error loading object {} from {}: {}",
            name, path, e
        )),
    }
}

fn attach_program(obj_name: &str, prog_name: &str, ifname: &str) -> CommandResult {
    match LOADED_OBJS.lock().unwrap().get(obj_name) {
        Some(obj) => {
            let prog = obj.get_prog_by_name(prog_name);

            match prog {
                Ok(p) => {
                    let a = p.get_attacher();

                    if a.is_err() {
                        return CommandResult::Error(format!(
                            "error getting the attacher: {}",
                            a.err().unwrap()
                        ));
                    }

                    let mut a = a.unwrap();

                    let att = a.with_if(ifname);
                    if att.is_err() {
                        return CommandResult::Error(format!(
                            "no interface with the name {}: {}",
                            ifname,
                            att.err().unwrap()
                        ));
                    }

                    let att = a.update_if_noexist().in_skb_mode().detach();
                    if att.is_err() {
                        return CommandResult::Error(format!(
                            "error detaching: {}",
                            att.err().unwrap()
                        ));
                    }

                    let a = a.attach();

                    if a.is_err() {
                        return CommandResult::Error(format!(
                            "error attaching: {}",
                            a.err().unwrap()
                        ));
                    }
                    CommandResult::Ok
                }
                Err(e) => CommandResult::Error(format!(
                    "no program with name {} in object {}: error {}",
                    prog_name, obj_name, e
                )),
            }
        }
        None => CommandResult::Error(format!("could not find object with name {}", obj_name)),
    }
}

fn list_objects() -> String {
    LOADED_OBJS
        .lock()
        .unwrap()
        .iter()
        .map(|(k, _)| format!("{}", k))
        .collect::<Vec<String>>()
        .join("\n")
}

fn list_obj_programs(name: &str) -> CommandResult {
    match LOADED_OBJS.lock().unwrap().get(name) {
        Some(obj) => {
            let programs = obj.get_progs_names().join("\n");
            CommandResult::Message(programs)
        }
        None => CommandResult::Error(format!("no obj with name {}", name)),
    }
}

fn list_obj_maps(name: &str) -> CommandResult {
    match LOADED_OBJS.lock().unwrap().get(name) {
        Some(obj) => {
            let maps = obj.get_maps_names().join("\n");
            CommandResult::Message(maps)
        }
        None => CommandResult::Error(format!("no obj with name {}", name)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let main_app = clap_app!(rusty_daemon =>
        (version: "0.1")
        (author: "Gheorghe Glavan <george.glavan27@gmail.com>")
        (about: "Rusty firewall daemon resposible for loading, unloading xdp programs and maps and updating maps")
        (@arg ip: +takes_value -i --ip "The ip to bind to")
        (@arg port: +takes_value -p --port "The port to bind to")
    )
    .get_matches();

    let env = Env::default().filter_or("RUSTY_LOG_LEVEL", "debug");
    env_logger::init_from_env(env);

    let ip = main_app.value_of("ip").unwrap_or("127.0.0.1");
    let port = main_app.value_of("port").unwrap_or("63336");

    let addr = ip.to_owned() + ":" + port;
    info!("binding to addr: {}", addr);

    let sock_addr: SocketAddr = (addr)
        .parse()
        .map_err(|e| format!("Error parsing address {}: {}", addr, e))?;

    let mut listener = TcpListener::bind(sock_addr)
        .await
        .map_err(|e| format!("Could not bid to {}: {}", addr, e))?;

    loop {
        let (mut socket, _) = listener
            .accept()
            .await
            .map_err(|e| format!("Error listening on {}: {}", addr, e))?;

        tokio::spawn(async move {
            loop {
                let mut buf = [0; 2048];

                match socket.read(&mut buf).await {
                    // socket closed
                    Ok(n) if n == 0 => return,
                    Ok(n) => n,
                    Err(e) => {
                        error!("failed to read from socket; err = {:?}", e);
                        return;
                    }
                };

                let message = match std::str::from_utf8(&buf) {
                    Ok(command_string) => {
                        debug!("got command {}", command_string);
                        let s = command_string
                            .trim_matches(char::from(0))
                            .trim_matches(char::from(10));
                        let mut s = s.split(" ").collect::<Vec<&str>>();
                        s.reverse();

                        let l1_commands = vec!["load, list, attach", "help"];

                        match s.pop() {
                            Some("help") => CommandResult::Message(format!(
                                "available commands: \n\t{}",
                                l1_commands.join(" ")
                            )),
                            Some("list") => {
                                let list_arguments =
                                    vec!["internal_maps", "obj_programs", "obj_maps"];
                                match s.pop() {
                                    Some("help") => CommandResult::Message(format!(
                                        "available commands for list:\n\t {}",
                                        list_arguments.join(" ")
                                    )),
                                    Some("internal_maps") => {
                                        let maps = vec!["objs", "progs", "maps"];
                                        match s.pop() {
                                            Some("help") => CommandResult::Message(format!(
                                                "available maps:\n\t\t{}",
                                                maps.join(" ")
                                            )),
                                            Some("objs") => CommandResult::Message(list_objects()),
                                            a => CommandResult::Error(format!(
                                                "internal_maps: could not parse {:?}",
                                                a
                                            )),
                                        }
                                    }
                                    Some("obj_programs") => {
                                        let programs_args = vec!["obj_name"];
                                        match s.pop() {
                                            Some("help") => CommandResult::Message(format!(
                                                "available arguments for objs_programs: {}",
                                                programs_args.join(" ")
                                            )),
                                            Some(n) => list_obj_programs(n),
                                            a => CommandResult::Error(format!(
                                                "obj_programs: could not parse {:?}",
                                                a
                                            )),
                                        }
                                    }
                                    Some("obj_maps") => {
                                        let maps_args = vec!["obj_name"];
                                        match s.pop() {
                                            Some("help") => CommandResult::Message(format!(
                                                "available arguments for objs_maps: {}",
                                                maps_args.join(" ")
                                            )),
                                            Some(n) => list_obj_maps(n),
                                            a => CommandResult::Error(format!(
                                                "obj_maps: could not parse {:?}",
                                                a
                                            )),
                                        }
                                    }
                                    a => CommandResult::Error(format!(
                                        "list: could not parse {:?}",
                                        a
                                    )),
                                }
                            }
                            Some("attach") => {
                                let attach_arguments = vec!["obj", "prog_name", "interface_name"];
                                match (s.pop(), s.pop(), s.pop()) {
                                    (a, b, c)
                                        if a == Some("help")
                                            || b == Some("help")
                                            || c == Some("help") =>
                                    {
                                        CommandResult::Message(format!(
                                            "available arguments for attach:\n\t {}",
                                            attach_arguments.join(" ")
                                        ))
                                    }
                                    (Some(a), Some(b), Some(c)) => attach_program(a, b, c),
                                    (a, b, c) => CommandResult::Error(format!(
                                        "attach: could not parse {:?} {:?} {:?}",
                                        a, b, c
                                    )),
                                }
                            }
                            Some("load") => {
                                let l2_arguments = vec!["name", "path"];
                                match (s.pop(), s.pop()) {
                                    (Some("help"), _) | (_, Some("help")) => {
                                        CommandResult::Message(format!(
                                            "available commands for load:\n\t {}",
                                            l2_arguments.join(" ")
                                        ))
                                    }
                                    (Some(name), Some(path)) => load_program(name, path),
                                    (a, b) => CommandResult::Error(format!(
                                        "load: could not parse {:?} {:?}",
                                        a, b
                                    )),
                                }
                            }
                            Some(c) => CommandResult::Error(format!(
                                "unknown command {}, available: {}",
                                c,
                                l1_commands.join(" ")
                            )),
                            None => CommandResult::Error("no command specified".to_string()),
                        }
                    }
                    Err(r) => CommandResult::Error(format!(
                        "error parsing utf8 string from message: {}",
                        r
                    )),
                };

                info!("sending message: {:?}", message);

                let m = serialize_result(&message);

                if let Err(e) = m {
                    error!("could not serialize '{:?}': {}", message, e);
                    return;
                }

                if let Err(e) = socket.write_all(m.unwrap().as_bytes()).await {
                    error!("error sending message '{:?}': {}", message, e);
                    return;
                }
            }
        });
    }
}

// fn main() -> Result<(), String> {
//     let object1 = BpfObjectLoader::new()
//         .with_file_name("objs/main_module.o")
//         .with_prog_type(BPF_PROG_TYPE_XDP)
//         .load()?;

//     object1
//         .programs()
//         .for_each(|prog| println!("object 1 got program: {}", prog.get_title_owned().unwrap()));

//     let object2 = BpfObjectLoader::new()
//         .with_file_name("objs/tail_call.o")
//         .with_prog_type(BPF_PROG_TYPE_XDP)
//         .load()?;

//     object2
//         .programs()
//         .for_each(|prog| println!("object 2 got program {}", prog.get_title_owned().unwrap()));

//     let first_prog = object1.get_prog_by_name("xdp_tail_call0")?;
//     let second_prog = object2.get_prog_by_name("xdp_tail_call1")?;

//     let mut prog_maps1 = object1
//         .get_map_by_name::<u32, u32>("xdp_progs_map")?
//         .get_fd()?;

//     let k = 0_u32;

//     prog_maps1.update_elem(&k, &(second_prog.get_fd()? as u32), BPF_ANY)?;

//     let prog_maps2 = object2.get_map_by_name::<u32, u32>("xdp_progs_map")?;

//     prog_maps2.reuse_fd(prog_maps1)?;

//     first_prog
//         .get_attacher()?
//         .with_if("lo")?
//         .update_if_noexist()
//         .in_skb_mode()
//         .detach()?
//         .attach()?;

//     println!("xdp program attached to lo");

//     while true {}
//     Ok(())
// }
