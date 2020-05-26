extern crate libbpf_helpers;
extern crate rusty_firewall;
use rusty_firewall::*;

use libbpf_helpers::map::*;
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
use std::sync::Arc;

#[macro_use]
extern crate lazy_static;
use std::sync::Mutex;

use std::mem::transmute;

static PROGS_MAP: &str = "xdp_progs_map";
static LOCALHOST: &str = "127.0.0.1";
static PORT: &str = "63336";
static DEFAULT_MAIN_MODULE: &str = "objs/main_module.o";
static DEFAULT_MAIN_PROG: &str = "xdp_tail_call0";

enum PinType {
    Map(MapFDRaw),
    Prog(ProgFDRaw),
}

struct PinnedEnt {
    pin_type: PinType,
    pin_name: String,
    pin_path: String,
}

impl PinnedEnt {
    fn new_map(pin_name: String, pin_path: String, fd: MapFDRaw) -> PinnedEnt {
        PinnedEnt {
            pin_type: PinType::Map(fd),
            pin_name,
            pin_path,
        }
    }
    fn new_prog(pin_name: String, pin_path: String, fd: ProgFDRaw) -> PinnedEnt {
        PinnedEnt {
            pin_type: PinType::Prog(fd),
            pin_name,
            pin_path,
        }
    }
}

struct HandledObject {
    obj: BpfObject,
    pinnned_entities: Vec<PinnedEnt>,
}

impl HandledObject {
    fn new(obj: BpfObject) -> HandledObject {
        HandledObject {
            obj,
            pinnned_entities: Vec::new(),
        }
    }
}

struct HandledProgram {
    prog: BpfProgram,
    parent_obj: Arc<HandledObject>,
}

impl HandledProgram {
    fn new(prog: BpfProgram, parent_obj: Arc<HandledObject>) -> HandledProgram {
        HandledProgram { prog, parent_obj }
    }
}

lazy_static! {
    static ref LOADED_OBJS: Mutex<HashMap<String, Arc<HandledObject>>> = Mutex::new(HashMap::new());
    static ref TAILED_PROGS: Mutex<HashMap<String, Vec<Arc<HandledProgram>>>> =
        Mutex::new(HashMap::new());
    static ref ATTACHED_IFS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ref MAIN_MODULE: Mutex<Option<BpfObject>> = Mutex::new(None);
    static ref MAIN_PROG: Mutex<Option<BpfProgram>> = Mutex::new(None);
    static ref MAIN_PROG_MAP: Mutex<Option<BpfMap>> = Mutex::new(None);
}

fn serialize_result(r: &CommandResult) -> Result<String, serde_json::Error> {
    serde_json::to_string(r)
}

fn validate_obj(obj: &BpfObject) -> Result<(), String> {
    let m = obj.get_map_by_name(PROGS_MAP)?;
    let t = m.get_map_type()?;
    if t != BPF_MAP_TYPE_PROG_ARRAY {
        return Err(format!(
            "Expected map of type {} for {}, got {}",
            BPF_MAP_TYPE_PROG_ARRAY, PROGS_MAP, t
        ));
    }
    Ok(())
}

fn load_object(name: &str, path: &str) -> CommandResult {
    if LOADED_OBJS.lock().unwrap().contains_key(name) {
        return CommandResult::Error(format!(
            "an object with the name {} is already loaded",
            name
        ));
    }
    let object = BpfObjectLoader::new()
        .with_file_name(path)
        .with_prog_type(BPF_PROG_TYPE_XDP)
        .load();

    let object = match object {
        Ok(o) => o,
        Err(e) => {
            return CommandResult::Error(format!(
                "error loading object {} from {}: {}",
                name, path, e
            ))
        }
    };

    if let Err(e) = validate_obj(&object) {
        return CommandResult::Error(format!("program {} from {} is invalid: {}", name, path, e));
    }

    LOADED_OBJS
        .lock()
        .unwrap()
        .insert(name.to_string(), Arc::new(HandledObject::new(object)));
    CommandResult::Ok
}

fn attach_main_program(ifname: &str) -> CommandResult {
    match *MAIN_PROG.lock().unwrap() {
        Some(ref p) => {
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
                return CommandResult::Error(format!("error detaching: {}", att.err().unwrap()));
            }
            let a = a.attach();
            if a.is_err() {
                return CommandResult::Error(format!("error attaching: {}", a.err().unwrap()));
            }
            ATTACHED_IFS.lock().unwrap().push(ifname.to_string());
            CommandResult::Ok
        }
        _ => panic!("main program not found"),
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
        Some(o) => {
            let programs = o.obj.get_progs_names().join("\n");
            CommandResult::Message(programs)
        }
        None => CommandResult::Error(format!("no obj with name {}", name)),
    }
}

fn list_obj_maps(name: &str) -> CommandResult {
    match LOADED_OBJS.lock().unwrap().get(name) {
        Some(o) => {
            let maps = o.obj.get_maps_names().join("\n");
            CommandResult::Message(maps)
        }
        None => CommandResult::Error(format!("no obj with name {}", name)),
    }
}

fn tail_prog(obj: &str, pname: &str, ifname: &str, index: usize) -> CommandResult {
    let prog = match LOADED_OBJS.lock().unwrap().get(obj) {
        Some(o) => match o.obj.get_prog_by_name(pname) {
            Ok(p) => Arc::new(HandledProgram::new(p, o.clone())),
            Err(r) => {
                return CommandResult::Error(format!(
                    "no program with name {} is in {}",
                    pname, obj
                ))
            }
        },
        None => return CommandResult::Error(format!("no program with the name {} is loaded", obj)),
    };

    if !ATTACHED_IFS.lock().unwrap().contains(&ifname.to_string()) {
        return CommandResult::Error(format!("no program attached to {}", ifname));
    }

    let mut t = TAILED_PROGS.lock().unwrap();

    let mut no_key = false;
    let max_index = if !t.contains_key(ifname) {
        no_key = true;
        0
    } else {
        t.get(ifname).unwrap().len()
    };

    if max_index < index {
        return CommandResult::Error(format!("index {} too big. max: {}", index, max_index));
    }
    if no_key {
        t.insert(ifname.to_string(), Vec::new());
    }
    let pfd = match prog.prog.get_fd() {
        Ok(fd) => fd,
        Err(e) => return CommandResult::Error(format!("error getting program for {}", pname)),
    };

    let bytes_fd: [u8; 4] = unsafe { transmute(pfd as u32) };
    let bytes_pfd_vec = bytes_fd.to_vec();
    let k = vec![0 as u8; 4];

    if index == 0 {
        // if max_index > 0 {
        //     match prog.parent_obj.get_map_by_name(MAIN_PROG_MAP) {
        //         Ok(m) => match map.get_fd {
        //             Ok(mut fd) => (),
        //             Err(e) => return
        //         },
        //         Err(e) => return CommandResult::Error("the object {} has no progs map", e),
        //     }
        // }

        match &*MAIN_PROG_MAP.lock().unwrap() {
            Some(map) => match map.get_fd() {
                Ok(mut fd) => match fd.update_elem(&k, &bytes_pfd_vec, BPF_ANY) {
                    Ok(()) => (),
                    Err(e) => {
                        return CommandResult::Error(format!("error updating main prog map: {}", e))
                    }
                },
                Err(e) => {
                    return CommandResult::Error(format!(
                        "could not get fd for the main prog map: {}",
                        e
                    ))
                }
            },

            None => return CommandResult::Error(format!("NO MIN PPROGS MAP")),
        }
    } else {
        let prev_obj = t.get(ifname).unwrap()[index - 1].parent_obj.clone();
        let prev_prog_map = (*prev_obj).obj.get_map_by_name(PROGS_MAP).unwrap();
        match prev_prog_map.get_fd() {
            Ok(mut fd) => match fd.update_elem(&k, &bytes_pfd_vec, BPF_ANY) {
                Ok(()) => (),
                Err(e) => {
                    return CommandResult::Error(format!(
                        "error updating prog map of object at index {}: {}",
                        index - 1,
                        e
                    ))
                }
            },
            Err(e) => {
                return CommandResult::Error(format!(
                    "could not get fd for the prog map of obj at index {}: {}",
                    index - 1,
                    e
                ))
            }
        }
    }

    t.get_mut(ifname).unwrap().insert(index, prog);
    CommandResult::Ok
}

fn obj_pin(obj_name: &str, pin_name: &str, pin_path: &str) -> CommandResult {
    CommandResult::Ok
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let main_app = clap_app!(rusty_daemon =>
        (version: "0.1")
        (author: "Gheorghe Glavan <george.glavan27@gmail.com>")
        (about: "Rusty firewall daemon resposible for loading, unloading xdp programs and maps and updating maps")
        (@arg ip: +takes_value -i --ip "The ip to bind to")
        (@arg port: +takes_value -p --port "The port to bind to")
        (@arg main_path: +takes_value -m --mpath "The main module to attach to an interface")
        (@arg main_prog: +takes_value -r --mprog "The program inside the main object to attach to an interface")
    )
    .get_matches();

    let env = Env::default().filter_or("RUSTY_LOG_LEVEL", "debug");
    env_logger::init_from_env(env);

    let ip = main_app.value_of("ip").unwrap_or(LOCALHOST);
    let port = main_app.value_of("port").unwrap_or(PORT);
    let main_path = main_app
        .value_of("main_path")
        .unwrap_or(DEFAULT_MAIN_MODULE);

    let main_prog = main_app.value_of("main_prog").unwrap_or(DEFAULT_MAIN_PROG);

    let object = BpfObjectLoader::new()
        .with_file_name(main_path)
        .with_prog_type(BPF_PROG_TYPE_XDP)
        .load()
        .map_err(|e| format!("Could not load the main object: {}", e))?;

    validate_obj(&object).map_err(|e| format!("module {} is invalid: {}", main_path, e));

    let prog = object
        .get_prog_by_name(main_prog)
        .map_err(|e| format!("Could not get the main program from the main module: {}", e))?;
    *(MAIN_PROG.lock().unwrap()) = Some(prog);

    let map = object
        .get_map_by_name(PROGS_MAP)
        .map_err(|e| format!("could not get the progs map from the main module: {}", e))?;
    *(MAIN_PROG_MAP.lock().unwrap()) = Some(map);

    *(MAIN_MODULE.lock().unwrap()) = Some(object);

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

                        let l1_commands = vec!["load", "list", "tail", "attach", "pin", "help"];

                        match s.pop() {
                            Some("help") => CommandResult::Message(format!(
                                "available commands: \n\t{}",
                                l1_commands.join(" ")
                            )),
                            Some("list") => {
                                let list_arguments = vec![
                                    "internal_maps",
                                    "obj_programs",
                                    "obj_maps",
                                    "attached_ifs",
                                ];
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
                                    Some("attached_ifs") => CommandResult::Message(
                                        ATTACHED_IFS.lock().unwrap().join("\n"),
                                    ),
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
                                let attach_arguments = vec!["interface_name"];
                                match s.pop() {
                                    Some("help") => CommandResult::Message(format!(
                                        "available arguments for attach:\n\t {}",
                                        attach_arguments.join(" ")
                                    )),
                                    Some(a) => attach_main_program(a),
                                    a => CommandResult::Error(format!(
                                        "attach: could not parse {:?}",
                                        a
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
                                    (Some(name), Some(path)) => load_object(name, path),
                                    (a, b) => CommandResult::Error(format!(
                                        "load: could not parse {:?} {:?}",
                                        a, b
                                    )),
                                }
                            }
                            Some("tail") => {
                                let tail_arguments =
                                    vec!["obj", "prog_name", "ifname", "tail_index"];
                                match (s.pop(), s.pop(), s.pop(), s.pop()) {
                                    (a, b, c, d)
                                        if a == Some("help")
                                            || b == Some("help")
                                            || c == Some("help")
                                            || d == Some("help") =>
                                    {
                                        CommandResult::Message(format!(
                                            "available arguments for tail:\n\t {}",
                                            tail_arguments.join(" ")
                                        ))
                                    }
                                    (a, b, c, Some(n)) if n.parse::<usize>().is_err() => {
                                        CommandResult::Error(format!(
                                            "could not parse {} as usize",
                                            n
                                        ))
                                    }
                                    (Some(obj), Some(pname), Some(ifname), Some(index)) => {
                                        tail_prog(
                                            obj,
                                            pname,
                                            ifname,
                                            index.parse::<usize>().unwrap(),
                                        )
                                    }
                                    (a, b, c, d) => CommandResult::Error(format!(
                                        "could not parse {:?} {:?} {:?} {:?}",
                                        a, b, c, d
                                    )),
                                }
                            }
                            Some("pin") => {
                                let pin_arguments = vec!["obj_name", "pin_name", "pin_path"];
                                match (s.pop(), s.pop(), s.pop()) {
                                    (a, b, c)
                                        if a == Some("help")
                                            || b == Some("help")
                                            || c == Some("help") =>
                                    {
                                        CommandResult::Message(format!(
                                            "available arguments for pin:\n\t {}",
                                            pin_arguments.join(" ")
                                        ))
                                    }
                                    (Some(a), Some(b), Some(c)) => obj_pin(a, b, c),
                                    (a, b, c) => CommandResult::Error(format!(
                                        "pin: could not parse {:?} {:?} {:?}",
                                        a, b, c
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
