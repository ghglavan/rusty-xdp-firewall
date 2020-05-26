extern crate rusty_firewall;
use rusty_firewall::*;

use std::io::prelude::*;
use std::net::SocketAddr;

#[macro_use]
extern crate log;

use env_logger::Env;

use std::fs::File;
use std::io::{self, BufRead, Read};
use std::net::TcpStream;

use std::collections::HashMap;
use std::process::{Command, Stdio};

use clap::{App, Arg};

fn deserialize_result(r: &str) -> Result<CommandResult, serde_json::Error> {
    serde_json::from_str(r)
}

fn serialize_map(m: &HashMap<String, Vec<u8>>) -> Result<String, serde_json::Error> {
    serde_json::to_string(m)
}

fn send_command(
    command: &[u8],
    stream: &mut TcpStream,
) -> Result<bool, Box<dyn std::error::Error>> {
    stream.write(command)?;

    let mut buf: [u8; 2048] = [0; 2048];
    stream.read(&mut buf)?;

    let result_str = std::str::from_utf8(&buf)?
        .trim_matches(char::from(0))
        .trim_matches(char::from(10));
    let result = deserialize_result(result_str);
    let mut is_error = false;

    match result {
        Ok(r) => match r {
            CommandResult::Ok => (),
            CommandResult::Error(e) => {
                is_error = true;
                error!("{}", e);
            }
            CommandResult::Message(m) => {
                println!("{}", m);
            }
        },
        Err(e) => {
            is_error = true;
            error!("internal: could not deserialize {}: {}", result_str, e);
        }
    };

    Ok(is_error)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("rusty_helper")
        .version("0.1")
        .author("Gheorghe Glavan <george.glavan27@gmail.com>")
        .about("Rusty firewall helper for managing programs and maps")
        .arg(
            Arg::with_name("ip")
                .short("-I")
                .takes_value(true)
                .help("Daemon ip if it is on another machine (localhost by default)"),
        )
        .arg(
            Arg::with_name("port")
                .short("-P")
                .takes_value(true)
                .help("Daemon port if a custom one was specifiend for it"),
        )
        .arg(
            Arg::with_name("command")
                .short("-c")
                .takes_value(true)
                .help("Command to be sent to the daemon (between ' ')"),
        )
        .arg(
            Arg::with_name("from_file")
                .short("-f")
                .conflicts_with("command")
                .takes_value(true)
                .help("send commands from a file. WARNING! on error, all previous commands will take effect"),
        ).get_matches();

    let env = Env::default().filter_or("RUSTY_LOG_LEVEL", "debug");
    env_logger::init_from_env(env);

    let ip = matches.value_of("ip").unwrap_or("127.0.0.1");
    let port = matches.value_of("port").unwrap_or("63336");

    let addr = ip.to_owned() + ":" + port;

    let sock_addr: SocketAddr = (addr)
        .parse()
        .map_err(|e| format!("Error parsing address {}: {}", addr, e))?;
    let mut stream = TcpStream::connect(sock_addr)?;

    if matches.is_present("command") {
        let command = matches.value_of("command").unwrap();
        info!("single command mode. Sending: {}", command);
        send_command(command.as_bytes(), &mut stream)?;
    } else if matches.is_present("from_file") {
        let file = File::open(matches.value_of("from_file").unwrap())?;
        for line in io::BufReader::new(file).lines() {
            let cmd = line?;
            match send_command(&cmd.as_bytes(), &mut stream) {
                Ok(true) => break,
                Err(e) => error!("error sending command {}: {}", cmd, e),
                _ => (),
            };
        }
    } else {
        info!("entering interactive mode. Press Ctrl-C to stop or type end");
        info!("enter one command per line");

        let mut vars: HashMap<String, Vec<u8>> = HashMap::new();
        let mut parsers: HashMap<String, String> = HashMap::new();

        loop {
            print!("> ");
            io::stdout().flush()?;
            let buffer = io::stdin().lock().lines().next().unwrap()?;

            if buffer.len() == 0 {
                continue;
            }

            if buffer == "end" {
                break;
            }

            let args = buffer.split(" ").collect::<Vec<&str>>();

            if args.len() == 0 {
                continue;
            }

            if args[0] == "map" {
                if args.len() == 4 && args[1] == "parser" {
                    let (p_name, p_cmd) = (args[2], args[3]);
                    parsers.insert(p_name.to_string(), p_cmd.to_string());
                    info!("added parser {} with cmd {} to parsers", p_name, p_cmd);
                    continue;
                }
            }

            if let Some('$') = args[0].chars().next() {
                if args.len() < 3 {
                    error!(
                        "expected 3 arguments to set the variable, got {}",
                        args.len()
                    );
                    continue;
                }
                let (var, parser, parg) = (args[0], args[1], args[2]);

                let parser_cmd = match parsers.get(parser) {
                    Some(p) => p,
                    None => {
                        error!("no parser found with name {}", parser);
                        continue;
                    }
                };

                let var_b = var.split(":").collect::<Vec<&str>>();

                if var_b.len() < 2 {
                    error!(
                        "no size specified for the variable: {}. Use $var_name:var_size_in_bytes",
                        var
                    );
                    continue;
                };
                let var = var_b[0];
                let v_size = match var_b[1].parse::<usize>() {
                    Ok(x) => x,
                    Err(e) => {
                        error!("error parsing size from {}: {}", var_b[1], e);
                        continue;
                    }
                };

                let p = Command::new(parser_cmd).arg(parg).output();
                if let Err(e) = p {
                    error!("error executing parser: {}", e);
                    continue;
                }
                let p = p.unwrap();

                let bytes = p.stdout;
                if bytes.len() != v_size {
                    error!("expected {} bytes got {}", v_size, bytes.len());
                    match std::str::from_utf8(&p.stderr[..]) {
                        Ok(s) => error!("stderr: {}", s),
                        Err(e) => error!("error getting stderror: {}", e),
                    };
                    continue;
                }

                vars.insert(var.to_string(), bytes);
                for (k, v) in &vars {
                    info!("var: {:?}: {:?}", k, v);
                }
                continue;
            }

            let mut buff: Vec<u8> = buffer.as_bytes().to_vec();
            let mut c_vars: HashMap<String, Vec<u8>> = HashMap::new();

            let mut all_vars_found = true;
            for arg in &args {
                if let Some('$') = arg.chars().next() {
                    if let Some(x) = vars.get(&arg.to_string()) {
                        c_vars.insert(arg.to_string(), x.clone());
                    } else {
                        all_vars_found = false;
                        error!("could not find var {}", arg);
                        break;
                    }
                }
            }

            if !all_vars_found {
                continue;
            }

            if c_vars.len() != 0 {
                let d = serialize_map(&c_vars);
                let s = match d {
                    Ok(s) => s,
                    Err(e) => {
                        error!("error serializing {:?}: {}", c_vars, e);
                        continue;
                    }
                };
                buff.append(&mut vec!['\n' as u8]);
                buff.append(&mut s.as_bytes().to_vec());
            }

            info!("sending {}", std::str::from_utf8(buff.as_slice())?);

            match send_command(&buff.as_slice(), &mut stream) {
                Ok(_) => (),
                Err(e) => error!("error sending command {}: {}", buffer, e),
            }
        }
    }

    Ok(())
}
