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

use clap::{App, Arg};

fn deserialize_result(r: &str) -> Result<CommandResult, serde_json::Error> {
    serde_json::from_str(r)
}

fn send_command(command: &str, stream: &mut TcpStream) -> Result<bool, Box<dyn std::error::Error>> {
    stream.write(command.as_bytes())?;

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
        send_command(command, &mut stream)?;
    } else if matches.is_present("from_file") {
        let file = File::open(matches.value_of("from_file").unwrap())?;
        for line in io::BufReader::new(file).lines() {
            let cmd = line?;
            match send_command(&cmd, &mut stream) {
                Ok(true) => break,
                Err(e) => error!("error sending command {}: {}", cmd, e),
                _ => (),
            };
        }
    } else {
        info!("entering interactive mode. Press Ctrl-C to stop or type end");
        info!("enter one command per line");
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

            match send_command(&buffer, &mut stream) {
                Ok(_) => (),
                Err(e) => error!("error sending command {}: {}", buffer, e),
            }
        }
    }

    Ok(())
}
