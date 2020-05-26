extern crate hex;
use std::io::{self, Read, Write};

use hex::FromHex;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if (args.len() < 2) {
        eprintln!("no argument provided");
        return;
    }

    let v = args[1].split(":").collect::<Vec<&str>>().join("");

    let raw = <[u8; 6]>::from_hex(v).expect("could not convert");

    io::stdout().write_all(&raw).expect("could not write");
}
