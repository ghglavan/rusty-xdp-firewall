extern crate hex;
use std::io::{self, Read, Write};

use hex::FromHex;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("no argument provided");
        return;
    }

    if args[1] == "-r" {
        let mut bytes: Vec<u8> = Vec::new();
        for b in io::stdin().bytes() {
            bytes.push(b.unwrap());
            if bytes.len() == 6 {
                break;
            }
        }

        if bytes.len() != 6 {
            eprintln!("expected 6 bytes, got {}", bytes.len());
            return;
        }

        println!("{}", hex::encode(bytes));
    } else {
        let v = args[1].split(":").collect::<Vec<&str>>().join("");

        let raw = <[u8; 6]>::from_hex(v).expect("could not convert");
        io::stdout().write_all(&raw).expect("could not write");
    }
}
