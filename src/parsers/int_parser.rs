use std::io::{self, Read, Write};

use std::env;

extern crate byteorder;
use byteorder::{ByteOrder, LittleEndian};

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
            if bytes.len() == 4 {
                break;
            }
        }

        if bytes.len() != 4 {
            eprintln!("expected 4 bytes, got {}", bytes.len());
            return;
        }

        println!("{}", LittleEndian::read_i32(&bytes[..]));
    } else {
        let n: i32 = args[1].parse().unwrap();
        let vn = vec![n];
        let mut v: [u8; 4] = [0; 4];
        LittleEndian::write_i32_into(&vn, &mut v);

        io::stdout().write_all(&v).expect("could not write");
    }
}
