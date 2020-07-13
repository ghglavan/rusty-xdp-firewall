use std::io::{self, Read, Write};
use std::env;
use std::net::Ipv4Addr;

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

        let mut s_arr: [u8; 4] = [0; 4];
        s_arr[0] = bytes[0];
        s_arr[1] = bytes[1];
        s_arr[2] = bytes[2];
        s_arr[3] = bytes[3];

        let i: Ipv4Addr = Ipv4Addr::from(s_arr);

        println!("{}", i);
    } else {
        let n: Ipv4Addr = args[1].parse().unwrap();
        let o = n.octets();
        io::stdout().write_all(&o).expect("could not write");
    }
}
