use std::env;

use vigenere::{decode, encode, print_table};

/*
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        return help(&args);
    }

    match args[1].as_str() {
        "--help" | "-h" | "help" => help(&args),
        "--encode" | "-e" | "encode" => println!("{}", encode(&args[2], &args[3])),
        "--decode" | "-d" | "decode" => println!("{}", decode(&args[2], &args[3])),
        "--table" | "-t" | "table" => print_table(),
        _ => help(&args),
    }
}

fn help(args: &[String]) {
    println!(
        r#"Usage:
    {} --table
    {} --encode <text> <key>
    {} --decode <text> <key>"#,
        args[0], args[0], args[0]
    );
}
*/

fn main() {
    loop {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer).unwrap();
        let mut split = buffer.split(":");
        let a = split.next().unwrap_or_default();
        let b = split.next().unwrap_or_default().trim_right();
        //println!("|{}||{}|", a, b);
        //println!("{}", encode(a, b));
        println!("{}", decode(a, b));
    }
}
