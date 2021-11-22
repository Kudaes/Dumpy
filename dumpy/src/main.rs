
#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use std::env;

fn main() {

    start();
}

fn start() {

    let args: Vec<String> = env::args().collect();

    if args.len() < 2
    {   

        println!("{}",lc!("[x] Insufficient number of arguments."));
        print_help();
        return;
    } 

    match args[1].as_str()
    {
        "-h" => { print_help();},
        "dump" => 
        { 
            if args.len() < 3
            {   
        
                println!("{}",lc!("[x] Insufficient number of arguments."));
                print_help();
        
            } else 
            {        
                dumper::dump(&args[2]);
            }
        }
        "decrypt" => 
        { 
            if args.len() < 5
            {   
        
                println!("{}",lc!("[x] Insufficient number of arguments."));
                print_help();
        
            } else 
            {
                dumper::decrypt(&args[2], &args[4], &args[3])
            }
        
        }
        _ => {println!("{}",lc!("[x] Unknown option."));}
    }

}

fn print_help () {
    
    let s = lc!("
[*] Usage: dumpy.exe dump encryption_key
           dumpy.exe decrypt enrypted_file_path output_file_name encryption_key
           ");
    
    println!("{}", s);
}