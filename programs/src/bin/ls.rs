#![no_std]
#![no_main]
use metallium_programs::fs::*;
use metallium_programs::*;

// ls <dir>: prints the names (however many the directory has: it is read in pieces); exits with their number.
program!("ls", |c| {
    let path = c.argv(1).unwrap_or("/");
    match read_dir(path) {
        Ok(entries) => {
            for e in &entries {
                println!("{}{}", e.name, if e.is_dir { "/" } else { "" });
            }
            entries.len() as u64
        }
        Err(e) => 2000 + e.code as u64,
    }
});
