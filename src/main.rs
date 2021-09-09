#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bindings;
mod db;

use db::Database;

fn main() {
    let mut db = Database::new().unwrap();
    //db.run_create_statements().unwrap();
    //db.build().unwrap();
    let args = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>();
    if let Ok(mut args) = args {
        if args.len() != 1 {
            println!("usage: buke 'query terms'");
            // print help
            return;
        }
        println!("Hello, world! {:?}", &args);
        let query = args.pop().unwrap();
        db.query(query).unwrap();
    }
}
