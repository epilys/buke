/*
 * buke
 *
 * Copyright 2021 buke  Manos Pitsidianakis
 *
 * This file is part of buke.
 *
 * buke is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * buke is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with buke. If not, see <http://www.gnu.org/licenses/>.
 */

mod db;

use db::Database;

fn run_app() -> Result<(), ()> {
    let args = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>();
    if let Ok(mut args) = args {
        if args.is_empty() {
            println!("usage: buke [--build] [--list] [--count] [-r|--re] 'query terms'");
            return Err(());
        }
        let is_re: bool = args.iter().any(|arg| arg == "-r" || arg == "--re");
        while let Some(arg) = args.pop() {
            if arg == "-r" || arg == "--re" {
                continue;
            } else if arg == "--build" {
                let mut db = Database::new(false).unwrap();
                db.run_create_statements().unwrap();
                db.build().unwrap();
            } else if arg == "--list" {
                let mut db = Database::new(true).unwrap();
                db.list().unwrap();
                break;
            } else if arg == "--count" {
                let mut db = Database::new(true).unwrap();
                db.count().unwrap();
                break;
            } else {
                let mut db = Database::new(true).unwrap();
                if !db.query(arg, is_re).unwrap() {
                    return Err(());
                }
            }
        }
    }
    Ok(())
}

fn main() {
    std::process::exit(match run_app() {
        Ok(_) => 0,
        Err(_) => 1,
    });
}
