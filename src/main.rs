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

fn main() {
    let mut db = Database::new().unwrap();
    db.run_create_statements().unwrap();
    let args = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>();
    if let Ok(mut args) = args {
        if args.len() < 1 {
            println!("usage: buke [--build] [--list] [--count] 'query terms'");
            return;
        }
        while let Some(query) = args.pop() {
            if query == "--build" {
                db.build().unwrap();
            } else if query == "--list" {
                db.list().unwrap();
                break;
            } else if query == "--count" {
                db.count().unwrap();
                break;
            } else {
                db.query(query).unwrap();
            }
        }
    }
}
