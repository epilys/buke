/*
 * ____
 *
 * Copyright ____  Manos Pitsidianakis
 *
 * This file is part of ____.
 *
 * ____ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ____ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ____. If not, see <http://www.gnu.org/licenses/>.
 */

use super::bindings::{
    self, sqlite3, sqlite3_bind_int, sqlite3_bind_text, sqlite3_close, sqlite3_column_int, sqlite3_column_text,
    sqlite3_exec, sqlite3_finalize, sqlite3_open_v2, sqlite3_prepare_v2, sqlite3_reset,
    sqlite3_step, sqlite3_stmt, SQLITE_OK, SQLITE_OPEN_CREATE, SQLITE_OPEN_READONLY,
    SQLITE_OPEN_READWRITE, SQLITE_ROW,
};
use flate2::read::GzDecoder;
use std::collections::*;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

struct Statement {
    ptr: std::ptr::NonNull<sqlite3_stmt>,
}

impl Drop for Statement {
    fn drop(&mut self) {
        let ret = unsafe { sqlite3_finalize(self.ptr.as_mut()) };
        if ret as u32 != SQLITE_OK {
            eprintln!("sqlite3_finalize returned {}", ret);
        }
    }
}
impl Statement {
    pub fn new(db: &mut Database, sql: &'static [u8]) -> Result<Self, String> {
        let mut ptr = std::ptr::null_mut();
        let ret = unsafe {
            sqlite3_prepare_v2(
                db.ptr.as_mut(),
                sql.as_ptr() as _,
                sql.len() as _,
                &mut ptr,
                &mut std::ptr::null(),
            )
        };
        let ptr = if let Some(ptr) = std::ptr::NonNull::new(ptr) {
            ptr
        } else {
            let errmsg = unsafe { bindings::sqlite3_errstr(ret) };
            let slice = unsafe { std::ffi::CStr::from_ptr(errmsg) };
            return Err(format!(
                "stmts: {:?}: {}",
                unsafe { std::str::from_utf8_unchecked(sql) },
                slice.to_str().unwrap().to_string()
            ));
        };

        Ok(Statement { ptr })
    }

    pub fn bind_text(&mut self, index: usize, text: &str) -> Result<(), String> {
        let ret = unsafe {
            sqlite3_bind_text(
                self.ptr.as_mut(),
                index as _,
                text.as_bytes().as_ptr() as _,
                text.len() as _,
                None,
            )
        };
        if ret as u32 != SQLITE_OK {
            return Err(format!("sqlite3_bind_text returned {}", ret));
        }
        Ok(())
    }

    pub fn bind_int(&mut self, index: usize, int: usize) -> Result<(), String> {
        let ret = unsafe { sqlite3_bind_int(self.ptr.as_mut(), index as _, int as _) };
        if ret as u32 != SQLITE_OK {
            return Err(format!("sqlite3_bind_int returned {}", ret));
        }
        Ok(())
    }

    pub fn step(&mut self) -> Result<bool, String> {
        let ret = unsafe { sqlite3_step(self.ptr.as_mut()) };
        //if ret as u32 != SQLITE_OK {
        //   return Err(format!("sqlite3_step returned {}", ret));
        //}
        //eprintln!("step returned {}", ret);
        Ok(ret as u32 == SQLITE_ROW)
    }
    pub fn reset(&mut self) -> Result<(), String> {
        let ret = unsafe { sqlite3_reset(self.ptr.as_mut()) };
        if ret as u32 != SQLITE_OK {
            return Err(format!("sqlite3_reset returned {}", ret));
        }
        Ok(())
    }
}

pub struct Database {
    ptr: std::ptr::NonNull<sqlite3>,
    readonly: bool,
}

impl Drop for Database {
    fn drop(&mut self) {
        let ret = unsafe { sqlite3_close(self.ptr.as_mut()) };
        if ret as u32 != SQLITE_OK {
            eprintln!("sqlite3_close returned {}", ret);
        }
    }
}

impl Database {
    pub fn new() -> Result<Self, String> {
        let mut db = std::ptr::null_mut();
        let ret = unsafe {
            sqlite3_open_v2(
                b"mans.db\0".as_ptr() as _,
                &mut db,
                (SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE) as _,
                std::ptr::null(),
            )
        };
        let ptr = if let Some(ptr) = std::ptr::NonNull::new(db) {
            ptr
        } else {
            let errmsg = unsafe { bindings::sqlite3_errstr(ret) };
            let slice = unsafe { std::ffi::CStr::from_ptr(errmsg) };
            return Err(slice.to_str().unwrap().to_string());
        };
        Ok(Database {
            ptr,
            readonly: false,
        })
    }

    pub fn run_create_statements(&mut self) -> Result<(), String> {
        let sql = b"CREATE TABLE IF NOT EXISTS page( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, section INT NOT NULL, path TEXT NOT NULL UNIQUE, last_modified INT NOT NULL); CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(id UNINDEXED, name, content, detail=none, tokenize=\"trigram\");\0";

        let mut errmsg = std::ptr::null_mut();
        let ret = unsafe {
            sqlite3_exec(
                self.ptr.as_mut(),
                sql.as_ptr() as _,
                None,
                std::ptr::null_mut(),
                &mut errmsg,
            )
        };
        if ret as u32 != SQLITE_OK {
            let slice = unsafe { std::ffi::CStr::from_ptr(errmsg) };
            return Err(slice.to_str().unwrap().to_string());
        }
        Ok(())
    }

    pub fn build(&mut self) -> Result<(), String> {
        let key = "MANPATH";
        let dirs = match env::var_os(key) {
            Some(paths) => paths,
            None => return Err(format!("{} is not defined in the environment.", key)),
        };
        let mut sections: HashMap<String, Vec<std::path::PathBuf>> = Default::default();
        let mut queue: HashSet<std::path::PathBuf> = Default::default();

        for dir in env::split_paths(&dirs) {
            println!("'{}'", dir.display());
            if let Ok(dir) = std::fs::read_dir(dir) {
                for direntry in dir {
                    if let Ok(direntry) = direntry {
                        let path = direntry.path();
                        println!("'{}'", path.display());
                        if path.is_dir()
                            && path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .map(|n| n.starts_with("man"))
                                .unwrap_or(false)
                        {
                            queue.insert(path);
                        }
                    }
                }
            }
        }
        let mut pages: HashSet<std::path::PathBuf> = Default::default();
        let mut datums: HashMap<std::path::PathBuf, String> = Default::default();
        println!("{:#?}", &queue);
        for section in queue.drain() {
            if let Ok(dir) = std::fs::read_dir(section) {
                for direntry in dir {
                    if let Ok(direntry) = direntry {
                        let path = direntry.path();
                        println!("'{}'", path.display());
                        if path.is_file()
                            && path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .map(|n| n.ends_with("gz"))
                                .unwrap_or(false)
                        {
                            pages.insert(path);
                        }
                    }
                }
            }
        }
        println!("{:#?}", &pages);

        let mut stmt_insert = Statement::new( self, b"INSERT INTO page(name, section, path,last_modified) VALUES(?, ?, ?, 0) RETURNING id\0")?;
        let mut stmt_fts = Statement::new(self, b"INSERT INTO fts(id, name, content) VALUES(?, ?, ?)\0")?;

        for page in pages.drain() {
            if let Ok(mut f) = File::open(&page) {
                let mut bytes = vec![];
                if f.read_to_end(&mut bytes).is_ok() {
                    println!("writing {:#?}", &page);
                    let mut d = GzDecoder::new(bytes.as_slice());
                    let mut bytes2 = vec![];
                    if d.read_to_end(&mut bytes2).is_ok() {
                        let mut mandoc = std::process::Command::new("mandoc")
                            .args(["-T", "utf8"])
                            .stdin(std::process::Stdio::piped())
                            .stdout(std::process::Stdio::piped())
                            .spawn()
                            .unwrap();
                        let mut stdin = mandoc.stdin.take().expect("Failed to open stdin");
                        std::thread::spawn(move || {
                            stdin.write_all(&bytes2).unwrap();
                        });
                        println!("mandoc {:#?}", &page);
                        let s = String::from_utf8_lossy(
                            &mandoc
                                .wait_with_output()
                                .expect("Failed to read stdout")
                                .stdout,
                        )
                        .to_string();
                        println!("inserting {:#?}", &page);
                        let fname = page.file_name().unwrap().to_str().unwrap().trim_end_matches(".gz");
                        stmt_insert.bind_text(1, fname)?;
                        stmt_insert.bind_int(2, 1)?;
                        //stmt_insert.bind_text(3, &s)?;
                        stmt_insert.bind_text(3, page.to_str().unwrap())?;
                        if stmt_insert.step()? {
                            let id = unsafe { sqlite3_column_int(stmt_insert.ptr.as_mut(), 0) };

                            println!("inserting id {}", id);
                            stmt_fts.bind_int(1, id as _)?;
                            stmt_fts.bind_text(2, fname)?;
                            stmt_fts.bind_text(3, &s)?;
                            stmt_fts.step()?;
                            stmt_fts.reset()?;
                        }
                        stmt_insert.reset()?;

                        //datums.insert(page, s);
                    }
                }
            }
        }
        println!("{:#?}", datums.len());
        drop(stmt_insert);
        drop(stmt_fts);

        Ok(())
    }

    pub fn query(&mut self, mut query: String) -> Result<(), String> {
        let mut names : BTreeSet<String> = Default::default();
        if !query.starts_with("*") {
            query.insert(0, '*');
        }
        if !query.ends_with("*") {
            query.push('*');
        }
        {
        let mut stmt = Statement::new(self, b"select name from fts where name glob ? ORDER BY bm25(fts) LIMIT 15\0")?;
        //let query = query.replace("\"", "\"\"");
        stmt.bind_text(1, &query)?;
        while stmt.step()? {
            let ptr = unsafe { sqlite3_column_text(stmt.ptr.as_mut(), 0) };
            if ptr.is_null() {
                continue;
            }
            let slice = unsafe { std::ffi::CStr::from_ptr(ptr as _) };
            let s = slice.to_string_lossy();
            println!("{}", s);
            names.insert(s.to_string());
        }

        drop(stmt);
        }
        println!("\ncontent matches:");
        let mut stmt = Statement::new(self, b"select name from fts where content glob ? ORDER BY bm25(fts) LIMIT 15\0")?;
        //let query = query.replace("\"", "\"\"");
        stmt.bind_text(1, &query)?;
        while stmt.step()? {
            let ptr = unsafe { sqlite3_column_text(stmt.ptr.as_mut(), 0) };
            if ptr.is_null() {
                continue;
            }
            let slice = unsafe { std::ffi::CStr::from_ptr(ptr as _) };
            let s = slice.to_string_lossy();
            if names.contains(s.as_ref()) {
                continue;
            }
            println!("{}", s);
        }

        drop(stmt);

        Ok(())
    }
}
