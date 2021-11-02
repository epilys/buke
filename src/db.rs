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

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bindings;
use self::bindings::{
    sqlite3, sqlite3_bind_int, sqlite3_bind_text, sqlite3_close, sqlite3_column_int,
    sqlite3_column_int64, sqlite3_column_text, sqlite3_exec, sqlite3_finalize, sqlite3_open_v2,
    sqlite3_prepare_v2, sqlite3_reset, sqlite3_step, sqlite3_stmt, SQLITE_OK, SQLITE_OPEN_CREATE,
    SQLITE_OPEN_READWRITE, SQLITE_ROW,
};
mod vfs;
use flate2::read::GzDecoder;
use regex::Regex;
use std::collections::*;
use std::env;
use std::fs::File;
use std::io::prelude::*;

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

    pub fn get_text(&mut self, index: usize) -> Result<String, String> {
        let ptr = unsafe { sqlite3_column_text(self.ptr.as_mut(), index as _) };
        if ptr.is_null() {
            return Err(format!("sqlite3_column_text {} returned Null", index));
        }
        let slice = unsafe { std::ffi::CStr::from_ptr(ptr as _) };
        Ok(slice.to_string_lossy().to_string())
    }

    pub fn get_int(&mut self, index: usize) -> Result<usize, String> {
        let val = unsafe { sqlite3_column_int64(self.ptr.as_mut(), index as _) };
        Ok(val as usize)
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
#[cfg(feature = "re")]
unsafe extern "C" fn _sqlite_regexp(
    ctx: *mut self::bindings::sqlite3_context,
    argc: ::std::os::raw::c_int,
    argv: *mut *mut self::bindings::sqlite3_value,
) {
    use self::bindings::{
        sqlite3_result_error, sqlite3_result_int, sqlite3_value, sqlite3_value_text,
    };
    assert_eq!(argc, 2);
    let slice: &mut [*mut sqlite3_value] = std::slice::from_raw_parts_mut(argv, argc as usize);
    let re_pattern: *const ::std::os::raw::c_uchar = sqlite3_value_text(slice[0]);
    let re_match: *const ::std::os::raw::c_uchar = sqlite3_value_text(slice[1]);
    let re_pattern = std::ffi::CStr::from_ptr(re_pattern as _);
    let re_match = std::ffi::CStr::from_ptr(re_match as _);
    match (
        re_pattern
            .to_str()
            .map_err(|err| err.to_string())
            .and_then(|s| regex::Regex::new(s).map_err(|err| err.to_string())),
        re_match.to_str().map_err(|err| err.to_string()),
    ) {
        (Ok(re_pattern), Ok(re_match)) => {
            //eprintln!("matching {:?} with {:?}", &re_pattern, &re_match);
            sqlite3_result_int(ctx, re_pattern.is_match(re_match) as _);
        }
        (Err(err), _) | (Ok(_), Err(err)) => {
            eprintln!("regex err:{} ", &err);
            let string = std::ffi::CString::new(err).unwrap();
            sqlite3_result_error(ctx, string.as_ptr(), -1);
        }
    }
}

impl Database {
    pub fn new() -> Result<Self, String> {
        let gz_vfs = vfs::Vfs::new()?;
        std::mem::forget(gz_vfs);
        let mut db = std::ptr::null_mut();
        let ret = unsafe {
            sqlite3_open_v2(
                b"mans.db\0".as_ptr() as _,
                &mut db,
                (SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE) as _,
                b"gz\0".as_ptr() as _,
            )
        };
        let mut ptr = if let Some(ptr) = std::ptr::NonNull::new(db) {
            ptr
        } else {
            let errmsg = unsafe { bindings::sqlite3_errstr(ret) };
            let slice = unsafe { std::ffi::CStr::from_ptr(errmsg) };
            return Err(slice.to_str().unwrap().to_string());
        };
        #[cfg(feature = "re")]
        {
            use self::bindings::{sqlite3_create_function, SQLITE_DETERMINISTIC, SQLITE_UTF8};
            let _ret = unsafe {
                sqlite3_create_function(
                    ptr.as_mut(),
                    b"regexp\0".as_ptr() as _,
                    2,
                    (SQLITE_UTF8 | SQLITE_DETERMINISTIC) as _,
                    std::ptr::null_mut(),
                    Some(_sqlite_regexp),
                    None,
                    None,
                )
            };
        }
        Ok(Database {
            ptr,
            readonly: false,
        })
    }

    pub fn run_create_statements(&mut self) -> Result<(), String> {
        let sql = b"CREATE TABLE IF NOT EXISTS page( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL, section INT NOT NULL, path TEXT NOT NULL UNIQUE, last_modified INT NOT NULL); CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(id UNINDEXED, name, content, detail=none, tokenize=\"trigram\");\0";

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
        let mut queue: HashSet<std::path::PathBuf> = Default::default();

        for dir in env::split_paths(&dirs) {
            //println!("'{}'", dir.display());
            if let Ok(dir) = std::fs::read_dir(dir) {
                for direntry in dir.flatten() {
                    let path = direntry.path();
                    //println!("'{}'", path.display());
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
        let mut pages: HashSet<std::path::PathBuf> = Default::default();
        //println!("{:#?}", &queue);
        for section in queue.drain() {
            if let Ok(dir) = std::fs::read_dir(section) {
                for direntry in dir.flatten() {
                    let path = direntry.path();
                    //println!("'{}'", path.display());
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
        //println!("{:#?}", &pages);

        let mut stmt_insert = Statement::new( self, b"INSERT OR IGNORE INTO page(name, description, section, path,last_modified) VALUES(?, ?, ?, ?, 0)\0")?;
        let mut stmt_id = Statement::new(self, b"SELECT id FROM page WHERE name IS ?\0")?;
        let mut stmt_fts = Statement::new(
            self,
            b"INSERT OR IGNORE INTO fts(id, name, content) VALUES(?, ?, ?)\0",
        )?;

        stmt_insert.reset()?;
        stmt_id.reset()?;
        stmt_fts.reset()?;
        let nl_re = Regex::new(r"\n(?P<S>\S)").unwrap();
        let ws_re = Regex::new(r"\s\s+").unwrap();
        for page in pages.drain() {
            if let Ok(mut f) = File::open(&page) {
                let mut bytes = vec![];
                if f.read_to_end(&mut bytes).is_ok() {
                    //println!("writing {:#?}", &page);
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
                        let mandoc_output = mandoc
                            .wait_with_output()
                            .expect("Failed to read stdout")
                            .stdout;
                        let mut col = std::process::Command::new("col")
                            .args(["-b"])
                            .stdin(std::process::Stdio::piped())
                            .stdout(std::process::Stdio::piped())
                            .spawn()
                            .unwrap();
                        let mut stdin = col.stdin.take().expect("Failed to open stdin");
                        std::thread::spawn(move || {
                            stdin.write_all(&mandoc_output).unwrap();
                        });
                        //println!("mandoc {:#?}", &page);
                        let s = String::from_utf8_lossy(
                            &col.wait_with_output()
                                .expect("Failed to read stdout")
                                .stdout,
                        )
                        .to_string();
                        let description = if let Some(start_pos) = s.find("NAME") {
                            if let Some(end_pos) = s[start_pos..].find("\n\n") {
                                let desc =
                                    s[start_pos + "NAME".len()..(start_pos + end_pos)].trim();
                                ws_re
                                    .replace_all(&nl_re.replace_all(desc, "$S"), " ")
                                    .to_string()
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        };
                        //println!("DESC IS {:?}", &description);
                        //println!("inserting {:#?}", &page);
                        let fname = page
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .trim_end_matches(".gz");
                        stmt_insert.bind_text(1, fname)?;
                        stmt_insert.bind_text(2, &description)?;
                        stmt_insert.bind_int(3, 1)?;
                        //stmt_insert.bind_text(3, &s)?;
                        stmt_insert.bind_text(4, page.to_str().unwrap())?;
                        stmt_insert.step()?;
                        stmt_insert.reset()?;
                        stmt_id.bind_text(1, fname)?;
                        if stmt_id.step()? {
                            let id = unsafe { sqlite3_column_int(stmt_id.ptr.as_mut(), 0) };

                            //println!("inserting id {}", id);
                            stmt_fts.bind_int(1, id as _)?;
                            stmt_fts.bind_text(2, fname)?;
                            stmt_fts.bind_text(3, &s)?;
                            stmt_fts.step()?;
                            stmt_fts.reset()?;
                        }
                        stmt_id.reset()?;
                    }
                }
            }
        }
        drop(stmt_insert);
        drop(stmt_fts);

        Ok(())
    }

    pub fn query(&mut self, mut query: String, is_re: bool) -> Result<bool, String> {
        let mut names: BTreeSet<String> = Default::default();
        if !is_re {
            if !query.starts_with("*") {
                query.insert(0, '*');
            }
            if !query.ends_with("*") {
                query.push('*');
            }
        }
        let mut results: Vec<(String, String)> = Default::default();
        {
            let mut stmt = Statement::new(
                self,
                if is_re {
                    b"select fts.name, page.description from fts as fts JOIN page ON page.id=fts.id where fts.name REGEXP ? ORDER BY bm25(fts) LIMIT 15\0"
                } else {
                    b"select fts.name, page.description from fts as fts JOIN page ON page.id=fts.id where fts.name GLOB ? ORDER BY bm25(fts) LIMIT 15\0"
                },
            )?;
            //let query = query.replace("\"", "\"\"");
            stmt.bind_text(1, &query)?;
            while stmt.step()? {
                let name = stmt.get_text(0)?;
                let description = stmt.get_text(1)?;
                //let description = String::new();
                //println!("{} - {}", name, description);
                names.insert(name.to_string());
                results.push((name, description));
            }

            drop(stmt);
        }
        let mut any_match = !results.is_empty();
        let first_col_width = results.iter().map(|(n, _)| n.len()).max().unwrap_or(1);
        for (name, description) in results {
            println!(
                "{:width$} - {:.55}",
                name,
                description,
                width = first_col_width
            );
        }
        let mut results: Vec<(String, String)> = Default::default();
        let mut stmt = Statement::new(
            self,
            if is_re {
                b"select fts.name, page.description from fts as fts JOIN page ON page.id=fts.id where fts.content REGEXP ? ORDER BY bm25(fts) LIMIT 15\0"
            } else {
                b"select fts.name, page.description from fts as fts JOIN page ON page.id=fts.id where fts.content GLOB ? ORDER BY bm25(fts) LIMIT 15\0"
            },
            //b"select name, description from page where name REGEXP ? or content LIMIT 15\0",
        )?;
        //let query = query.replace("\"", "\"\"");
        stmt.bind_text(1, &query)?;
        while stmt.step()? {
            let name = stmt.get_text(0)?;
            let description = stmt.get_text(1)?;
            if names.contains(name.as_str()) {
                continue;
            }
            results.push((name, description));
        }
        any_match |= !results.is_empty();
        let first_col_width = results.iter().map(|(n, _)| n.len()).max().unwrap_or(1);
        if !results.is_empty() {
            println!("\ncontent matches:");
        }
        for (name, description) in results {
            println!(
                "{:width$} - {:.55}",
                name,
                description,
                width = first_col_width
            );
        }

        drop(stmt);

        Ok(any_match)
    }

    pub fn list(&mut self) -> Result<(), String> {
        let mut stmt = Statement::new(self, b"select name, description from page ORDER BY name\0")?;
        let mut results: Vec<(String, String)> = Default::default();
        while stmt.step()? {
            let name = stmt.get_text(0)?;
            let description = stmt.get_text(1)?;
            results.push((name, description));
        }
        let first_col_width = results.iter().map(|(n, _)| n.len()).max().unwrap_or(1);
        for (name, description) in results {
            println!(
                "{:width$} - {:.55}",
                name,
                description,
                width = first_col_width
            );
        }
        drop(stmt);
        Ok(())
    }

    pub fn count(&mut self) -> Result<(), String> {
        let mut stmt = Statement::new(self, b"select count(*) from page\0")?;
        while stmt.step()? {
            let count = stmt.get_int(0)?;
            println!("{}", count);
        }
        drop(stmt);
        Ok(())
    }
}
