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

use super::bindings::{
    sqlite3_errstr, sqlite3_file, sqlite3_int64, sqlite3_io_methods, sqlite3_vfs, sqlite3_vfs_find,
    sqlite3_vfs_register, SQLITE_IOCAP_ATOMIC, SQLITE_IOCAP_POWERSAFE_OVERWRITE,
    SQLITE_IOCAP_SAFE_APPEND, SQLITE_IOCAP_SEQUENTIAL, SQLITE_IOERR_SHORT_READ, SQLITE_NOTFOUND,
    SQLITE_OK, *,
};

use flate2::read::GzDecoder;

use flate2::Compression;
use flate2::GzBuilder;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::io::{Cursor, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use core::ffi::c_void;
use nix::sys::mman::MapFlags;
use nix::sys::mman::ProtFlags;
use std::fs::File;

use std::os::unix::io::AsRawFd;

const COMPRESSED_BLOCK_SIZE: usize = 12 * 4096;

pub struct Vfs {
    parent: std::ptr::NonNull<sqlite3_vfs>,
    inner: sqlite3_vfs,
    io_methods: sqlite3_io_methods,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum FileType {
    Main = 0,          /* Main database file */
    Journal = 1,       /* Rollback journal */
    Wal = 2,           /* Write-ahead log file */
    MasterJournal = 3, /* Master journal */
    SubJournal = 4,    /* Subjournal */
    TempDb = 5,        /* TEMP database */
    TempJournal = 6,   /* Journal for TEMP database */
    Transient = 7,     /* Transient database */
    Any = 8,           /* Unspecified file type */
}

pub type Offset = usize;
pub type BlockNo = usize;

#[repr(C)]
#[derive(Debug)]
pub struct GzFile {
    base: sqlite3_file,
    vfs: std::ptr::NonNull<Vfs>,
    buf: Cursor<Vec<u8>>,
    block_cache: BTreeMap<BlockNo, (Offset, Vec<u8>)>,
    file: File,
    index: BTreeMap<Offset, BlockNo>,
    dirty: Arc<Mutex<bool>>,
    path: std::ffi::OsString,
    filetype: FileType,
    sub: sqlite3_file,
}

impl GzFile {
    fn find_offset(&mut self, i_ofst: usize) -> usize {
        let mut index_offsets = self.index.keys().copied().collect::<Vec<Offset>>();
        if index_offsets.len() == 0 {
            return 0;
        }
        let mut lo = 0;
        let mut hi = index_offsets.len() - 1;

        loop {
            //eprintln!("i_ofst: {} lo = {}, high = {}",i_ofst, lo, hi);
            //std::dbg!(&self.index);
            //std::dbg!(&index_offsets);   i = low + (high-low) // 2
            if (lo + 1) == hi && index_offsets[hi] <= i_ofst && index_offsets[lo] >= i_ofst {
                return hi;
            }
            match index_offsets.binary_search(&i_ofst) {
                Ok(k) => {
                    let i = self.index[&index_offsets[k]];
                    return i;
                }
                Err(k) => {
                    if self.index[&index_offsets[k]] == 0 {
                        return 0;
                    }
                    let i = self.index[&index_offsets[k]] - 1;
                    if i == hi {
                        return i;
                    };
                    self.file
                        .seek(SeekFrom::Start(((i) * COMPRESSED_BLOCK_SIZE) as u64))
                        .unwrap();
                    let d = GzDecoder::new(&self.file);
                    let header = d.header().unwrap();
                    let block_no: usize = String::from_utf8(header.filename().unwrap().to_vec())
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    let offset: usize = String::from_utf8(header.comment().unwrap().to_vec())
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    //eprintln!( "i = {} header = {:?} block_no = {} offset= {}", i, header, block_no, offset);
                    self.index.insert(offset, block_no);
                    index_offsets = self.index.keys().copied().collect::<Vec<Offset>>();
                    hi = block_no;
                    if offset < i_ofst {
                        lo = k;
                    } else {
                        hi = k - 1;
                    }
                }
            }
        }
    }

    fn find_block(&mut self, block_no: usize) -> Option<(Offset, Vec<u8>)> {
        if !self.block_cache.contains_key(&block_no) {
            let mut buffer: Vec<u8> = vec![];
            self.file
                .seek(SeekFrom::Start(((block_no) * COMPRESSED_BLOCK_SIZE) as u64))
                .ok()?;
            let mut d = GzDecoder::new(&self.file);
            let header = d.header()?;
            let actual_offset: usize = String::from_utf8(header.comment()?.to_vec())
                .ok()?
                .parse::<usize>()
                .ok()?;
            d.read_to_end(&mut buffer).ok()?;
            self.block_cache.insert(block_no, (actual_offset, buffer));
        }
        self.block_cache.get(&block_no).cloned()
    }
}

unsafe extern "C" fn gzOpen(
    vfs: *mut sqlite3_vfs,
    zPath: *const ::std::os::raw::c_char,
    file_ptr: *mut sqlite3_file,
    flags: ::std::os::raw::c_int,
    pOutFlags: *mut ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let mut vfs_ptr = if let Some(ptr) = std::ptr::NonNull::new(vfs) {
        ptr
    } else {
        panic!("Could not find default sqlite3 vfs");
    };
    let sqlite_vfs: &mut sqlite3_vfs = vfs_ptr.as_mut();
    let mut vfs_ptr: std::ptr::NonNull<Vfs> =
        std::ptr::NonNull::new(sqlite_vfs.pAppData as *mut Vfs)
            .expect("pAppData of gz vfs is null");
    let vfs_ = vfs_ptr.as_mut();

    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let os_path =
        std::ffi::OsStr::from_bytes(std::ffi::CStr::from_ptr(zPath).to_bytes()).to_os_string();
    //eprintln!("open {:?}", &os_path);
    let gz_file = gz_conn.as_mut();
    let e_type = flags & 0x0FFF00; /* Type of file to open */

    let filetype = match e_type {
        _ if e_type == SQLITE_OPEN_MAIN_DB => FileType::Main,
        _ if e_type == SQLITE_OPEN_MAIN_JOURNAL => FileType::Journal,
        _ if e_type == SQLITE_OPEN_WAL => FileType::Wal,
        _ if e_type == SQLITE_OPEN_SUPER_JOURNAL => FileType::MasterJournal,
        _ if e_type == SQLITE_OPEN_SUBJOURNAL => FileType::SubJournal,
        _ if e_type == SQLITE_OPEN_TEMP_DB => FileType::TempDb,
        _ if e_type == SQLITE_OPEN_TEMP_JOURNAL => FileType::TempJournal,
        _ if e_type == SQLITE_OPEN_TRANSIENT_DB => FileType::Transient,
        _ => unreachable!(),
    };
    std::ptr::write(&mut gz_file.filetype, filetype);
    std::ptr::write(&mut gz_file.index, BTreeMap::default());
    std::ptr::write(&mut gz_file.block_cache, BTreeMap::default());

    std::ptr::write(&mut gz_file.dirty, Arc::new(Mutex::new(false)));
    let buffer = Vec::new();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&os_path)
        .unwrap();
    if e_type == SQLITE_OPEN_MAIN_DB {
        let size = file.metadata().unwrap().len() as usize;
        if size != 0 {
            let number_of_blocks = size / COMPRESSED_BLOCK_SIZE - 1;
            for i in [0, number_of_blocks / 2, number_of_blocks] {
                //let mut bytes2 = Vec::new();
                //file.read_to_end(&mut buffer);
                //file.read_to_end(&mut bytes2).unwrap();
                //eprintln!("file is {:?} {} bytes", file, bytes2.len());
                file.seek(SeekFrom::Start((i * COMPRESSED_BLOCK_SIZE) as u64))
                    .unwrap();
                let d = GzDecoder::new(&file);
                //eprintln!("i = {}", i);
                let header = d.header().unwrap();
                let block_no: usize = String::from_utf8(header.filename().unwrap().to_vec())
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                let offset: usize = String::from_utf8(header.comment().unwrap().to_vec())
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                //eprintln!( "i = {} header = {:?} block_no = {} offset= {}", i, header, block_no, offset);
                gz_file.index.insert(offset, block_no);
            }
        }
    } else {
        let _parent_Open = unsafe {
            (vfs_.parent.as_ref().xOpen.unwrap())(
                vfs_.parent.as_ptr() as _,
                zPath,
                &mut gz_file.sub as *mut _,
                flags,
                pOutFlags,
            )
        };
    }
    std::ptr::write(&mut gz_file.file, file);

    gz_file.buf = Cursor::new(buffer);
    gz_file.path = os_path;
    gz_file.base.pMethods = &mut vfs_.io_methods as *mut _;

    /*
    let mut file_ptr: std::ptr::NonNull<sqlite3_file> =
         std::ptr::NonNull::new(file_ptr).expect("file_ptr of gz vfs is null") ;
    let file_ref =  file_ptr.as_mut() ;

    let orig_io_methods =
        std::ptr::NonNull::new(file_ref.pMethods as *mut sqlite3_io_methods)
            .expect("file_ref.pMethods of gz vfs is null")
    ;
    let orig_io_methods_ref = unsafe { orig_io_methods.as_mut() };
    orig_io_methods_ref.xRead = unsafe {
        Some(do_something_handler), Box::into_raw(cb) as *mut _);
    }

    let mut read_cb_ref: xReadFn = Pin::into_inner_unchecked(vfs_.x_read_fn.as_ref());
    orig_io_methods_ref.xRead = Some(unsafe { std::mem::transmute(read_cb_ref) });
    */

    SQLITE_OK
}

impl Vfs {
    pub fn new() -> Result<Pin<Box<Self>>, String> {
        let default_ptr = unsafe { sqlite3_vfs_find(std::ptr::null()) };
        let default = if let Some(default) = std::ptr::NonNull::new(default_ptr) {
            default
        } else {
            return Err("Could not find default sqlite3 vfs".into());
        };

        let default_ref = unsafe { default.as_ref() };
        let mut inner = default_ref.clone();
        //eprintln!("default {:#?}", &inner);
        //eprintln!(
        //    "default name: {} ",
        //    unsafe { std::ffi::CStr::from_ptr(inner.zName) }
        //        .to_str()
        //        .unwrap()
        //);
        inner.zName = b"gz\0".as_ptr() as _;
        inner.pNext = std::ptr::null_mut();
        inner.pAppData = std::ptr::null_mut();
        inner.xOpen = Some(gzOpen);
        let fsize: i32 = std::mem::size_of::<GzFile>()
            .try_into()
            .expect("Could not convert VFS file size from usize to i32");
        inner.szOsFile += fsize;

        let io_methods: sqlite3_io_methods = sqlite3_io_methods {
            iVersion: 1,
            xClose: Some(gzClose),
            xRead: Some(gzRead),
            xWrite: Some(gzWrite),
            xTruncate: Some(gzTruncate),
            xSync: Some(gzSync),
            xFileSize: Some(gzFileSize),
            xLock: Some(gzLock),
            xUnlock: Some(gzUnlock),
            xCheckReservedLock: Some(gzCheckReservedLock),
            xFileControl: Some(gzFileControl),
            xSectorSize: Some(gzSectorSize),
            xDeviceCharacteristics: Some(gzDeviceCharacteristics),
            xShmMap: None,
            xShmLock: None,
            xShmBarrier: None,
            xShmUnmap: None,
            xFetch: None,
            xUnfetch: None,
        };

        //eprintln!("inner {:#?}", &inner);
        //eprintln!(
        //    "inner name: {} ",
        //    unsafe { std::ffi::CStr::from_ptr(inner.zName) }
        //        .to_str()
        //        .unwrap()
        //);
        let mut self_ = Box::pin(Vfs {
            parent: default,
            inner: inner,
            io_methods,
        });
        self_.inner.pAppData =
            unsafe { std::mem::transmute((self_.as_ref().get_ref()) as *const _) };
        let ret = unsafe { sqlite3_vfs_register(&mut self_.inner, 1) };
        //eprintln!("ret {}", ret);
        if ret != SQLITE_OK {
            let errmsg = unsafe { sqlite3_errstr(ret) };
            let slice = unsafe { std::ffi::CStr::from_ptr(errmsg) };
            return Err(format!(
                "Vfs::new() sqlite3_vfs_register returned {}: {}",
                ret,
                slice.to_str().unwrap().to_string()
            ));
        }

        Ok(self_)
    }
}

pub unsafe fn write_to_file(
    file: &mut File,
    slice: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    nix::unistd::ftruncate(file.as_raw_fd(), 0)?;
    //println!("slice len {} chunks {}", slice.len(), slice.chunks(1024).len());
    let mut block_no = 0;
    let mut slices_done = 0;
    loop {
        //println!("new_block no {} slices_done = {}", block_no, slices_done);
        nix::unistd::ftruncate(
            file.as_raw_fd(),
            ((block_no + 1) * COMPRESSED_BLOCK_SIZE) as _,
        )?;
        let ptr: *mut c_void = nix::sys::mman::mmap(
            std::ptr::null_mut(),
            COMPRESSED_BLOCK_SIZE,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
            file.as_raw_fd(),
            ((block_no) * COMPRESSED_BLOCK_SIZE) as _,
        )?;
        let block_slice: &mut [u8] =
            core::slice::from_raw_parts_mut(ptr as *mut u8, COMPRESSED_BLOCK_SIZE);
        let block = Cursor::new(block_slice);

        let mut e = GzBuilder::new()
            .filename(block_no.to_string())
            .comment((slices_done * 1024).to_string())
            .write(block, Compression::default());
        let mut position = 0;
        for (_i, chunk) in slice.chunks(1024).skip(slices_done).enumerate() {
            if position + 1024 > COMPRESSED_BLOCK_SIZE {
                break;
            }
            if let Err(_) = e.write_all(chunk).and_then(|_| e.flush()) {
                break;
            }
            slices_done += 1;
            position = e.get_ref().position() as usize;
            //println!("{} {} {}", i, position, chunk.len());
        }
        //println!("position, {}", position);
        if position != 0 {
            //println!("e.finish()?");
            e.finish()?;
        } else {
            drop(e);
        }
        //println!("msync {}", position);
        nix::sys::mman::msync(ptr, position as _, nix::sys::mman::MsFlags::MS_SYNC)?;
        //println!("munmap {}", COMPRESSED_BLOCK_SIZE);
        nix::sys::mman::munmap(ptr, COMPRESSED_BLOCK_SIZE)?;
        if position == 0 {
            //nix::unistd::ftruncate(
            //    file.as_raw_fd(),
            //    ((block_no) * COMPRESSED_BLOCK_SIZE) as _,
            //)?;
            break;
        }
        //println!("block_no {} + 1", block_no);
        block_no += 1;
    }
    //println!("total blocks: {}", block_no);
    Ok(())
}

unsafe extern "C" fn gzClose(file_ptr: *mut sqlite3_file) -> ::std::os::raw::c_int {
    //eprintln!("TRACE:close");
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let gz_file = gz_conn.as_mut();
    //eprintln!( "{:?} on close I have {} bytes and {} dirty, filetype {:?}", &gz_file.path, gz_file.buf.get_ref().len(), *gz_file.dirty.lock().unwrap(), gz_file.filetype);
    //eprintln!("close {:?}", gz_file.path);
    if gz_file.filetype as i32 == FileType::Main as i32 && *gz_file.dirty.lock().unwrap() {
    } else if gz_file.filetype as i32 != FileType::Main as i32 {
        return ((*gz_file.sub.pMethods).xClose.unwrap())(&mut gz_file.sub as *mut _);
    }
    //file.write_all(gz_file.buf.get_ref().as_slice()).unwrap();
    /*
     */
    SQLITE_OK
}

unsafe extern "C" fn gzRead(
    file_ptr: *mut sqlite3_file,
    zBuf: *mut ::std::os::raw::c_void,
    iAmt: ::std::os::raw::c_int, /* Size of data to read in bytes */
    iOfst: sqlite3_int64,
) -> ::std::os::raw::c_int {
    //eprintln!("TRACE:read");
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let mut rc = SQLITE_OK;
    let gz_file = gz_conn.as_mut();
    if gz_file.filetype as i32 != FileType::Main as i32 {
        //eprintln!("want to read {} bytes with {} offset", iAmt, iOfst);
        return ((*gz_file.sub.pMethods).xRead.unwrap())(
            &mut gz_file.sub as *mut _,
            zBuf,
            iAmt,
            iOfst,
        );
    } else {
        //eprintln!("\n\n\n\n gzRead iAmt {} iOfst {}\n\n", iAmt, iOfst);
        //std::dbg!(&gz_file);
        let iOfst = iOfst as usize;
        let mut iAmt = iAmt as usize;

        let block_no: usize = gz_file.find_offset(iOfst);
        //eprintln!("for offset iOfst {} I found block_no {}", iOfst, block_no);
        if let Some((actual_offset, buffer)) = gz_file.find_block(block_no) {
            //eprintln!( "for block_no {} I have offset {} while my read request was {}", block_no, actual_offset, iOfst);
            assert!((iOfst as usize) >= actual_offset);
            let buf_offset = (iOfst as usize) - actual_offset;
            //eprintln!("buf_offset {}", buf_offset);
            let out_buffer = &buffer[buf_offset..];
            if out_buffer.len() < iAmt {
                let rc2 = gzRead(
                    file_ptr,
                    zBuf.add(out_buffer.len() as _),
                    (iAmt - out_buffer.len()) as _,
                    (iOfst + out_buffer.len()) as _,
                );
                iAmt = out_buffer.len();
                if rc2 != SQLITE_OK {
                    rc = SQLITE_IOERR_SHORT_READ;
                }
            }
            //print_hex_range(&out_buffer[..iAmt ], 0);
            std::ptr::copy_nonoverlapping(out_buffer[..iAmt].as_ptr(), zBuf as *mut u8, iAmt);
        } else {
            rc = SQLITE_IOERR_SHORT_READ;
        }
    }
    rc
}

unsafe extern "C" fn gzWrite(
    file_ptr: *mut sqlite3_file,
    mut zBuf: *const ::std::os::raw::c_void,
    iAmt: ::std::os::raw::c_int,
    iOfst: sqlite3_int64,
) -> ::std::os::raw::c_int {
    //eprintln!("TRACE:write");
    //eprintln!("AAAAAAAAAAAAAAa write {} bytes", iAmt);
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let gz_file = gz_conn.as_mut();
    *gz_file.dirty.lock().unwrap() = true;

    //eprintln!("\n\n\ngzWrite\n\n\n");
    //eprintln!( "{:?}: want to write {} bytes with {} offset", &gz_file.path, iAmt, iOfst);

    let _len: usize = iAmt.try_into().unwrap();
    if gz_file.filetype as i32 != FileType::Main as i32 {
        return ((*gz_file.sub.pMethods).xWrite.unwrap())(
            &mut gz_file.sub as *mut _,
            zBuf,
            iAmt,
            iOfst,
        );
    } else {
        //eprintln!("\n\n\n\n gzWrite iAmt {} iOfst {}\n\n", iAmt, iOfst);
        //std::dbg!(&gz_file.index);
        let mut iOfst = iOfst as usize;
        let mut iAmt = iAmt as usize;
        while iAmt > 0 {
            let block_no: usize = gz_file.find_offset(iOfst);
            //eprintln!("for offset iOfst {} I found block_no {}", iOfst, block_no);
            if let Some((actual_offset, mut buffer)) = gz_file.find_block(block_no) {
                gz_file.block_cache.remove(&block_no);
                //eprintln!( "for block_no {} I have offset {} while my write request was {}", block_no, actual_offset, iOfst);
                assert!((iOfst as usize) >= actual_offset);
                let buf_offset = (iOfst as usize) - actual_offset;
                //print_hex_range(&buffer[buf_offset..][..iAmt ], 0);
                let out_buffer = &mut buffer[buf_offset..];
                if out_buffer.len() < iAmt {
                    std::ptr::copy_nonoverlapping(
                        zBuf as *mut u8,
                        out_buffer.as_mut_ptr(),
                        out_buffer.len() as _,
                    );
                    zBuf = zBuf.add(out_buffer.len() as _);
                    iOfst += out_buffer.len();
                } else {
                    std::ptr::copy_nonoverlapping(zBuf as *mut u8, out_buffer.as_mut_ptr(), iAmt);
                }
                iAmt -= out_buffer.len();
                //print_hex_range(&buffer[buf_offset..][..iAmt ], 0);
                gz_file
                    .file
                    .seek(SeekFrom::Start(((block_no) * COMPRESSED_BLOCK_SIZE) as u64))
                    .unwrap();
                gz_file.file.write_all(&buffer).unwrap();
            } else {
                /* create block */
                nix::unistd::ftruncate(
                    gz_file.file.as_raw_fd(),
                    ((block_no + 1) * COMPRESSED_BLOCK_SIZE) as _,
                )
                .unwrap();
                gz_file
                    .file
                    .seek(SeekFrom::Start(((block_no) * COMPRESSED_BLOCK_SIZE) as u64))
                    .unwrap();
                let block_slice: &mut [u8] = core::slice::from_raw_parts_mut(
                    zBuf as *mut u8,
                    std::cmp::min(COMPRESSED_BLOCK_SIZE, iAmt),
                );
                let block_offset = if block_no == 0 {
                    0
                } else {
                    let (actual_offset, buffer) = gz_file.find_block(block_no - 1).unwrap();
                    actual_offset + buffer.len()
                };
                let mut e = GzBuilder::new()
                    .filename(block_no.to_string())
                    .comment(block_offset.to_string())
                    .write(&gz_file.file, Compression::default());
                let mut slices_done = 0;
                for (_i, chunk) in block_slice.chunks(1024).enumerate() {
                    if let Err(_) = e.write_all(chunk).and_then(|_| e.flush()) {
                        break;
                    }
                    slices_done += 1;
                }
                e.finish().unwrap();
                iAmt -= slices_done * 1024;
                zBuf = zBuf.add(slices_done * 1024);
                iOfst += slices_done * 1024;
            }
        }
    }

    /*
    let ret = unsafe {
        ((*gz_file.sub.pMethods).xWrite.unwrap())(
            &mut gz_file.sub as *mut _,
            vec.as_ptr() as *const _,
            vec.len().try_into().unwrap(),
            iOfst,
        )
    };
    */
    /*
    if ret== SQLITE_OK {
        let len:usize = iAmt.try_into().unwrap();
        let slice:&[u8] =  std::slice::from_raw_parts(zBuf as *mut u8, len);
        let mut actual_len = len;
        if let Some(pos) = slice.iter().enumerate().rposition(|(i, c)| *c != 0) {
            actual_len = len+1;
            ////eprintln!("write actual length {}", actual_len);
        }
    }
    ret
    */
    SQLITE_OK
}

unsafe extern "C" fn gzTruncate(
    file_ptr: *mut sqlite3_file,
    size: sqlite3_int64,
) -> ::std::os::raw::c_int {
    //eprintln!("TRACE: truncate");
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let gz_file = gz_conn.as_mut();
    gz_file.buf.get_mut().truncate(size as usize);

    /*
    let ret = unsafe {
        ((*gz_file.sub.pMethods).xTruncate.unwrap())(
            &mut gz_file.sub as *mut _,
            size,
        )
    };
    ret
    */
    SQLITE_OK
}

unsafe extern "C" fn gzSync(
    _file_ptr: *mut sqlite3_file,
    _flags: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    //eprintln!("TRACE:sync");
    //return gzClose(file_ptr);
    SQLITE_OK
    /*
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let gz_file = gz_conn.as_mut();

    let ret = unsafe {
        ((*gz_file.sub.pMethods).xSync.unwrap())(
            &mut gz_file.sub as *mut _,
            flags,
        )
    };
    ret
    */
}

unsafe extern "C" fn gzFileSize(
    file_ptr: *mut sqlite3_file,
    pSize: *mut sqlite3_int64,
) -> ::std::os::raw::c_int {
    //eprintln!("TRACE:filesize");
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let gz_file = gz_conn.as_mut();

    if gz_file.filetype as i32 == FileType::Main as i32 {
        if let Some(max) = gz_file.index.keys().max() {
            let last_block_no = gz_file.index[&max];
            let (actual_offset, block) = gz_file.find_block(last_block_no).unwrap();
            *pSize = (actual_offset + block.len()) as _;
        } else {
            *pSize = 0;
        }
    } else {
        return ((*gz_file.sub.pMethods).xFileSize.unwrap())(&mut gz_file.sub as *mut _, pSize);
    }

    /*
    let ret = unsafe {
        ((*gz_file.sub.pMethods).xFileSize.unwrap())(
            &mut gz_file.sub as *mut _,
            pSize,
        )
    };
    ret
    */
    SQLITE_OK
}

unsafe extern "C" fn gzLock(
    file_ptr: *mut sqlite3_file,
    _arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let _gz_file = gz_conn.as_mut();

    /*let ret = unsafe {
            ((*gz_file.sub.pMethods).xLock.unwrap())(&mut gz_file.sub as *mut _, arg2)
        };
    //eprintln!("lock returning {}", ret);
        ret
        */
    SQLITE_OK
}

unsafe extern "C" fn gzUnlock(
    file_ptr: *mut sqlite3_file,
    _arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let _gz_file = gz_conn.as_mut();

    /*
        let ret = unsafe {
            ((*gz_file.sub.pMethods).xUnlock.unwrap())(&mut gz_file.sub as *mut _, arg2)
        };
    //eprintln!("unlock returning {}", ret);
        ret
            */
    SQLITE_OK
}

unsafe extern "C" fn gzCheckReservedLock(
    file_ptr: *mut sqlite3_file,
    pResOut: *mut ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let _gz_file = gz_conn.as_mut();

    /*
        let ret = unsafe {
            ((*gz_file.sub.pMethods).xCheckReservedLock.unwrap())(
                &mut gz_file.sub as *mut _,
                pResOut,
            )
        };
    //eprintln!("checkreserverlock returning {}", ret);
        ret
        */
    *pResOut = 0;
    SQLITE_OK
}

unsafe extern "C" fn gzFileControl(
    file_ptr: *mut sqlite3_file,
    _op: ::std::os::raw::c_int,
    _pArg: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    //eprintln!("TRACE:filecontrol {}", _op);
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let _gz_file = gz_conn.as_mut();

    /*
    let ret = unsafe {
        ((*gz_file.sub.pMethods).xFileControl.unwrap())(
            &mut gz_file.sub as *mut _,
            op,
            pArg,
        )
    };
    */
    ////eprintln!("filecontrol returning {}", ret);
    //ret
    SQLITE_NOTFOUND
}

unsafe extern "C" fn gzSectorSize(file_ptr: *mut sqlite3_file) -> ::std::os::raw::c_int {
    //eprintln!("TRACE:sectorsize");
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let _gz_file = gz_conn.as_mut();

    /*let ret = unsafe {
            ((*gz_file.sub.pMethods).xSectorSize.unwrap())(&mut gz_file.sub as *mut _)
        };
    //eprintln!("sectorsize returning {}", ret);
        ret
        */
    1024
}

unsafe extern "C" fn gzDeviceCharacteristics(file_ptr: *mut sqlite3_file) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<GzFile> =
        std::ptr::NonNull::new(file_ptr as *mut GzFile).expect("null file_ptr in gzOpen");
    let _gz_file = gz_conn.as_mut();

    //let ret = unsafe {
    //    ((*gz_file.sub.pMethods).xDeviceCharacteristics.unwrap())(
    //        &mut gz_file.sub as *mut _,
    //    )
    //};
    ////eprintln!("devicecharacteristics returning {}", ret);
    //ret
    SQLITE_IOCAP_ATOMIC
        | SQLITE_IOCAP_POWERSAFE_OVERWRITE
        | SQLITE_IOCAP_SAFE_APPEND
        | SQLITE_IOCAP_SEQUENTIAL
}

fn print_hex_range(bytes: &[u8], start_offset: usize) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    println!(
        "-Showing {} bytes---------------------------------------------------------------",
        bytes.len()
    );
    let mut child = Command::new("xxd")
        .arg("-o")
        .arg(start_offset.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn child process");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    stdin.write_all(bytes).expect("Failed to write to stdin");
    drop(stdin);

    let _ = child.wait().expect("Failed to read stdout");
    println!("--------------------------------------------------------------------------------");
}

#[test]
fn test_uncompress() {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("./mans.db")
        .unwrap();
    let mut buffer = Vec::new();
    let size = file.metadata().unwrap().len() as usize;
    let number_of_blocks = size / COMPRESSED_BLOCK_SIZE - 1;
    for i in 0..(number_of_blocks) {
        file.seek(SeekFrom::Start((i * COMPRESSED_BLOCK_SIZE) as u64))
            .unwrap();
        let mut d = GzDecoder::new(&file);
        d.read_to_end(&mut buffer).unwrap();
    }
    let mut output = OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .open("./mans_test2.db")
        .unwrap();
    output.write_all(&buffer);
}
#[test]
fn test_compress() {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("./mans.db")
        .unwrap();
    let mut s = vec![];
    File::open("./mans.db.bkp")
        .unwrap()
        .read_to_end(&mut s)
        .unwrap();
    unsafe { write_to_file(&mut file, &s).unwrap() };
}
