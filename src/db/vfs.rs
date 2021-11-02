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
    SQLITE_OK,
};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::io::{Cursor, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

pub struct Vfs {
    //parent: std::ptr::NonNull<sqlite3_vfs>,
    inner: sqlite3_vfs,
    io_methods: sqlite3_io_methods,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct gzConn {
    base: sqlite3_file,
    vfs: std::ptr::NonNull<Vfs>,
    buf: Cursor<Vec<u8>>,
    dirty: Arc<Mutex<bool>>,
    path: std::ffi::OsString,
    sub: sqlite3_file,
}

unsafe extern "C" fn gzOpen(
    vfs: *mut sqlite3_vfs,
    zPath: *const ::std::os::raw::c_char,
    file_ptr: *mut sqlite3_file,
    _flags: ::std::os::raw::c_int,
    _pOutFlags: *mut ::std::os::raw::c_int,
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

    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let os_path =
        std::ffi::OsStr::from_bytes(std::ffi::CStr::from_ptr(zPath).to_bytes()).to_os_string();
    //eprintln!("open {:?}", &os_path);
    let gz_conn_ref = gz_conn.as_mut();
    std::mem::forget(std::mem::replace(
        &mut gz_conn_ref.dirty,
        Arc::new(Mutex::new(false)),
    ));
    let mut buffer = Vec::new();
    {
        let mut bytes2 = Vec::new();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&os_path)
            .unwrap();
        //file.read_to_end(&mut buffer);
        file.read_to_end(&mut bytes2).unwrap();
        //eprintln!("file is {:?} {} bytes", file, bytes2.len());
        if !bytes2.is_empty() {
            let mut d = GzDecoder::new(Cursor::new(bytes2));
            d.read_to_end(&mut buffer).unwrap();
        }
    }
    gz_conn_ref.buf = Cursor::new(buffer);
    gz_conn_ref.path = os_path;
    /*let parent_Open = unsafe {
        (vfs_.parent.as_ref().xOpen.unwrap())(
            vfs_.parent.as_ptr() as _,
            zPath,
            &mut gz_conn_ref.sub as *mut _,
            flags,
            pOutFlags,
        )
    };
    */
    gz_conn_ref.base.pMethods = &mut vfs_.io_methods as *mut _;

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

    SQLITE_OK as _
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
        let fsize: i32 = std::mem::size_of::<gzConn>()
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
            //parent: default,
            inner: inner,
            io_methods,
        });
        self_.inner.pAppData =
            unsafe { std::mem::transmute((self_.as_ref().get_ref()) as *const _) };
        let ret = unsafe { sqlite3_vfs_register(&mut self_.inner, 1) };
        //eprintln!("ret {}", ret);
        if ret as u32 != SQLITE_OK {
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

unsafe extern "C" fn gzClose(file_ptr: *mut sqlite3_file) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let gz_conn_ref = gz_conn.as_mut();
    //eprintln!("close {:?}", gz_conn_ref.path);
    //eprintln!("on close I have {} bytes", gz_conn_ref.buf.get_ref().len());
    if !*gz_conn_ref.dirty.lock().unwrap() {
        return SQLITE_OK as _;
    }

    gz_conn_ref.buf.seek(SeekFrom::Start(0)).unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(false)
        .open(&gz_conn_ref.path)
        .unwrap();
    let mut e = GzEncoder::new(file, Compression::default());
    e.write_all(gz_conn_ref.buf.get_ref().as_slice()).unwrap();
    e.finish().unwrap();
    //file.write_all(gz_conn_ref.buf.get_ref().as_slice()).unwrap();
    /*
    let ret = unsafe {
        ((*gz_conn_ref.sub.pMethods).xClose.unwrap())(
        &mut gz_conn_ref.sub as *mut _,
        )
    };
    ret
        */
    SQLITE_OK as _
}

unsafe extern "C" fn gzRead(
    file_ptr: *mut sqlite3_file,
    zBuf: *mut ::std::os::raw::c_void,
    iAmt: ::std::os::raw::c_int, /* Size of data to read in bytes */
    iOfst: sqlite3_int64,
) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let gz_conn_ref = gz_conn.as_mut();

    //eprintln!("want to read {} bytes with {} offset", iAmt, iOfst);
    gz_conn_ref.buf.seek(SeekFrom::Start(iOfst as _)).unwrap();
    let mut position = gz_conn_ref.buf.position() as usize;
    let len: usize = iAmt.try_into().unwrap();
    let slice: &mut [u8] = std::slice::from_raw_parts_mut(zBuf as *mut u8, len);
    if position > gz_conn_ref.buf.get_ref().as_slice().len() {
        position = gz_conn_ref.buf.get_ref().as_slice().len();
        slice.fill(0);
        ////eprintln!("SHORT READ!");
        //return SQLITE_OK as _;
    }
    let read_slice = &gz_conn_ref.buf.get_ref().as_slice()[position..];
    if read_slice.len() < iAmt.try_into().unwrap() {
        slice[read_slice.len()..].fill(0);
        //eprintln!("SHORT READ!");
        return SQLITE_IOERR_SHORT_READ as _;
    }
    std::ptr::copy_nonoverlapping(read_slice.as_ptr(), zBuf as *mut u8, iAmt as usize);
    SQLITE_OK as _
}

unsafe extern "C" fn gzWrite(
    file_ptr: *mut sqlite3_file,
    zBuf: *const ::std::os::raw::c_void,
    iAmt: ::std::os::raw::c_int,
    iOfst: sqlite3_int64,
) -> ::std::os::raw::c_int {
    //eprintln!("write {} bytes", iAmt);
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let gz_conn_ref = gz_conn.as_mut();
    *gz_conn_ref.dirty.lock().unwrap() = true;

    //eprintln!("want to write {} bytes with {} offset", iAmt, iOfst);

    let len: usize = iAmt.try_into().unwrap();
    let slice: &[u8] = std::slice::from_raw_parts(zBuf as *mut u8, len);

    gz_conn_ref.buf.seek(SeekFrom::Start(iOfst as _)).unwrap();
    gz_conn_ref.buf.write_all(slice).unwrap();

    /*
    let ret = unsafe {
        ((*gz_conn_ref.sub.pMethods).xWrite.unwrap())(
            &mut gz_conn_ref.sub as *mut _,
            vec.as_ptr() as *const _,
            vec.len().try_into().unwrap(),
            iOfst,
        )
    };
    */
    /*
    if ret as u32 == SQLITE_OK {
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
    SQLITE_OK as _
}

unsafe extern "C" fn gzTruncate(
    file_ptr: *mut sqlite3_file,
    size: sqlite3_int64,
) -> ::std::os::raw::c_int {
    //eprintln!("truncate");
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let gz_conn_ref = gz_conn.as_mut();
    gz_conn_ref.buf.get_mut().truncate(size as usize);

    /*
    let ret = unsafe {
        ((*gz_conn_ref.sub.pMethods).xTruncate.unwrap())(
            &mut gz_conn_ref.sub as *mut _,
            size,
        )
    };
    ret
    */
    SQLITE_OK as _
}

unsafe extern "C" fn gzSync(
    _file_ptr: *mut sqlite3_file,
    _flags: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    //eprintln!("sync");
    //return gzClose(file_ptr);
    SQLITE_OK as _
    /*
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let gz_conn_ref = gz_conn.as_mut();

    let ret = unsafe {
        ((*gz_conn_ref.sub.pMethods).xSync.unwrap())(
            &mut gz_conn_ref.sub as *mut _,
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
    //eprintln!("filesize");
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let gz_conn_ref = gz_conn.as_mut();

    gz_conn_ref.buf.seek(SeekFrom::Start(0)).unwrap();
    *pSize = gz_conn_ref.buf.get_ref().len() as _;

    /*
    let ret = unsafe {
        ((*gz_conn_ref.sub.pMethods).xFileSize.unwrap())(
            &mut gz_conn_ref.sub as *mut _,
            pSize,
        )
    };
    ret
    */
    SQLITE_OK as _
}

unsafe extern "C" fn gzLock(
    file_ptr: *mut sqlite3_file,
    _arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let _gz_conn_ref = gz_conn.as_mut();

    /*let ret = unsafe {
            ((*gz_conn_ref.sub.pMethods).xLock.unwrap())(&mut gz_conn_ref.sub as *mut _, arg2)
        };
    //eprintln!("lock returning {}", ret);
        ret
        */
    SQLITE_OK as _
}

unsafe extern "C" fn gzUnlock(
    file_ptr: *mut sqlite3_file,
    _arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let _gz_conn_ref = gz_conn.as_mut();

    /*
        let ret = unsafe {
            ((*gz_conn_ref.sub.pMethods).xUnlock.unwrap())(&mut gz_conn_ref.sub as *mut _, arg2)
        };
    //eprintln!("unlock returning {}", ret);
        ret
            */
    SQLITE_OK as _
}

unsafe extern "C" fn gzCheckReservedLock(
    file_ptr: *mut sqlite3_file,
    pResOut: *mut ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let _gz_conn_ref = gz_conn.as_mut();

    /*
        let ret = unsafe {
            ((*gz_conn_ref.sub.pMethods).xCheckReservedLock.unwrap())(
                &mut gz_conn_ref.sub as *mut _,
                pResOut,
            )
        };
    //eprintln!("checkreserverlock returning {}", ret);
        ret
        */
    *pResOut = 0;
    SQLITE_OK as _
}

unsafe extern "C" fn gzFileControl(
    file_ptr: *mut sqlite3_file,
    _op: ::std::os::raw::c_int,
    _pArg: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let _gz_conn_ref = gz_conn.as_mut();

    /*
    let ret = unsafe {
        ((*gz_conn_ref.sub.pMethods).xFileControl.unwrap())(
            &mut gz_conn_ref.sub as *mut _,
            op,
            pArg,
        )
    };
    */
    ////eprintln!("filecontrol returning {}", ret);
    //ret
    SQLITE_NOTFOUND as _
}

unsafe extern "C" fn gzSectorSize(file_ptr: *mut sqlite3_file) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let _gz_conn_ref = gz_conn.as_mut();

    /*let ret = unsafe {
            ((*gz_conn_ref.sub.pMethods).xSectorSize.unwrap())(&mut gz_conn_ref.sub as *mut _)
        };
    //eprintln!("sectorsize returning {}", ret);
        ret
        */
    1024
}

unsafe extern "C" fn gzDeviceCharacteristics(file_ptr: *mut sqlite3_file) -> ::std::os::raw::c_int {
    let mut gz_conn: std::ptr::NonNull<gzConn> =
        std::ptr::NonNull::new(file_ptr as *mut gzConn).expect("null file_ptr in gzOpen");
    let _gz_conn_ref = gz_conn.as_mut();

    //let ret = unsafe {
    //    ((*gz_conn_ref.sub.pMethods).xDeviceCharacteristics.unwrap())(
    //        &mut gz_conn_ref.sub as *mut _,
    //    )
    //};
    ////eprintln!("devicecharacteristics returning {}", ret);
    //ret
    (SQLITE_IOCAP_ATOMIC
        | SQLITE_IOCAP_POWERSAFE_OVERWRITE
        | SQLITE_IOCAP_SAFE_APPEND
        | SQLITE_IOCAP_SEQUENTIAL) as _
}
