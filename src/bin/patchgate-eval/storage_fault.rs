//! Linux syscall faults for the storage evaluation cases.
//! Compile this file as a cdylib. It is not part of the production gate.

use std::ffi::{c_int, c_long, c_void};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!("The storage fault fixture needs Linux x86_64 or aarch64 and procfs.");

#[cfg(target_arch = "x86_64")]
const WRITE: c_long = 1;
#[cfg(target_arch = "x86_64")]
const WRITEV: c_long = 20;
#[cfg(target_arch = "x86_64")]
const FSYNC: c_long = 74;
#[cfg(target_arch = "x86_64")]
const FDATASYNC: c_long = 75;
#[cfg(target_arch = "aarch64")]
const WRITE: c_long = 64;
#[cfg(target_arch = "aarch64")]
const WRITEV: c_long = 66;
#[cfg(target_arch = "aarch64")]
const FSYNC: c_long = 82;
#[cfg(target_arch = "aarch64")]
const FDATASYNC: c_long = 83;

extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn __errno_location() -> *mut c_int;
}

#[repr(C)]
pub struct IoVec {
    base: *const c_void,
    length: usize,
}

static PARTIAL: AtomicUsize = AtomicUsize::new(0);
static SYNCS: AtomicUsize = AtomicUsize::new(0);

fn selected(fd: c_int) -> Option<std::path::PathBuf> {
    let target = std::env::var_os("PATCHGATE_EVAL_FAULT_TARGET")?;
    let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    (path == std::path::Path::new(&target)).then_some(path)
}

fn event(kind: &str, requested: usize, result: isize, errno: c_int, path: &std::path::Path) {
    let Some(log) = std::env::var_os("PATCHGATE_EVAL_FAULT_LOG") else {
        return;
    };
    let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(log) else {
        return;
    };
    let line = format!("{kind}\t{requested}\t{result}\t{errno}\t{}\n", path.display());
    unsafe {
        syscall(WRITE, file.as_raw_fd(), line.as_ptr(), line.len());
    }
}

unsafe fn failure(kind: &str, requested: usize, errno: c_int, path: &std::path::Path) -> isize {
    event(kind, requested, -1, errno, path);
    unsafe { *__errno_location() = errno };
    -1
}

unsafe fn write_fault(fd: c_int, buffer: *const c_void, count: usize) -> Option<isize> {
    let path = selected(fd)?;
    let mode = std::env::var("PATCHGATE_EVAL_FAULT_KIND").ok()?;
    match mode.as_str() {
        "full" => Some(unsafe { failure("full", count, 28, &path) }),
        "short" if PARTIAL.load(Ordering::SeqCst) != 0 => {
            Some(unsafe { failure("error", count, 5, &path) })
        }
        "short" if count > 1 => {
            let length = (count / 2).min(17).max(1);
            let result = unsafe { syscall(WRITE, fd, buffer, length) } as isize;
            let errno = if result < 0 { unsafe { *__errno_location() } } else { 0 };
            if result > 0 {
                PARTIAL.store(1, Ordering::SeqCst);
            }
            event("short", count, result, errno, &path);
            if result < 0 {
                unsafe { *__errno_location() = errno };
            }
            Some(result)
        }
        _ => None,
    }
}

#[no_mangle]
pub unsafe extern "C" fn write(fd: c_int, buffer: *const c_void, count: usize) -> isize {
    unsafe { write_fault(fd, buffer, count) }
        .unwrap_or_else(|| unsafe { syscall(WRITE, fd, buffer, count) as isize })
}

#[no_mangle]
pub unsafe extern "C" fn writev(fd: c_int, vectors: *const IoVec, count: c_int) -> isize {
    if count > 0 && !vectors.is_null() && selected(fd).is_some() {
        let vectors = unsafe { std::slice::from_raw_parts(vectors, count as usize) };
        let requested = vectors.iter().map(|vector| vector.length).sum::<usize>();
        let mode = std::env::var("PATCHGATE_EVAL_FAULT_KIND").unwrap_or_default();
        if mode == "full" || (mode == "short" && PARTIAL.load(Ordering::SeqCst) != 0) {
            let path = selected(fd).expect("The selected descriptor has a path");
            return unsafe {
                failure(if mode == "full" { "full" } else { "error" }, requested,
                    if mode == "full" { 28 } else { 5 }, &path)
            };
        }
        if mode == "short" && requested > 1 {
            if let Some(vector) = vectors.iter().find(|vector| vector.length > 0) {
                // The scalar syscall writes a proper prefix of the same real file.
                let length = vector.length.min((requested / 2).min(17).max(1));
                let result = unsafe { syscall(WRITE, fd, vector.base, length) } as isize;
                let errno = if result < 0 { unsafe { *__errno_location() } } else { 0 };
                if result > 0 {
                    PARTIAL.store(1, Ordering::SeqCst);
                }
                if let Some(path) = selected(fd) {
                    event("short", requested, result, errno, &path);
                }
                if result < 0 {
                    unsafe { *__errno_location() = errno };
                }
                return result;
            }
        }
    }
    unsafe { syscall(WRITEV, fd, vectors, count) as isize }
}

unsafe fn sync_fault(fd: c_int, number: c_long) -> c_int {
    if let Some(path) = selected(fd) {
        if std::env::var("PATCHGATE_EVAL_FAULT_KIND").as_deref() == Ok("sync") {
            let skip = std::env::var("PATCHGATE_EVAL_FAULT_SKIP_SYNC")
                .ok().and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
            if SYNCS.fetch_add(1, Ordering::SeqCst) >= skip {
                return unsafe { failure("sync", 0, 5, &path) as c_int };
            }
        }
    }
    unsafe { syscall(number, fd) as c_int }
}

#[no_mangle]
pub unsafe extern "C" fn fsync(fd: c_int) -> c_int {
    unsafe { sync_fault(fd, FSYNC) }
}

#[no_mangle]
pub unsafe extern "C" fn fdatasync(fd: c_int) -> c_int {
    unsafe { sync_fault(fd, FDATASYNC) }
}
