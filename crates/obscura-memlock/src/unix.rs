use std::ptr;

pub fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).unwrap_or(0)
}

pub fn lock(start: usize, len: usize) -> bool {
    unsafe { libc::mlock(ptr::without_provenance(start), len) == 0 }
}

pub fn unlock(start: usize, len: usize) {
    unsafe { libc::munlock(ptr::without_provenance(start), len) };
}

pub fn harden() {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const none) };
    undumpable();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn undumpable() {
    let off: libc::c_ulong = 0;
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, off) };
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
const fn undumpable() {}
