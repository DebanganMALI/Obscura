use std::ptr;

use windows_sys::Win32::System::{
    ErrorReporting::{WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP},
    Memory::{VirtualLock, VirtualUnlock},
    SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    Threading::{GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize},
};

const HEADROOM: usize = 16 * 1024 * 1024;

pub fn page_size() -> usize {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&raw mut info) };
    usize::try_from(info.dwPageSize).unwrap_or(0)
}

pub fn lock(start: usize, len: usize) -> bool {
    unsafe { VirtualLock(ptr::without_provenance(start), len) != 0 }
}

pub fn unlock(start: usize, len: usize) {
    unsafe { VirtualUnlock(ptr::without_provenance(start), len) };
}

pub fn harden() {
    unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) };
    let process = unsafe { GetCurrentProcess() };
    let (mut least, mut most) = (0usize, 0usize);
    if unsafe { GetProcessWorkingSetSize(process, &raw mut least, &raw mut most) } != 0 {
        unsafe {
            SetProcessWorkingSetSize(
                process,
                least.saturating_add(HEADROOM),
                most.saturating_add(HEADROOM),
            )
        };
    }
}
