#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

#[cfg_attr(unix, path = "unix.rs")]
#[cfg_attr(windows, path = "windows.rs")]
#[cfg_attr(not(any(unix, windows)), path = "none.rs")]
mod sys;

static HELD: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

#[derive(Debug, Default)]
pub struct Region {
    first: usize,
    pages: usize,
}

impl Region {
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.pages > 0
    }

    #[must_use]
    pub const fn pages(&self) -> usize {
        self.pages
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        if self.pages == 0 {
            return;
        }
        let size = page_size();
        let mut held = held();
        for page in release(&mut held, self.first, self.pages) {
            sys::unlock(page * size, size);
        }
    }
}

#[must_use]
pub fn lock<T: ?Sized>(value: &T) -> Region {
    lock_range(
        std::ptr::from_ref(value).cast::<u8>().addr(),
        size_of_val(value),
    )
}

#[must_use]
pub fn lock_range(start: usize, len: usize) -> Region {
    let size = page_size();
    let Some((first, pages)) = span(start, len, size) else {
        return Region::default();
    };
    let mut held = held();
    if !sys::lock(first * size, pages * size) {
        return Region::default();
    }
    hold(&mut held, first, pages);
    Region { first, pages }
}

pub fn harden() {
    sys::harden();
}

#[must_use]
pub fn locked_pages() -> usize {
    held().len()
}

fn held() -> MutexGuard<'static, BTreeMap<usize, usize>> {
    HELD.lock().unwrap_or_else(PoisonError::into_inner)
}

fn page_size() -> usize {
    static SIZE: OnceLock<usize> = OnceLock::new();
    *SIZE.get_or_init(|| {
        let size = sys::page_size();
        if size.is_power_of_two() {
            size
        } else {
            4096
        }
    })
}

fn span(start: usize, len: usize, size: usize) -> Option<(usize, usize)> {
    if len == 0 || size == 0 {
        return None;
    }
    let last = start.checked_add(len - 1)? / size;
    let first = start / size;
    Some((first, last - first + 1))
}

fn hold(held: &mut BTreeMap<usize, usize>, first: usize, pages: usize) {
    for page in first..first + pages {
        *held.entry(page).or_insert(0) += 1;
    }
}

fn release(held: &mut BTreeMap<usize, usize>, first: usize, pages: usize) -> Vec<usize> {
    let mut freed = Vec::new();
    for page in first..first + pages {
        if let Some(count) = held.get_mut(&page) {
            *count -= 1;
            if *count == 0 {
                held.remove(&page);
                freed.push(page);
            }
        }
    }
    freed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_span_covers_every_page_the_bytes_touch() {
        assert_eq!(span(0, 1, 4096), Some((0, 1)));
        assert_eq!(span(4095, 2, 4096), Some((0, 2)));
        assert_eq!(span(4096, 4096, 4096), Some((1, 1)));
        assert_eq!(span(4096, 4097, 4096), Some((1, 2)));
        assert_eq!(span(100, 0, 4096), None);
        assert_eq!(span(usize::MAX, 2, 4096), None);
    }

    #[test]
    fn a_page_is_released_only_when_nothing_else_holds_it() {
        let mut held = BTreeMap::new();
        hold(&mut held, 10, 2);
        hold(&mut held, 11, 2);
        assert_eq!(release(&mut held, 10, 2), vec![10]);
        assert_eq!(held.get(&11), Some(&1));
        assert_eq!(release(&mut held, 11, 2), vec![11, 12]);
        assert_eq!(held.len(), 0);
    }

    #[test]
    fn nothing_is_locked_for_an_empty_value() {
        let empty: [u8; 0] = [];
        assert_eq!(lock(&empty).pages(), 0);
        assert_eq!(lock_range(0, 0).pages(), 0);
    }

    #[test]
    fn the_page_size_is_a_power_of_two() {
        assert!(page_size().is_power_of_two());
        assert!(page_size() >= 4096);
    }
}
