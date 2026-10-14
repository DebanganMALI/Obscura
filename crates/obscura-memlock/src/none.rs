pub const fn page_size() -> usize {
    4096
}

pub const fn lock(_start: usize, _len: usize) -> bool {
    false
}

pub const fn unlock(_start: usize, _len: usize) {}

pub const fn harden() {}
