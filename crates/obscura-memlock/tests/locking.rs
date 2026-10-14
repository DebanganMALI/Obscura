use obscura_memlock::{lock, locked_pages};

#[cfg(target_os = "linux")]
fn locked_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix("VmLck:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(u64::MAX)
}

#[cfg(not(target_os = "linux"))]
const fn locked_kib() -> u64 {
    0
}

#[test]
fn a_shared_page_stays_locked_until_its_last_holder_lets_go() {
    let secret = Box::new([0x5a_u8; 64]);
    let before = (locked_pages(), locked_kib());

    let first = lock(&*secret);
    let second = lock(&*secret);
    assert!(first.is_locked());
    assert!(second.is_locked());
    let held = (locked_pages(), locked_kib());
    assert!(held.0 > before.0);
    assert!(cfg!(not(target_os = "linux")) || held.1 > before.1);

    drop(first);
    assert_eq!((locked_pages(), locked_kib()), held);

    drop(second);
    assert_eq!((locked_pages(), locked_kib()), before);
}
