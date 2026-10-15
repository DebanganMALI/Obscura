use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, FindWindowW, GetForegroundWindow, GetWindowThreadProcessId,
    SetForegroundWindow, ASFW_ANY,
};

const DIALOG_CLASS: &str = "Credential Dialog Xaml Host";
const POLL: Duration = Duration::from_millis(100);
const LIMIT: Duration = Duration::from_secs(150);

pub struct PromptWatch {
    done: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
}

impl Drop for PromptWatch {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

#[must_use]
pub fn watch_for_prompts() -> PromptWatch {
    unsafe { AllowSetForegroundWindow(ASFW_ANY) };
    let done = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&done);
    let watcher = thread::Builder::new()
        .name("obscura-prompt".to_owned())
        .spawn(move || watch(&flag))
        .ok();
    PromptWatch { done, watcher }
}

fn watch(done: &AtomicBool) {
    let class: Vec<u16> = DIALOG_CLASS.encode_utf16().chain([0]).collect();
    let ours = std::process::id();
    let started = Instant::now();
    while !done.load(Ordering::Relaxed) && started.elapsed() < LIMIT {
        let dialog = unsafe { FindWindowW(class.as_ptr(), std::ptr::null()) };
        if !dialog.is_null() {
            let front = unsafe { GetForegroundWindow() };
            if front != dialog && (front.is_null() || owner(front) == ours) {
                unsafe { SetForegroundWindow(dialog) };
            }
        }
        thread::sleep(POLL);
    }
}

fn owner(window: HWND) -> u32 {
    let mut process = 0u32;
    unsafe { GetWindowThreadProcessId(window, &raw mut process) };
    process
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_watch_stops_as_soon_as_its_guard_is_dropped() {
        let started = Instant::now();
        let watch = watch_for_prompts();
        thread::sleep(POLL * 2);
        drop(watch);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
