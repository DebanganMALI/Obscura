use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

use obscura_vault::Vault;

pub const DEFAULT_AUTO_LOCK: Duration = Duration::from_secs(5 * 60);

pub const MAX_AUTO_LOCK: Duration = Duration::from_secs(60 * 60);

pub struct Session {
    pub vault: Vault,
    pub path: PathBuf,
    pub last_activity: Instant,
    pub min_revision: u64,
}

pub struct AppState {
    session: Mutex<Option<Session>>,
    auto_lock: Mutex<Duration>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            session: Mutex::new(None),
            auto_lock: Mutex::new(DEFAULT_AUTO_LOCK),
        }
    }
}

impl AppState {
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.session.lock().is_ok_and(|guard| guard.is_some())
    }

    pub fn set(&self, session: Session) {
        if let Ok(mut guard) = self.session.lock() {
            *guard = Some(session);
        }
    }

    pub fn lock(&self) -> bool {
        self.session
            .lock()
            .is_ok_and(|mut guard| guard.take().is_some())
    }

    pub fn with_session<T>(
        &self,
        f: impl FnOnce(&mut Session) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| "the vault state is poisoned".to_owned())?;
        let session = guard.as_mut().ok_or_else(|| "locked".to_owned())?;
        session.last_activity = Instant::now();
        f(session)
    }

    pub fn touch(&self) {
        if let Ok(mut guard) = self.session.lock() {
            if let Some(session) = guard.as_mut() {
                session.last_activity = Instant::now();
            }
        }
    }

    #[must_use]
    pub fn auto_lock(&self) -> Duration {
        self.auto_lock
            .lock()
            .map_or(DEFAULT_AUTO_LOCK, |guard| *guard)
    }

    pub fn set_auto_lock(&self, timeout: Duration) {
        let clamped = timeout.clamp(Duration::from_secs(15), MAX_AUTO_LOCK);
        if let Ok(mut guard) = self.auto_lock.lock() {
            *guard = clamped;
        }
    }

    #[must_use]
    pub fn lock_if_idle(&self) -> bool {
        let timeout = self.auto_lock();
        let Ok(mut guard) = self.session.lock() else {
            return false;
        };
        let expired = guard
            .as_ref()
            .is_some_and(|session| session.last_activity.elapsed() >= timeout);
        if expired {
            guard.take();
        }
        expired
    }
}
