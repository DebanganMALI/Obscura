use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

use obscura_vault::Vault;

pub const DEFAULT_AUTO_LOCK: Duration = Duration::from_secs(5 * 60);

pub const MAX_AUTO_LOCK: Duration = Duration::from_secs(60 * 60);

pub struct Session {
    pub vault: Vault,
    pub path: PathBuf,
    pub last_activity: Instant,
    pub last_seen: SystemTime,
    pub min_revision: u64,
}

impl Session {
    pub fn new(vault: Vault, path: PathBuf) -> Self {
        let min_revision = vault.revision();
        Self {
            vault,
            path,
            last_activity: Instant::now(),
            last_seen: SystemTime::now(),
            min_revision,
        }
    }

    fn idle_for(&self, timeout: Duration) -> bool {
        if self.last_activity.elapsed() >= timeout {
            return true;
        }
        SystemTime::now()
            .duration_since(self.last_seen)
            .map_or(true, |elapsed| elapsed >= timeout)
    }

    fn mark_active(&mut self) {
        self.last_activity = Instant::now();
        self.last_seen = SystemTime::now();
    }
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
        f(session)
    }

    pub fn touch(&self) {
        if let Ok(mut guard) = self.session.lock() {
            if let Some(session) = guard.as_mut() {
                session.mark_active();
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
            .is_some_and(|session| session.idle_for(timeout));
        if expired {
            guard.take();
        }
        expired
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use obscura_crypto::KdfParams;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    fn session() -> Session {
        Session::new(
            Vault::create(b"correct horse battery staple", FAST).unwrap(),
            PathBuf::from("vault.obscura"),
        )
    }

    #[test]
    fn a_machine_that_slept_through_the_timeout_still_locks() {
        let state = AppState::default();
        state.set_auto_lock(Duration::from_secs(60));

        let mut resumed = session();
        resumed.last_activity = Instant::now();
        resumed.last_seen = SystemTime::now() - Duration::from_secs(3600);
        state.set(resumed);

        assert!(
            state.lock_if_idle(),
            "Instant does not advance across suspend, so an hour asleep leaves the monotonic \
             timer untouched and the vault open behind the lock screen"
        );
        assert!(!state.is_unlocked());
    }

    #[test]
    fn an_active_session_is_left_alone() {
        let state = AppState::default();
        state.set_auto_lock(Duration::from_secs(600));
        state.set(session());

        assert!(!state.lock_if_idle());
        assert!(state.is_unlocked());
    }

    #[test]
    fn a_clock_moved_backwards_locks_rather_than_being_trusted() {
        let state = AppState::default();
        state.set_auto_lock(Duration::from_secs(60));

        let mut skewed = session();
        skewed.last_seen = SystemTime::now() + Duration::from_secs(3600);
        state.set(skewed);

        assert!(
            state.lock_if_idle(),
            "a last-seen time in the future means the clock moved, and locking is the safe answer"
        );
    }

    #[test]
    fn a_background_poll_does_not_hold_the_vault_open() {
        let state = AppState::default();
        state.set_auto_lock(Duration::from_secs(60));

        let mut idled = session();
        idled.last_seen = SystemTime::now() - Duration::from_secs(3600);
        state.set(idled);

        state.with_session(|_| Ok(())).unwrap();

        assert!(
            state.lock_if_idle(),
            "reading through with_session must not count as activity, or a one-second \
             TOTP poll keeps the vault unlocked for as long as the entry is on screen"
        );
    }

    #[test]
    fn an_explicit_touch_does_hold_the_vault_open() {
        let state = AppState::default();
        state.set_auto_lock(Duration::from_secs(60));

        let mut idled = session();
        idled.last_seen = SystemTime::now() - Duration::from_secs(3600);
        state.set(idled);

        state.touch();

        assert!(
            !state.lock_if_idle(),
            "real input still refreshes the timer - the frontend sends touch on pointerdown and keydown"
        );
    }
}
