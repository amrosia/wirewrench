//! Per-session exclusive locks for dumb (unframed) shells.
//!
//! A dumb reverse shell has no framing: commands are written raw and output is
//! read from one shared buffer, so two clients using the same shell at once
//! interleave and steal each other's output.  A `SessionLock` serialises them.
//!
//! Ownership is bound to the **control connection**, not to a client-sent
//! "release" message: the [`LockGuard`] is dropped when the handler for that
//! connection returns, which happens as soon as the client's socket closes.
//! A `kill -9`'d (or crashed) client therefore cannot hardlock a shell — the
//! kernel closes the fd, the server sees EOF, and the guard's `Drop` releases.
//!
//! Two extra safety nets on top of that:
//!
//! * a **lease deadline** ([`Duration`]) for TCP control connections, where a
//!   dead peer can leave a socket half-open.  A background reaper expires a
//!   lock whose lease has lapsed, so the shell comes back automatically.
//! * an explicit **force** acquire, so an operator can break a lock (for
//!   example a client that is stopped, not dead, and will never close).

use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Snapshot of who holds a lock.
#[derive(Clone, Debug)]
pub struct LockState {
    /// Control-connection id that holds the lock.
    pub conn: u64,
    /// Human-readable holder (uid / key fingerprint / peer address).
    pub owner: String,
    /// When the lock was taken.
    pub since: Instant,
    /// When it lapses if not refreshed (`None` = never, e.g. Unix sockets).
    pub lease: Option<Instant>,
}

impl LockState {
    /// Seconds the lock has been held.
    #[must_use]
    pub fn held_for(&self) -> f64 {
        self.since.elapsed().as_secs_f64()
    }

    /// Seconds until the lease lapses, if it has one.
    #[must_use]
    pub fn expires_in(&self) -> Option<f64> {
        self.lease.map(|l| l.saturating_duration_since(Instant::now()).as_secs_f64())
    }
}

/// Exclusive lock for one session.  Cheap to clone behind an `Arc`.
pub struct SessionLock {
    state: StdMutex<Option<LockState>>,
    notify: Notify,
}

impl SessionLock {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self { state: StdMutex::new(None), notify: Notify::new() })
    }

    fn guard(&self) -> MutexGuard<'_, Option<LockState>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Current holder, if any.
    #[must_use]
    pub fn holder(&self) -> Option<LockState> {
        self.guard().clone()
    }

    /// Is the lock currently held by `conn`?
    #[must_use]
    pub fn held_by(&self, conn: u64) -> bool {
        self.guard().as_ref().is_some_and(|s| s.conn == conn)
    }

    /// Set the state and hand back the owning guard.  Caller holds `self`'s
    /// internal mutex when this is called; the guard is *not* the mutex guard
    /// (the lock outlives this function).
    fn install(self: &Arc<Self>, conn: u64, owner: &str, ttl: Option<Duration>, since: Instant) -> LockGuard {
        let mut g = self.guard();
        *g = Some(LockState {
            conn,
            owner: owner.to_string(),
            since,
            lease: ttl.map(|d| Instant::now() + d),
        });
        drop(g);
        LockGuard { lock: Arc::clone(self), conn }
    }

    /// Take the lock if free (or already ours — reentrant, refreshing the
    /// lease).  Returns the current holder on contention.
    pub fn try_acquire(
        self: &Arc<Self>,
        conn: u64,
        owner: &str,
        ttl: Option<Duration>,
    ) -> Result<LockGuard, LockState> {
        {
            let g = self.guard();
            if let Some(s) = g.as_ref()
                && s.conn != conn
            {
                return Err(s.clone());
            }
            let since = g.as_ref().map_or_else(Instant::now, |s| s.since);
            drop(g);
            Ok(self.install(conn, owner, ttl, since))
        }
    }

    /// Take the lock, waiting up to `wait` seconds (0 = fail immediately).
    pub async fn acquire(
        self: &Arc<Self>,
        conn: u64,
        owner: &str,
        ttl: Option<Duration>,
        wait: f64,
    ) -> Result<LockGuard, LockState> {
        let deadline = if wait > 0.0 { Some(Instant::now() + Duration::from_secs_f64(wait)) } else { None };
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            match self.try_acquire(conn, owner, ttl) {
                Ok(g) => return Ok(g),
                Err(held) => {
                    let Some(dl) = deadline else { return Err(held) };
                    let now = Instant::now();
                    if now >= dl {
                        return Err(held);
                    }
                    // Register as a waiter; `notify_one` stores a permit when
                    // there is nobody waiting, so a release racing this call is
                    // not lost.
                    if tokio::time::timeout(dl - now, notified).await.is_err() {
                        return Err(held);
                    }
                }
            }
        }
    }

    /// Take the lock unconditionally, displacing any current holder.
    pub fn force_acquire(self: &Arc<Self>, conn: u64, owner: &str, ttl: Option<Duration>) -> LockGuard {
        let old = self.guard().take();
        let guard = self.install(conn, owner, ttl, Instant::now());
        if let Some(old) = old {
            eprintln!("[!] lock on a session force-taken from {} by {}", old.owner, owner);
        }
        self.notify.notify_one();
        guard
    }

    /// Push the lease deadline out (holder activity).
    pub fn refresh(&self, conn: u64, ttl: Option<Duration>) {
        let Some(d) = ttl else { return };
        let mut g = self.guard();
        if let Some(s) = g.as_mut()
            && s.conn == conn
        {
            s.lease = Some(Instant::now() + d);
        }
    }

    /// Drop the lock if it is held by `conn`.
    fn release(&self, conn: u64) {
        let cleared = {
            let mut g = self.guard();
            if g.as_ref().is_some_and(|s| s.conn == conn) {
                *g = None;
                true
            } else {
                false
            }
        };
        if cleared {
            self.notify.notify_one();
        }
    }

    /// Expire a lapsed lease.  Returns the evicted state so the caller can log.
    pub fn expire_stale(&self, now: Instant) -> Option<LockState> {
        let evicted = {
            let mut g = self.guard();
            if g.as_ref().is_some_and(|s| s.lease.is_some_and(|l| l <= now)) {
                g.take()
            } else {
                None
            }
        };
        if evicted.is_some() {
            self.notify.notify_one();
        }
        evicted
    }
}

/// RAII ownership of a session lock.  Releasing is `Drop`, so it happens on
/// every exit path — normal return, `?`, panic unwind, or the client vanishing
/// mid-operation.
pub struct LockGuard {
    lock: Arc<SessionLock>,
    conn: u64,
}

impl LockGuard {
    /// Keep the lease alive while an operation is in progress.
    pub fn refresh(&self, ttl: Option<Duration>) {
        self.lock.refresh(self.conn, ttl);
    }

    /// Are we still the owner?  (False once the lease lapsed or it was taken.)
    #[must_use]
    pub fn still_held(&self) -> bool {
        self.lock.held_by(self.conn)
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        self.lock.release(self.conn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_then_drop_releases() {
        let l = SessionLock::new();
        let g = l.try_acquire(1, "alice", None).unwrap();
        assert!(l.held_by(1));
        assert_eq!(l.holder().unwrap().owner, "alice");
        drop(g);
        assert!(l.holder().is_none());
    }

    #[test]
    fn contention_reports_the_holder() {
        let l = SessionLock::new();
        let _g = l.try_acquire(1, "alice", None).unwrap();
        let held = l.try_acquire(2, "bob", None).err().expect("expected contention");
        assert_eq!(held.conn, 1);
        assert_eq!(held.owner, "alice");
    }

    #[test]
    fn same_connection_may_reenter() {
        let l = SessionLock::new();
        let _a = l.try_acquire(7, "x", None).unwrap();
        let _b = l.try_acquire(7, "x", None).unwrap();
        assert!(l.held_by(7));
    }

    #[test]
    fn force_displaces_and_the_old_guard_cannot_free_the_new_holder() {
        let l = SessionLock::new();
        let old = l.try_acquire(1, "alice", None).unwrap();
        let new = l.force_acquire(2, "bob", None);
        assert!(l.held_by(2));
        drop(old);
        assert!(l.held_by(2), "a displaced guard must not release the new owner");
        drop(new);
        assert!(l.holder().is_none());
    }

    #[test]
    fn lapsed_lease_is_evicted() {
        let l = SessionLock::new();
        let _g = l.try_acquire(1, "alice", Some(Duration::from_millis(1))).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let evicted = l.expire_stale(Instant::now()).expect("lease should lapse");
        assert_eq!(evicted.owner, "alice");
        assert!(l.holder().is_none());
    }

    #[test]
    fn a_lock_without_a_lease_never_lapses() {
        let l = SessionLock::new();
        let _g = l.try_acquire(1, "alice", None).unwrap();
        assert!(l.expire_stale(Instant::now()).is_none());
        assert!(l.held_by(1));
    }

    #[test]
    fn refresh_extends_the_lease() {
        let l = SessionLock::new();
        let g = l.try_acquire(1, "alice", Some(Duration::from_secs(1))).unwrap();
        let before = l.holder().unwrap().expires_in().unwrap();
        g.refresh(Some(Duration::from_secs(30)));
        let after = l.holder().unwrap().expires_in().unwrap();
        assert!(after > before, "refresh must push the deadline out");
    }

    #[tokio::test]
    async fn waiting_acquires_after_release() {
        let l = SessionLock::new();
        let guard = l.try_acquire(1, "alice", None).unwrap();
        let waiter = {
            let l = Arc::clone(&l);
            tokio::spawn(async move { l.acquire(2, "bob", None, 5.0).await.map_err(|e| e.owner) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(guard);
        let acquired = waiter.await.unwrap().expect("waiter should acquire once released");
        assert!(l.held_by(2));
        drop(acquired);
        assert!(l.holder().is_none());
    }

    #[tokio::test]
    async fn waiting_gives_up_when_the_holder_stays() {
        let l = SessionLock::new();
        let _guard = l.try_acquire(1, "alice", None).unwrap();
        let held = l.acquire(2, "bob", None, 0.05).await.err().expect("expected contention");
        assert_eq!(held.conn, 1);
    }
}
