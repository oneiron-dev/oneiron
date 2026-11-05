use std::{
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

mod power;

/// When a live wake pass may hold the machine awake (ruled 2026-10-08).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AwakePolicy {
    /// Only while on mains power. On battery normal idle sleep holds.
    #[default]
    PluggedIn,
    Always,
    Never,
}

struct AwakeState {
    program: &'static str,
    args: Vec<String>,
    policy: AwakePolicy,
    /// What a PluggedIn assertion follows the power source by (FIX 9547).
    watch: power::Watch,
    /// The host's notice that power-source changes are not observed, said
    /// at most once.
    notice: OnceLock<Box<dyn Fn() + Send + Sync>>,
    told: AtomicBool,
    held: Mutex<Held>,
}

impl AwakeState {
    /// One assertion: the child that holds the machine awake while it runs.
    fn assertion(&self) -> Option<Child> {
        Command::new(self.program)
            .args(&self.args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()
    }

    /// Says once, through the host's notice, that power-source changes are
    /// not observed here.
    fn unobserved(&self) {
        if let Some(notice) = self.notice.get()
            && !self.told.swap(true, Ordering::Relaxed)
        {
            notice();
        }
    }
}

/// The holders, the one assertion they share and, under PluggedIn, the
/// power observer their set started.
#[derive(Default)]
struct Held {
    holders: usize,
    /// Moves on at each first holder, so an ended set's observer changes
    /// nothing.
    generation: u64,
    assertion: Option<Child>,
    observer: Option<power::PowerObserver>,
}

/// One idle-sleep assertion shared by every live pass: the first holder
/// takes it and the last one out releases it. Under PluggedIn it follows the
/// power source while held: released on battery, taken again on mains.
#[derive(Clone, Default)]
pub struct KeepAwake(Option<Arc<AwakeState>>);
impl KeepAwake {
    /// A logind idle inhibitor. Suspend on lid close or by hand still wins.
    pub fn systemd(policy: AwakePolicy) -> Self {
        Self::with(
            "/usr/bin/systemd-inhibit",
            [
                "--what=idle",
                "--who=oneiron",
                "--why=a wake pass is running",
                "--mode=block",
                "sleep",
                "infinity",
            ]
            .map(String::from)
            .to_vec(),
            policy,
            power::UDEV_WATCH,
        )
    }
    /// A PreventUserIdleSystemSleep assertion; `-i` leaves display sleep be.
    pub fn launchd(policy: AwakePolicy) -> Self {
        Self::with(
            "/usr/bin/caffeinate",
            vec!["-i".to_owned()],
            policy,
            power::PMSET_WATCH,
        )
    }
    fn with(
        program: &'static str,
        args: Vec<String>,
        policy: AwakePolicy,
        watch: power::Watch,
    ) -> Self {
        Self(Some(Arc::new(AwakeState {
            program,
            args,
            policy,
            watch,
            notice: OnceLock::new(),
            told: AtomicBool::new(false),
            held: Mutex::new(Held::default()),
        })))
    }
    /// Calls `notice`, once, if this host's power-source changes cannot be
    /// observed, so a PluggedIn assertion follows only the source sampled as
    /// its holders began (FIX 9547). The first notice set stands.
    pub fn on_unobserved(&self, notice: impl Fn() + Send + Sync + 'static) {
        if let Some(state) = &self.0 {
            let _ = state.notice.set(Box::new(notice));
        }
    }
    /// Holds the machine awake until the guard drops.
    pub fn hold(&self) -> AwakeGuard {
        if let Some(state) = &self.0 {
            let mut observe = None;
            if let Ok(mut held) = state.held.lock() {
                held.holders += 1;
                if held.holders == 1 {
                    held.generation = held.generation.wrapping_add(1);
                    match state.policy {
                        AwakePolicy::Never => {}
                        AwakePolicy::Always => held.assertion = state.assertion(),
                        // The set's observer takes it on mains power.
                        AwakePolicy::PluggedIn => observe = Some(held.generation),
                    }
                }
            }
            // Started outside the lock: it samples the source and spawns.
            if let Some(generation) = observe {
                power::PowerObserver::start(state, generation);
            }
        }
        AwakeGuard(self.0.clone())
    }
}

pub struct AwakeGuard(Option<Arc<AwakeState>>);
impl Drop for AwakeGuard {
    fn drop(&mut self) {
        let Some(state) = &self.0 else {
            return;
        };
        let mut ended = (None, None);
        if let Ok(mut held) = state.held.lock() {
            held.holders = held.holders.saturating_sub(1);
            if held.holders == 0 {
                ended = (held.assertion.take(), held.observer.take());
            }
        }
        // Reaped and joined outside the lock, which the observer takes.
        release(ended.0);
        drop(ended.1);
    }
}

/// Ends an assertion or observer child: killed, then reaped.
fn release(child: Option<Child>) {
    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}
