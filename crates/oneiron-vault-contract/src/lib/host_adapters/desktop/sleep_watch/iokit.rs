//! IOKit's system power notifications, on a thread of its own running a run
//! loop.
//!
//! The thread registers for the root power domain's interest notifications,
//! adds the notification port's run-loop source and runs the loop. A sleep
//! the system allows is never vetoed: the watch answers every power change
//! and only releases first while the system waits.

use super::SleepHooks;
use std::ffi::c_void;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::JoinHandle;

/// An IOKit object name.
type IoObject = u32;
/// An IOKit connection to a service.
type IoConnect = u32;
/// An IOKit return code.
type KernReturn = i32;
/// An IOKit notification port.
type IONotificationPortRef = *mut c_void;
/// A CoreFoundation run loop.
type CFRunLoopRef = *mut c_void;
/// A CoreFoundation run-loop source.
type CFRunLoopSourceRef = *mut c_void;
/// A CoreFoundation string.
type CFStringRef = *const c_void;
/// An IOKit interest callback.
type IOServiceInterestCallback = unsafe extern "C" fn(
    refcon: *mut c_void,
    service: IoObject,
    message_type: u32,
    message_argument: *mut c_void,
);

/// The system asks whether it may sleep.
const CAN_SYSTEM_SLEEP: u32 = 0xe000_0270;
/// The system will sleep.
const SYSTEM_WILL_SLEEP: u32 = 0xe000_0280;
/// The system has powered on.
const SYSTEM_HAS_POWERED_ON: u32 = 0xe000_0300;
/// `kCFRunLoopRunFinished`: the loop has no source left to run.
const RUN_LOOP_FINISHED: i32 = 1;
/// How long one run of the loop lasts before the thread reads its stop flag
/// again, in seconds.
const RUN_LOOP_SLICE_SECONDS: f64 = 1.0;

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        the_port_ref: *mut IONotificationPortRef,
        callback: IOServiceInterestCallback,
        notifier: *mut IoObject,
    ) -> IoConnect;
    fn IOAllowPowerChange(kernel_port: IoConnect, notification_id: isize) -> KernReturn;
    fn IONotificationPortGetRunLoopSource(notify: IONotificationPortRef) -> CFRunLoopSourceRef;
    fn IODeregisterForSystemPower(notifier: *mut IoObject) -> KernReturn;
    fn IOServiceClose(connect: IoConnect) -> KernReturn;
    fn IONotificationPortDestroy(notify: IONotificationPortRef);
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRunInMode(mode: CFStringRef, seconds: f64, return_after_source_handled: u8) -> i32;
    fn CFRunLoopStop(rl: CFRunLoopRef);
    static kCFRunLoopDefaultMode: CFStringRef;
}

/// What the power callback reads: the hooks and the root port.
struct PowerContext {
    hooks: Arc<dyn SleepHooks>,
    root_port: AtomicU32,
}

/// The power callback: answers every power change, releasing first while the
/// system waits. A panic never unwinds across the boundary.
unsafe extern "C" fn power_message(
    refcon: *mut c_void,
    _service: IoObject,
    message_type: u32,
    message_argument: *mut c_void,
) {
    // SAFETY: `refcon` is the boxed context's address, kept alive for the
    // loop's whole life; only this callback dereferences it, on the loop's
    // thread.
    let context = unsafe { &*refcon.cast::<PowerContext>() };
    let root_port = context.root_port.load(Ordering::SeqCst);
    // The notification id rides in the argument pointer; the allow call takes
    // it as the address-sized integer the framework declares.
    let notification = message_argument as isize;
    if message_type == CAN_SYSTEM_SLEEP {
        // SAFETY: `root_port` is the registered connection and `notification`
        // is this message's id.
        unsafe {
            IOAllowPowerChange(root_port, notification);
        }
    } else if message_type == SYSTEM_WILL_SLEEP {
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| context.hooks.will_sleep()));
        // SAFETY: as above; the release ran first, and the sleep is still
        // answered when the release panicked.
        unsafe {
            IOAllowPowerChange(root_port, notification);
        }
    } else if message_type == SYSTEM_HAS_POWERED_ON {
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| context.hooks.woke()));
    }
}

/// A run loop stopped from another thread.
struct RunLoopRef(CFRunLoopRef);

// SAFETY: `CFRunLoopStop` may be called from any thread; the pointer stays
// valid until the run-loop thread joins.
unsafe impl Send for RunLoopRef {}
// SAFETY: the only use of the pointer is `CFRunLoopStop`, which is safe from
// any thread at once.
unsafe impl Sync for RunLoopRef {}

/// What the run-loop thread reports back to the start.
enum ThreadReady {
    /// The registration failed.
    Failed,
    /// The loop runs.
    Running(RunLoopRef),
}

/// The IOKit sleep watch: its run loop, the loop's stop flag and its thread.
/// Dropping it sets the flag and stops the loop, then joins the thread.
pub(super) struct IokitWatch {
    run_loop: RunLoopRef,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl IokitWatch {
    /// Starts the IOKit watch: the run-loop thread registers, reports its
    /// loop back and runs it. `None` when it did not register, which
    /// `unobserved` hears once with its reason.
    pub(super) fn start(
        hooks: Arc<dyn SleepHooks>,
        unobserved: impl FnOnce(&'static str),
    ) -> Option<Self> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = match std::thread::Builder::new()
            .name("oneiron-sleep".to_owned())
            .spawn(move || run_loop_thread(hooks, &thread_stop, &ready_tx))
        {
            Ok(thread) => thread,
            Err(_) => {
                unobserved("sleep watch thread did not start");
                return None;
            }
        };
        match ready_rx.recv() {
            Ok(ThreadReady::Running(run_loop)) => Some(Self {
                run_loop,
                stop,
                thread: Some(thread),
            }),
            Ok(ThreadReady::Failed) | Err(_) => {
                let _ = thread.join();
                unobserved("IORegisterForSystemPower failed");
                None
            }
        }
    }
}

impl Drop for IokitWatch {
    fn drop(&mut self) {
        // The flag ends a loop the stop below reaches before it runs.
        self.stop.store(true, Ordering::SeqCst);
        // SAFETY: `run_loop` is the thread's current loop, alive until the
        // thread joins below; `CFRunLoopStop` may run on any thread.
        unsafe {
            CFRunLoopStop(self.run_loop.0);
        }
        if let Some(thread) = self.thread.take()
            && thread.thread().id() != std::thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

/// The run-loop thread: registers, reports its loop back and runs it in
/// slices until `stop` is set, then deregisters, closes and destroys before
/// it ends.
fn run_loop_thread(
    hooks: Arc<dyn SleepHooks>,
    stop: &AtomicBool,
    ready: &std::sync::mpsc::Sender<ThreadReady>,
) {
    let context = Box::new(PowerContext {
        hooks,
        root_port: AtomicU32::new(0),
    });
    let context_ptr = std::ptr::from_ref(&*context).cast_mut().cast::<c_void>();
    let mut port_ref: IONotificationPortRef = std::ptr::null_mut();
    let mut notifier: IoObject = 0;
    // SAFETY: `context_ptr` is the boxed context, alive until the thread
    // ends; `port_ref` and `notifier` are valid out parameters; the callback
    // is a valid interest function.
    let root_port = unsafe {
        IORegisterForSystemPower(context_ptr, &mut port_ref, power_message, &mut notifier)
    };
    if root_port == 0 {
        let _ = ready.send(ThreadReady::Failed);
        return;
    }
    context.root_port.store(root_port, Ordering::SeqCst);
    // SAFETY: the registration succeeded, so `port_ref` is a live
    // notification port; the current loop exists on this thread.
    let run_loop = unsafe { CFRunLoopGetCurrent() };
    // SAFETY: as above; the source belongs to the live port.
    let source = unsafe { IONotificationPortGetRunLoopSource(port_ref) };
    // SAFETY: `run_loop` and `source` are live; the default mode is a valid
    // constant string for the loop's life.
    unsafe {
        CFRunLoopAddSource(run_loop, source, kCFRunLoopDefaultMode);
    }
    let _ = ready.send(ThreadReady::Running(RunLoopRef(run_loop)));
    while !stop.load(Ordering::SeqCst) {
        // SAFETY: the loop is this thread's current one, and the default
        // mode is a valid constant string for its life.
        let ran = unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, RUN_LOOP_SLICE_SECONDS, 0) };
        if ran == RUN_LOOP_FINISHED {
            break;
        }
    }
    // SAFETY: `notifier` is the registration this thread made.
    unsafe {
        IODeregisterForSystemPower(&mut notifier);
    }
    // SAFETY: `root_port` is the connection this thread registered.
    unsafe {
        IOServiceClose(root_port);
    }
    // SAFETY: `port_ref` is the port this thread registered with.
    unsafe {
        IONotificationPortDestroy(port_ref);
    };
}
