//! A paid job's checkpoint signals at 50, 80 and 95 percent of its maximum
//! (CROSS-ARCH-0023 lifecycle 04), and a stored job's maximum state: a host
//! restart keeps the warning, the checkpoint, the stop and its one resume.

use oneiron_run_budget::run_budget::{
    CheckpointRef, DeclaredMaximum, JobMaximum, JobSignal, LeaseUnit, MaximumShown, MaximumStop,
    ResumeOffer, ResumeRefused, StopRefused,
};

const SHOWN: Option<MaximumShown> = Some(MaximumShown { at_ms: 1 });

fn maximum(units: u64) -> DeclaredMaximum {
    DeclaredMaximum {
        units,
        unit: LeaseUnit::new("gpu_seconds").expect("unit"),
    }
}

fn warning(used_units: u64, maximum_units: u64) -> JobSignal {
    JobSignal::Warning95 {
        used_units,
        maximum_units,
    }
}

fn checkpoint_due(percent: u8) -> JobSignal {
    JobSignal::CheckpointDue { percent }
}

fn checkpoint(name: &str) -> CheckpointRef {
    CheckpointRef(name.to_owned())
}

/// Stores the job as its record would and reads it back.
fn round_trip(job: &JobMaximum) -> JobMaximum {
    let stored = serde_json::to_string(job).expect("store the job");
    let restored: JobMaximum = serde_json::from_str(&stored).expect("restore the job");
    assert_eq!(&restored, job);
    restored
}

/// Runs a job to its maximum and stops it from `name`.
fn stopped_at(units: u64, name: &str) -> (JobMaximum, MaximumStop) {
    let mut job = JobMaximum::start("job-1", maximum(units), SHOWN).expect("start");
    job.record_usage(units);
    assert!(job.confirm_warning());
    job.checkpoint(checkpoint(name));
    let stop = job.stop_at_maximum().expect("stop at the maximum");
    (job, stop)
}

#[test]
fn checkpoint_signals_fire_once_at_fifty_eighty_and_ninety_five() {
    let mut job = JobMaximum::start("job-1", maximum(100), SHOWN).expect("start");
    assert_eq!(job.record_usage(49), vec![]);
    assert_eq!(job.record_usage(50), vec![checkpoint_due(50)]);
    assert_eq!(job.record_usage(79), vec![]);
    assert_eq!(job.record_usage(80), vec![checkpoint_due(80)]);
    assert_eq!(job.record_usage(94), vec![]);
    assert_eq!(
        job.record_usage(95),
        vec![checkpoint_due(95), warning(95, 100)]
    );
    // The customer's warning repeats until it is confirmed; the job's
    // checkpoint signal does not.
    assert_eq!(job.record_usage(96), vec![warning(96, 100)]);
    assert!(job.confirm_warning());
    assert_eq!(job.record_usage(97), vec![]);
    assert_eq!(
        serde_json::to_value(checkpoint_due(50)).expect("signal json"),
        serde_json::json!({ "signal": "checkpoint_due", "percent": 50 })
    );

    // A record that passes several percents at once asks for one checkpoint.
    let mut jumping = JobMaximum::start("job-2", maximum(100), SHOWN).expect("start");
    assert_eq!(jumping.record_usage(85), vec![checkpoint_due(80)]);
    assert_eq!(jumping.record_usage(90), vec![]);
    assert_eq!(
        jumping.record_usage(120),
        vec![checkpoint_due(95), warning(120, 100), JobSignal::AtMaximum]
    );
}

#[test]
fn a_stored_job_keeps_its_warning_checkpoint_and_stop() {
    let mut job = JobMaximum::start("job-1", maximum(100), SHOWN).expect("start");
    assert_eq!(
        job.record_usage(95),
        vec![checkpoint_due(95), warning(95, 100)]
    );
    assert!(job.confirm_warning());

    // Restored after the warning reached the customer and before any
    // checkpoint: the warning stays delivered, and the stop still waits.
    let mut job = round_trip(&job);
    assert_eq!(job.record_usage(100), vec![JobSignal::AtMaximum]);
    assert_eq!(job.stop_at_maximum(), Err(StopRefused::NoCheckpoint));
    job.checkpoint(checkpoint("ck-1"));
    let mut job = round_trip(&job);
    let stop = job.stop_at_maximum().expect("stop at the maximum");
    assert_eq!(stop.notice.checkpoint, checkpoint("ck-1"));
    assert_eq!(stop.notice.used_units, 100);
    assert_eq!(stop.notice.maximum, maximum(100));

    // Restored after the stop, with the offer from the stored notice.
    let mut job = round_trip(&job);
    assert!(job.is_stopped());
    assert_eq!(job.stop_at_maximum(), Err(StopRefused::Stopped));
    let offer: ResumeOffer =
        serde_json::from_str(&serde_json::to_string(&stop.resume).expect("store offer"))
            .expect("restore offer");
    assert_eq!(
        job.resume(&offer, maximum(100), SHOWN),
        Err(ResumeRefused::MaximumNotRaised)
    );
    assert_eq!(
        job.resume(&offer, maximum(200), SHOWN),
        Ok(checkpoint("ck-1"))
    );
    assert_eq!(
        job.resume(&offer, maximum(300), SHOWN),
        Err(ResumeRefused::NotStopped)
    );

    // At the next stop, the first offer is spent.
    job.record_usage(200);
    assert!(job.confirm_warning());
    job.checkpoint(checkpoint("ck-2"));
    let second = job.stop_at_maximum().expect("second stop");
    let mut job = round_trip(&job);
    assert_eq!(
        job.resume(&offer, maximum(300), SHOWN),
        Err(ResumeRefused::StaleOffer)
    );
    assert_eq!(
        job.resume(&second.resume, maximum(300), SHOWN),
        Ok(checkpoint("ck-2"))
    );
}

#[test]
fn a_resumed_chunk_signals_again() {
    let (mut job, stop) = stopped_at(100, "ck-1");
    assert_eq!(
        job.resume(&stop.resume, maximum(300), SHOWN),
        Ok(checkpoint("ck-1"))
    );
    let mut job = round_trip(&job);
    assert_eq!(job.record_usage(149), vec![]);
    assert_eq!(job.record_usage(150), vec![checkpoint_due(50)]);
    assert_eq!(job.record_usage(240), vec![checkpoint_due(80)]);
    assert_eq!(
        job.record_usage(285),
        vec![checkpoint_due(95), warning(285, 300)]
    );

    // A chunk that starts past a percent of its new maximum is not told to
    // checkpoint again for it: it has just restored from one.
    let (mut job, stop) = stopped_at(100, "ck-1");
    assert_eq!(
        job.resume(&stop.resume, maximum(200), SHOWN),
        Ok(checkpoint("ck-1"))
    );
    assert_eq!(job.record_usage(100), vec![]);
    assert_eq!(job.record_usage(159), vec![]);
    assert_eq!(job.record_usage(160), vec![checkpoint_due(80)]);
}
