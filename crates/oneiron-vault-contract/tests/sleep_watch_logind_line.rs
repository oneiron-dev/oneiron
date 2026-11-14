#![cfg(target_os = "linux")]

use oneiron_vault_contract::host_adapters::prepare_for_sleep_line;

#[test]
fn a_prepare_for_sleep_true_line_reads_true() {
    assert_eq!(
        prepare_for_sleep_line(
            "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (true,)"
        ),
        Some(true)
    );
}

#[test]
fn a_prepare_for_sleep_false_line_reads_false() {
    assert_eq!(
        prepare_for_sleep_line(
            "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (false,)"
        ),
        Some(false)
    );
}

#[test]
fn header_and_other_signal_lines_read_none() {
    assert_eq!(
        prepare_for_sleep_line(
            "Monitoring signals from all objects owned by org.freedesktop.login1"
        ),
        None
    );
    assert_eq!(
        prepare_for_sleep_line("The name org.freedesktop.login1 is owned by :1.5"),
        None
    );
    assert_eq!(
        prepare_for_sleep_line(
            "/org/freedesktop/login1: org.freedesktop.login1.Manager.SessionNew ('c2', '/org/freedesktop/login1/session/c2')"
        ),
        None
    );
    assert_eq!(prepare_for_sleep_line(""), None);
}
