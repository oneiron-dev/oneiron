//! Waiting for a run's existing pass without consuming its landing result.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use super::{FlightOutcome, RunCompaction, Seat};

pub(super) enum FlightReceiver {
    Receiving(Receiver<FlightOutcome>),
    Ready(FlightOutcome),
}

impl RunCompaction {
    pub(in crate::engine_executor) fn wait_for_flight(&mut self, timeout: Duration) -> bool {
        let Seat::Live(seat) = &mut self.seat else {
            return false;
        };
        let Some(flight) = seat.flight.as_mut() else {
            return false;
        };
        let FlightReceiver::Receiving(receiver) = flight else {
            return true;
        };
        match receiver.recv_timeout(timeout) {
            Ok(outcome) => {
                *flight = FlightReceiver::Ready(outcome);
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
            // The original take_finished path records the disconnected pass.
            Err(RecvTimeoutError::Disconnected) => true,
        }
    }
}
