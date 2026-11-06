//! Owned caller-built pack state in decision-ask output records.

use oneiron::llm::decision::DecisionAsk;

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_decision_ask(
    verb: &str,
    mut ask: DecisionAsk,
) -> Result<crate::DecisionAsk, OneironError> {
    let state = take_state(&mut ask)?;
    let mut output: crate::DecisionAsk = lift_record(verb, &ask)?;
    output.pack_state = state;
    Ok(output)
}

pub(crate) fn lift_decision_asks(
    verb: &str,
    mut asks: Vec<DecisionAsk>,
) -> Result<Vec<crate::DecisionAsk>, OneironError> {
    let states: Vec<_> = asks.iter_mut().map(take_state).collect();
    // Consume every native JSON leaf before returning the first error.
    let states: Vec<_> = states.into_iter().collect::<Result<_, _>>()?;
    let mut output: Vec<crate::DecisionAsk> = lift_record(verb, &asks)?;
    for (ask, state) in output.iter_mut().zip(states) {
        ask.pack_state = state;
    }
    Ok(output)
}

fn take_state(ask: &mut DecisionAsk) -> Result<Option<WireJson>, OneironError> {
    ask.pack_state
        .take()
        .filter(|value| !value.is_null())
        .map(WireJson::lift)
        .transpose()
}
