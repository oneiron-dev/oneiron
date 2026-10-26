//! An ask spec as its class and the engine admit it: `TaskAskSpec::effective`.

use super::*;

impl TaskAskSpec {
    pub(in crate::task_verb) fn effective(
        &self,
        who: &BTreeSet<EntityId>,
        now: u64,
        bound: Option<TaskAskClass>,
    ) -> MemoryResult<Self> {
        // Counts and sizes never refuse here: an ask's rows measure them
        // where it is kept (`ask_limits`), and it is served whole.
        if self.intent_key.trim().is_empty()
            || self.what.revision == 0
            || self.what.revision > u64::from(u32::MAX)
            || who.is_empty()
        {
            return Err(MemoryError::bad_request("invalid ask spec"));
        }
        let mut effective = self.clone();
        if let Some(bound) = bound {
            if self.class.as_ref().is_some_and(|class| class != &bound) {
                return Err(MemoryError::bad_request(
                    "ask cannot replace its task's class",
                ));
            }
            effective.class = Some(bound);
        }
        if let Some(ladder) = &self.what.ladder_answer
            && (!self.what.options.contains_key(&ladder.option)
                || !matches!(
                    ladder.rung,
                    crate::llm::decision::DecisionRung::Rule
                        | crate::llm::decision::DecisionRung::SystemOne
                        | crate::llm::decision::DecisionRung::Escalation
                )
                || ladder
                    .probability
                    .is_some_and(|p| !p.is_finite() || !(0.0..=1.0).contains(&p))
                || (ladder.rung != crate::llm::decision::DecisionRung::Rule
                    && ladder.probability.is_none()))
        {
            return Err(MemoryError::bad_request("invalid ask ladder prediction"));
        }
        if self.what.class_key.as_ref().is_some_and(String::is_empty) {
            return Err(MemoryError::bad_request("invalid ask question class"));
        }
        if let Some(binding) = &self.what.outcome_binding {
            binding.validate()?;
        }
        if let Some(class) = &effective.class {
            if self
                .what
                .class_key
                .as_deref()
                .is_some_and(|key| key != class.key)
            {
                return Err(MemoryError::bad_request(
                    "ask question class conflicts with task policy",
                ));
            }
            effective.what.class_key = Some(class.key.clone());
            if class.key.is_empty()
                || class.version == 0
                || class.deadline_seconds == 0
                || !who.is_subset(&class.allowed_recipients)
                || !class.required_people.is_subset(who)
                || usize::from(class.minimum_responses) > who.len()
            {
                return Err(MemoryError::bad_request("impossible ask class obligations"));
            }
            // A zero limit discloses nothing; any other is the class's own
            // setting, observed at its asks, never capped by a storage bound
            // (FIX 10173).
            if class.guest_fact_limit == Some(0) {
                return Err(MemoryError::bad_request("invalid ask guest fact limit"));
            }
            if class.governance {
                match effective.default {
                    TaskAskDefault::Proceed => {
                        return Err(MemoryError::bad_request(
                            "governance ask cannot default to proceed",
                        ));
                    }
                    TaskAskDefault::AskMe => effective.default = TaskAskDefault::Hold,
                    TaskAskDefault::Hold => {}
                }
                if effective.on_disagree.branch == TaskAskBranch::Proceed {
                    return Err(MemoryError::bad_request(
                        "governance disagreement cannot proceed",
                    ));
                }
            }
            let disagreement = match effective.on_disagree.branch {
                TaskAskBranch::Hold => TaskAskDefault::Hold,
                TaskAskBranch::Proceed => TaskAskDefault::Proceed,
            };
            if !class.fallback.contains(&effective.default)
                || !class.fallback.contains(&disagreement)
            {
                return Err(MemoryError::bad_request("ask fallback violates class"));
            }
            if self.need.count < class.minimum_responses {
                return Err(MemoryError::bad_request("ask coverage violates class"));
            }
            if let Some(decide) = &class.decision {
                if effective
                    .decide
                    .as_ref()
                    .is_some_and(|requested| requested != decide)
                {
                    return Err(MemoryError::bad_request("ask decision violates class"));
                }
                effective.decide = Some(decide.clone());
            }
            let disclosed: BTreeSet<_> = std::iter::once(self.what.reference)
                .chain(self.what.context_refs.iter().copied())
                .collect();
            if !class.required_sources.is_subset(&disclosed)
                || who.iter().any(|actor| {
                    class
                        .disclosure
                        .get(actor)
                        .is_none_or(|allowed| !disclosed.is_subset(allowed))
                })
            {
                return Err(MemoryError::bad_request(
                    "ask sources or disclosure violate class",
                ));
            }
            if effective.until.is_none() {
                effective.until = Some(
                    now.checked_add(class.deadline_seconds)
                        .ok_or_else(|| MemoryError::bad_request("ask deadline overflow"))?,
                );
            }
            if effective.remind.is_none() {
                effective.remind = Some(class.remind.clone());
            }
        }
        if effective.what.ladder_answer.is_some() && effective.what.class_key.is_none() {
            return Err(MemoryError::bad_request(
                "comparable ask requires a question class",
            ));
        }
        // Ungoverned short asks still need a finite cutoff. A bound class
        // supplies its own deadline first; otherwise use the base one-day TTL.
        if effective.until.is_none() {
            effective.until = Some(
                now.checked_add(24 * 60 * 60)
                    .ok_or_else(|| MemoryError::bad_request("ask deadline overflow"))?,
            );
        }
        if effective.until.is_none_or(|until| until <= now) {
            return Err(MemoryError::bad_request(
                "ask needs a future deadline or a class deadline policy",
            ));
        }
        let seats = effective.need.of.seats(who)?;
        if effective.need.count == 0 || usize::from(effective.need.count) > seats.len() {
            return Err(MemoryError::bad_request("impossible ask response coverage"));
        }
        match &effective.decide {
            Some(TaskAskDecide::First)
                if effective.need.count > 1
                    || effective
                        .class
                        .as_ref()
                        .is_some_and(|class| class.required_people.len() > 1) =>
            {
                return Err(MemoryError::bad_request(
                    "first decision cannot require multiple responses",
                ));
            }
            Some(TaskAskDecide::All { of, answer } | TaskAskDecide::AtLeast { of, answer, .. }) => {
                let seats = of.seats(who)?;
                if !effective.what.options.contains_key(answer) {
                    return Err(MemoryError::bad_request(
                        "ask decision names an unknown option",
                    ));
                }
                if let Some(TaskAskDecide::AtLeast { count, .. }) = &effective.decide
                    && (*count == 0 || usize::from(*count) > seats.len())
                {
                    return Err(MemoryError::bad_request(
                        "impossible ask decision threshold",
                    ));
                }
            }
            _ => {}
        }
        let remind = effective.remind.get_or_insert_with(Vec::new);
        if remind.iter().any(|delay| now.checked_add(*delay).is_none())
            || remind.first() == Some(&0)
            || remind.windows(2).any(|pair| pair.first() >= pair.get(1))
        {
            return Err(MemoryError::bad_request(
                "ask reminders must be positive, increasing, and without time overflow",
            ));
        }
        Ok(effective)
    }
}
