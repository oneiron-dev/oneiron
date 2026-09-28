//! Shared host stub for cross-module connector admission tests.
use super::*;

struct NamedStub {
    inner: Stub,
    name: String,
}
struct NamedConnection<'a> {
    inner: Box<dyn QualificationConnection + 'a>,
    name: String,
}
impl QualificationConnection for NamedConnection<'_> {
    fn tools_list(&mut self) -> Result<Vec<ProbeTool>, QualificationFailure> {
        let mut tools = self.inner.tools_list()?;
        tools[0].name.clone_from(&self.name);
        Ok(tools)
    }
    fn call(&mut self, request: &ProbeRequest) -> Result<ProbeReply, QualificationFailure> {
        self.inner.call(request)
    }
}
impl QualificationConnector for NamedStub {
    fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure> {
        Ok(Box::new(NamedConnection {
            inner: self.inner.connect()?,
            name: self.name.clone(),
        }))
    }
    fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure> {
        self.inner.effect_state()
    }
}
/// Two independent connections; in-/out-of-scope reads, cited writes,
/// idempotency replay and timeout retry all execute through the real runner.
pub(crate) fn passing_suite(
    name: &str,
) -> (
    Box<dyn QualificationConnector>,
    QualificationPlan,
    Box<dyn GroundingOracle>,
) {
    let mut plan = super::plan();
    for case in &mut plan.reads {
        case.call.name = name.into();
    }
    plan.write.as_mut().expect("write case").call.name = name.into();
    plan.timeout_retry.as_mut().expect("retry case").call.name = name.into();
    (
        Box::new(NamedStub {
            inner: Stub {
                fault: Fault::None,
                connections: Cell::new(0),
                effects: Rc::default(),
            },
            name: name.into(),
        }),
        plan,
        Box::new(Oracle),
    )
}
