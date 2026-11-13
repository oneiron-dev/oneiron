//! Diagnostic, pin only (not for merge): where assembling the OpenAPI
//! document spends its time, stage by stage, three runs in one process.

use oneiron_server::test_doors::openapi_document::stage_ms;

#[test]
fn openapi_document_stage_timing() {
    for run in 0..3 {
        let stages = stage_ms();
        let mut total = 0.0;
        for (name, value) in &stages {
            if matches!(*name, "paths" | "schemas" | "bytes") {
                println!("## OPENAPI-SIZE run={run} {name}={value:.0}");
            } else {
                total += value;
                println!("## OPENAPI-STAGE run={run} {name} ms={value:.1}");
            }
        }
        println!("## OPENAPI-STAGE run={run} total ms={total:.1}");
        assert!(stages.len() > 3, "the stages were timed");
    }
}
