use oneiron_server::runtime::{GpuHealth, GpuRegistry};

#[test]
fn p2c_balances_only_its_sample_before_capacity_is_exhausted() {
    let mut registry = GpuRegistry::new("west").unwrap();
    let health = GpuHealth {
        transport: true,
        app: true,
        inference: true,
    };
    registry.register("a".into(), 100, health).unwrap();
    assert_eq!(registry.acquire(0, [0, 0]).unwrap().pod, "a");
    for pod in ["b", "c"] {
        registry.register(pod.into(), 100, health).unwrap();
    }
    let mut counts = [1_usize, 0];
    for _ in 0..40 {
        // The fixed sample is a/b. Pod c is healthy but outside that sample.
        let lease = registry.acquire(0, [0, 0]).unwrap();
        let index = match lease.pod.as_str() {
            "a" => 0,
            "b" => 1,
            _ => panic!("routing escaped its two choices"),
        };
        counts[index] += 1;
        assert!(counts[0].abs_diff(counts[1]) <= 1);
    }
}
