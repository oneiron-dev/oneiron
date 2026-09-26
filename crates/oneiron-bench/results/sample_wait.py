"""Sample ALL tasks during full-thread prefix only; includes leader, excludes drain tail.

This is a point-in-time wait-channel profile, not a complete trial-time breakdown.
The count guard intentionally omits warmup and the tail after the first worker exits.
"""
import collections, json, pathlib, re, sys, time
pid=int(sys.argv[1]); log=pathlib.Path(sys.argv[2]); out=pathlib.Path(sys.argv[3]); task=pathlib.Path(f"/proc/{pid}/task")
counts=collections.defaultdict(collections.Counter)
samples=collections.Counter()
while task.exists():
    try:
        text=log.read_text()
        lines=re.findall(r"START (\w+) (\d+) trial=(\d+)", text)
        if lines:
            mode, agents, trial=lines[-1]
            tids=list(task.iterdir())
            if len(tids)>=int(agents)+1:
                key=f"{mode}:{agents}:trial{trial}"
                samples[key]+=1
                for t in tids:
                    try:
                        state=t.joinpath("status").read_text().split("State:",1)[1].splitlines()[0].strip().split()[0]
                        wchan=t.joinpath("wchan").read_text().strip()
                        counts[key][f"{state}:{wchan}"]+=1
                    except (OSError, IndexError): pass
        if "EXIT=" in text:break
    except (OSError,ValueError):pass
    time.sleep(0.05)
out.write_text(json.dumps({"scope":"all tasks including leader, full-thread prefix only; no draining tail", "interval_ms":50, "samples":samples,"wait_channels":counts},indent=2,sort_keys=True))
