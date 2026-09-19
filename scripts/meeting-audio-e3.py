#!/usr/bin/env python3
"""Local E3 capture and named-principal scoring. No model acquisition or role changes.

Capture executes both full-file ports. Scoring separately consumes output-bound,
host-supplied enrollment matching receipts; it never fits labels to the truth.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import subprocess
import uuid
import os
import signal


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


runtime = module("meeting_audio_runtime", Path(__file__).with_name("meeting_audio_runtime.py"))
bridge = module("meeting_audio_native", Path(__file__).with_name("meeting-audio-native.py"))
ARMS = {"community1": ("community1_exclusive_full_file", "exclusive_tracks", "diarization"),
        "moss": ("moss_e3_full_file", "segment_tracks", "moss")}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()


def checksum(value):
    return hashlib.sha256(value).hexdigest()


def read_bytes(path, limit=64 * 1024 * 1024):
    if not path.is_file() or path.stat().st_size > limit:
        raise bridge.Refusal("InputUnavailableOrTooLarge")
    data = path.read_bytes()
    if len(data) > limit:
        raise bridge.Refusal("InputTooLarge")
    return data


def read_json(path):
    try:
        return runtime.strict_json(read_bytes(path))
    except (ValueError, UnicodeError):
        raise bridge.Refusal("InvalidJson") from None


def write_new(path, value):
    with path.open("xb") as stream:
        stream.write(encoded(value))


def nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def checked_reference(value):
    if (not isinstance(value, dict) or set(value) != {"language", "tokenizer", "words"}
            or not nonblank(value["language"]) or not nonblank(value["tokenizer"])
            or not isinstance(value["words"], list) or not 1 <= len(value["words"]) <= 100000):
        raise bridge.Refusal("InvalidReference")
    seen, speakers = set(), set()
    for word in value["words"]:
        if (not isinstance(word, dict) or set(word) != {"word_id", "start_ms", "end_ms", "principal_id"}
                or not nonblank(word["word_id"]) or word["word_id"] in seen
                or not nonblank(word["principal_id"])
                or type(word["start_ms"]) is not int or type(word["end_ms"]) is not int
                or not 0 <= word["start_ms"] < word["end_ms"] <= 7200000):
            raise bridge.Refusal("InvalidReference")
        seen.add(word["word_id"])
        speakers.add(word["principal_id"])
    if len(speakers) < 2:
        raise bridge.Refusal("TwoSpeakerReferenceRequired")
    return value


def select_cluster(word, tracks):
    best, best_i, best_u = None, 0, 1
    for track in tracks:
        intersection = max(0, min(word["end_ms"], track["end_ms"]) - max(word["start_ms"], track["start_ms"]))
        union = max(word["end_ms"], track["end_ms"]) - min(word["start_ms"], track["start_ms"])
        if intersection and intersection * best_u > best_i * union:
            best, best_i, best_u = track["speaker_cluster"], intersection, union
    return best


def score_words(reference, tracks, mapping):
    # Mapping comes from enrollment matching, never an optimization against
    # reference identities. Missing/unmatched predictions are scored as missing.
    score = {"correct": 0, "wrong_speaker": 0, "missing_words": 0, "reference_words": len(reference["words"])}
    for word in reference["words"]:
        predicted = mapping.get(select_cluster(word, tracks))
        if predicted is None:
            score["missing_words"] += 1
        elif predicted == word["principal_id"]:
            score["correct"] += 1
        else:
            score["wrong_speaker"] += 1
    return score


class ProcessPorts:
    """One bounded framed subprocess per port, using this existing interpreter."""
    def __init__(self, args):
        self.args = args

    def dispatch(self, operation, body, options):
        request_id = str(uuid.uuid4())
        request = {"protocol": bridge.PROTOCOL, "request_id": request_id, "operation": operation,
                   "input_bytes": len(body), "input_sha256": checksum(body), "options": options}
        args = self.args
        command = [sys.executable, str(Path(__file__).with_name("meeting-audio-native.py")),
            "--workspace", str(args.workspace), "--ffmpeg", str(args.ffmpeg),
            "--model-snapshot", str(args.model_snapshot), "--runtime-profile", str(args.runtime_profile),
            "--runtime-profile-sha256", args.runtime_profile_sha256]
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, start_new_session=True) as child:
            try:
                stdout, _ = child.communicate(bridge.encode_header(request) + body, timeout=7200)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    child.kill()
                child.communicate()
                raise bridge.Refusal("NativePortTimedOut") from None
            exit_code = child.returncode
        header, separator, raw = stdout.partition(b"\n")
        if not separator or len(header) > bridge.MAX_HEADER or len(raw) > bridge.MAX_PCM:
            raise bridge.Refusal("InvalidNativeFrame")
        reply = runtime.strict_json(header)
        if (reply.get("protocol") != bridge.PROTOCOL or reply.get("request_id") != request_id
                or reply.get("body_bytes") != len(raw) or operation != "decode" and raw):
            raise bridge.Refusal("InvalidNativeFrame")
        if exit_code != 0 or reply.get("ok") is not True:
            raise bridge.Refusal(reply.get("error", {}).get("code", "NativePortFailed"))
        return reply["result"], raw

    def capabilities(self):
        result, _ = self.dispatch("capabilities", b"", {})
        if (result.get("script_sha256") != checksum(Path(__file__).with_name("meeting-audio-native.py").read_bytes())
                or result.get("runtime_helper_sha256") != checksum(Path(__file__).with_name("meeting_audio_runtime.py").read_bytes())
                or result.get("runtime_profile_sha256") != self.args.runtime_profile_sha256):
            raise bridge.Refusal("CapabilityBindingMismatch")
        return result


def capture(args):
    source = read_bytes(args.cohort)
    cohort = runtime.strict_json(source)
    if (not isinstance(cohort, dict) or set(cohort) != {"schema", "corpus_id", "files"}
            or cohort["schema"] != "oneiron.audio.e3.cohort.v1" or not nonblank(cohort["corpus_id"])
            or not isinstance(cohort["files"], list) or not cohort["files"]):
        raise bridge.Refusal("InvalidCohort")
    write_new(args.output / "setup.json", {"phase": "setup", "cohort_sha256": checksum(source),
        "profile_sha256": args.runtime_profile_sha256, "harness_sha256": checksum(Path(__file__).read_bytes()),
        "bridge_sha256": checksum(Path(__file__).with_name("meeting-audio-native.py").read_bytes()),
        "runtime_helper_sha256": checksum(Path(__file__).with_name("meeting_audio_runtime.py").read_bytes()),
        "python_executable": sys.executable, "python_version": sys.version.split()[0],
        "e1_e3_qualified": False})
    workspace = bridge.configure_workspace(args.workspace)
    args.workspace = workspace
    host = ProcessPorts(args)
    capabilities = host.capabilities()
    # A comparison may be provisioned without artifact ASR/alignment/cleanup.
    for operation, _field, _stage in ARMS.values():
        if operation not in capabilities["operations"]:
            raise bridge.Refusal("E3BackendUnavailable")
    write_new(args.output / "capabilities.json", capabilities)
    native = runtime.LocalRuntime(args.runtime_profile, args.runtime_profile_sha256, error=bridge.Refusal)
    records, ids, invocations = [], set(), set()
    for entry in cohort["files"]:
        if (not isinstance(entry, dict) or set(entry) != {"file_id", "audio_path", "audio_sha256", "reference_path", "reference_sha256", "consent_ref"}
                or not nonblank(entry["file_id"]) or entry["file_id"] in ids or not nonblank(entry["consent_ref"])
                or not runtime.hash_string(entry["audio_sha256"]) or not runtime.hash_string(entry["reference_sha256"])
                or not isinstance(entry["audio_path"], str) or not isinstance(entry["reference_path"], str)):
            raise bridge.Refusal("InvalidCohortFile")
        ids.add(entry["file_id"])
        audio = read_bytes(args.cohort.parent / entry["audio_path"], bridge.MAX_INPUT)
        reference_bytes = read_bytes(args.cohort.parent / entry["reference_path"])
        if checksum(audio) != entry["audio_sha256"] or checksum(reference_bytes) != entry["reference_sha256"]:
            raise bridge.Refusal("CohortFileDigestMismatch")
        reference = checked_reference(runtime.strict_json(reference_bytes))
        decoded, pcm = host.dispatch("decode", audio, {})
        if checksum(pcm) != decoded["pcm_sha256"] or any(word["end_ms"] > (len(pcm) // 2 + 15) // 16 for word in reference["words"]):
            raise bridge.Refusal("ReferenceDurationMismatch")
        record = {"file_id": entry["file_id"], "audio_sha256": entry["audio_sha256"],
                  "reference_sha256": entry["reference_sha256"], "reference_json": reference_bytes.decode("utf-8"),
                  "consent_ref": entry["consent_ref"], "pcm_sha256": checksum(pcm), "arms": {}}
        for arm, (operation, field, stage) in ARMS.items():
            with (args.output / "events.jsonl").open("ab") as events:
                events.write(encoded({"event": "started", "file_id": entry["file_id"], "arm": arm}) + b"\n")
            started = time.monotonic()
            output, body = host.dispatch(operation, pcm, {})
            receipt = output["provenance"]
            if (body or receipt["input_sha256"] != checksum(pcm) or receipt["execution"] != "measured"
                    or receipt["model_id"] != native.profile[stage]["model_id"]
                    or not nonblank(receipt["invocation_id"]) or receipt["invocation_id"] in invocations):
                raise bridge.Refusal("InvalidNativeRunReceipt")
            invocations.add(receipt["invocation_id"])
            tracks = output[field]
            spec = native.profile[stage]
            record["arms"][arm] = {"tracks": tracks, "tracks_sha256": checksum(encoded(tracks)),
                "provenance": output["provenance"], "model_id": spec["model_id"],
                "model_files_sha256": checksum(encoded(spec["files"])), "runtime_sha256": checksum(encoded(capabilities)), "elapsed_seconds": time.monotonic() - started}
            with (args.output / "events.jsonl").open("ab") as events:
                events.write(encoded({"event": "completed", "file_id": entry["file_id"], "arm": arm,
                    "tracks_sha256": record["arms"][arm]["tracks_sha256"]}) + b"\n")
        path = checksum(entry["file_id"].encode()) + ".json"
        write_new(args.output / path, record)
        records.append({"path": path, "sha256": checksum(encoded(record))})
    result = {"phase": "capture_complete", "schema": "oneiron.audio.e3.capture.v1", "corpus_id": cohort["corpus_id"],
              "cohort_sha256": checksum(source), "capabilities_sha256": checksum(encoded(capabilities)),
              "records": records, "named_principal_scored": False,
              "e1_e3_qualified": False, "next": "supply output-bound enrollment-matching receipts; then score"}
    write_new(args.output / "completion.json", result)
    return result


def score(capture_dir, matches_path):
    completion = read_json(capture_dir / "completion.json")
    if completion.get("phase") != "capture_complete" or completion.get("schema") != "oneiron.audio.e3.capture.v1":
        raise bridge.Refusal("CaptureNotComplete")
    matches = read_json(matches_path)
    fields = {"schema", "enrollment_sha256", "enrollment_consent_ref", "matcher_model_sha256", "matcher_runtime_sha256", "matches"}
    if (not isinstance(matches, dict) or set(matches) != fields or matches["schema"] != "oneiron.audio.e3.enrollment_matches.v1"
            or not nonblank(matches["enrollment_consent_ref"])
            or any(not runtime.hash_string(matches[key]) for key in ["enrollment_sha256", "matcher_model_sha256", "matcher_runtime_sha256"])
            or not isinstance(matches["matches"], list)):
        raise bridge.Refusal("InvalidEnrollmentReceipts")
    indexed = {}
    for entry in matches["matches"]:
        if (not isinstance(entry, dict) or set(entry) != {"file_id", "arm", "audio_sha256", "tracks_sha256", "receipt_ref", "cluster_to_principal"}
                or not nonblank(entry["file_id"]) or entry["arm"] not in ARMS or not nonblank(entry["receipt_ref"])
                or not runtime.hash_string(entry["audio_sha256"]) or not runtime.hash_string(entry["tracks_sha256"])
                or not isinstance(entry["cluster_to_principal"], dict)
                or any(not nonblank(k) or not nonblank(v) for k, v in entry["cluster_to_principal"].items())):
            raise bridge.Refusal("InvalidEnrollmentReceipts")
        key = (entry["file_id"], entry["arm"])
        if key in indexed:
            raise bridge.Refusal("DuplicateEnrollmentReceipt")
        indexed[key] = entry
    scores, consumed = {}, set()
    if not isinstance(completion.get("records"), list) or not completion["records"]:
        raise bridge.Refusal("InvalidCaptureManifest")
    for row in completion["records"]:
        if not isinstance(row.get("path"), str) or Path(row["path"]).name != row["path"]:
            raise bridge.Refusal("InvalidCapturePath")
        data = read_bytes(capture_dir / row["path"])
        if checksum(data) != row["sha256"]:
            raise bridge.Refusal("CaptureDigestMismatch")
        record = runtime.strict_json(data)
        if record["file_id"] in scores or checksum(record["reference_json"].encode("utf-8")) != record["reference_sha256"]:
            raise bridge.Refusal("CaptureReferenceMismatch")
        reference = checked_reference(runtime.strict_json(record["reference_json"]))
        scores[record["file_id"]] = {}
        for arm in ARMS:
            captured = record["arms"][arm]
            key = (record["file_id"], arm)
            match = indexed.get(key)
            if (match is None or match["audio_sha256"] != record["audio_sha256"]
                    or match["tracks_sha256"] != captured["tracks_sha256"]
                    or checksum(encoded(captured["tracks"])) != captured["tracks_sha256"]):
                raise bridge.Refusal("EnrollmentOutputBindingMismatch")
            labels = {track["speaker_cluster"] for track in captured["tracks"] if track["speaker_cluster"] is not None}
            if not match["cluster_to_principal"].keys() <= labels:
                raise bridge.Refusal("UnknownEnrollmentCluster")
            scores[record["file_id"]][arm] = score_words(reference, captured["tracks"], match["cluster_to_principal"])
            consumed.add(key)
    if consumed != indexed.keys():
        raise bridge.Refusal("UnrelatedEnrollmentReceipt")
    return {"schema": "oneiron.audio.e3.named_score.v1", "phase": "scored", "scores": scores,
        "cohort_sha256": completion["cohort_sha256"], "matching_receipts_sha256": runtime.file_digest(matches_path),
        "evidence_kind": "captured_native_outputs_with_host_enrollment_receipts",
        "e1_e3_qualified": False, "boundary": "host-reported matching; human qualification required; no default change"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    run = sub.add_parser("capture")
    for name in ["workspace", "ffmpeg", "model-snapshot", "runtime-profile", "cohort", "output"]:
        run.add_argument("--" + name, required=True, type=Path)
    run.add_argument("--runtime-profile-sha256", required=True)
    evaluate = sub.add_parser("score")
    evaluate.add_argument("--capture", required=True, type=Path)
    evaluate.add_argument("--matches", required=True, type=Path)
    args = parser.parse_args()
    owned = False
    try:
        if args.mode == "capture":
            args.output.mkdir(exist_ok=False)
            owned = True
            with contextlib.redirect_stdout(sys.stderr):
                result = capture(args)
        else:
            result = score(args.capture, args.matches)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except Exception as error:
        code = getattr(error, "code", type(error).__name__)
        failure = {"phase": "failed", "error": code, "e1_e3_qualified": False}
        if owned and not (args.output / "completion.json").exists():
            write_new(args.output / "completion.json", failure)
        print(json.dumps(failure))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
