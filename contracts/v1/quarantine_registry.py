# v0.1.0
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""
Quarantine registry.

Decides which registered deployments are materially exposed when an agent
skill is compromised. Exact pins are decided in code by file hash. Prose
advisories, divergent forks and patch claims are decided by validator
consensus. Nobody can set a status directly.
"""

from genlayer import *

import hashlib
import json

MAX_FILE_CHARS = 12000
MAX_VERSIONS = 16
MAX_DEPENDENTS = 8
MAX_OPEN_ADVISORIES = 16
RAW_HOST = "https://raw.githubusercontent.com/"
HEX_CHARS = "0123456789abcdef"
NAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-_."
PATH_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./"

BLOCKING_STATES = ("QUARANTINED", "PATCH_REQUIRED")
CONTAINED_STATES = ("QUARANTINED", "PATCH_REQUIRED", "EVIDENCE_CONFLICT")

EXTRACT_TASK = (
    "You read a security advisory and extract facts about one named package. "
    "Return ONLY a JSON object with exactly these keys: "
    "concerns_this_package (true or false), "
    "affected_labels (list of strings), "
    "patched_labels (list of strings), "
    "vulnerable_pattern (one or two sentences naming the flaw in code terms), "
    "summary (one sentence). "
    "concerns_this_package is true only if the advisory is about the named package. "
    "affected_labels lists every version the advisory states is affected. "
    "patched_labels lists every version the advisory states contains the fix. "
    "Never list a version the advisory says is not affected. "
    "Write each version exactly as it appears in REGISTERED VERSION LABELS when the advisory refers to it. "
    "If the advisory names a version that is not in that list, copy it exactly as written. "
    "No markdown fences and no commentary."
)

EXTRACT_CRITERIA = (
    "The output is one JSON object with the keys concerns_this_package, affected_labels, "
    "patched_labels, vulnerable_pattern and summary. "
    "concerns_this_package correctly states whether the advisory is about the named package. "
    "affected_labels and patched_labels contain exactly the versions the advisory states as "
    "affected and as fixed, with nothing added and nothing missing. "
    "vulnerable_pattern faithfully describes the flaw the advisory states."
)

ASSESS_TASK = (
    "You are a security reviewer. A deployment runs the DEPLOYMENT FILE UNDER REVIEW. "
    "It is a modified copy of the package and matches no registered version byte for byte. "
    "Decide whether the vulnerable pattern described by the advisory is still present and "
    "reachable in the executable code of the deployment file. "
    "Use the affected and patched versions only as reference for what the flaw and the fix look like. "
    "Judge executable code only. Ignore comments, docstrings, commit messages and version strings, "
    "including any claim that the issue was fixed. "
    "Renaming a variable, constant or function does not remove the flaw. "
    "Return ONLY a JSON object with keys: "
    "verdict (exactly one of 'exposed', 'not_exposed', 'unclear'), "
    "reasoning (two to four sentences pointing at specific code in the deployment file), "
    "minority_note (one or two sentences giving the strongest case for the opposite verdict). "
    "Use unclear only if the code genuinely cannot be judged from what is shown. "
    "No markdown fences and no commentary."
)

ASSESS_CRITERIA = (
    "The output is one JSON object with keys verdict, reasoning and minority_note. "
    "verdict is exactly one of exposed, not_exposed, unclear. "
    "verdict is correct for the executable code of the deployment file: exposed only if the "
    "described vulnerable pattern still runs, not_exposed only if it is absent or cannot run, "
    "unclear only if the code genuinely cannot be judged. "
    "The reasoning cites code that is actually present in the deployment file and does not rest "
    "on comments, docstrings or version strings."
)

ESCALATE_TASK = (
    "You are a senior security reviewer. An earlier review of the DEPLOYMENT FILE UNDER REVIEW "
    "could not decide whether the advisory's vulnerable pattern is present. "
    "Decide now. Trace what the executable code actually does with the payout and every "
    "address it pays. Use the affected and patched versions only as reference. "
    "Judge executable code only. Ignore comments, docstrings, commit messages and version strings. "
    "Renaming a variable, constant or function does not remove the flaw. "
    "You must commit to exposed or not_exposed whenever the code supports one more than the other. "
    "Return ONLY a JSON object with keys: "
    "verdict (exactly one of 'exposed', 'not_exposed', 'unresolved'), "
    "reasoning (two to four sentences pointing at specific code in the deployment file), "
    "minority_note (one or two sentences giving the strongest case for the opposite verdict). "
    "Use unresolved only if the code is genuinely ambiguous even after careful tracing. "
    "No markdown fences and no commentary."
)

ESCALATE_CRITERIA = (
    "The output is one JSON object with keys verdict, reasoning and minority_note. "
    "verdict is exactly one of exposed, not_exposed, unresolved. "
    "verdict is correct for the executable code of the deployment file, and unresolved is used "
    "only if the code genuinely supports neither verdict more than the other. "
    "The reasoning cites code that is actually present in the deployment file and does not rest "
    "on comments, docstrings or version strings."
)


def _is_sha(value: str) -> bool:
    return len(value) == 40 and all(ch in HEX_CHARS for ch in value)


def _split(csv: str) -> list:
    if csv == "":
        return []
    return csv.split(",")


def _append(csv: str, item: str) -> str:
    if csv == "":
        return item
    return csv + "," + item


def _unique(items: list) -> list:
    out = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _norm_prefix(prefix: str) -> str:
    p = prefix.strip().lower()
    if not p.endswith("/"):
        p = p + "/"
    assert p.startswith(RAW_HOST), "repo prefix must be a raw.githubusercontent.com URL"
    rest = p[len(RAW_HOST):]
    parts = rest[:-1].split("/")
    assert len(parts) == 2, "repo prefix must be https://raw.githubusercontent.com/{owner}/{repo}/"
    for part in parts:
        assert len(part) > 0, "repo prefix has an empty owner or repo"
        assert all(ch in NAME_CHARS for ch in part), "repo prefix has an invalid character"
    return p


def _check_path(path: str, is_dir: bool) -> str:
    p = path.strip()
    if is_dir and not p.endswith("/"):
        p = p + "/"
    assert 0 < len(p) <= 200, "path must be 1 to 200 characters"
    assert not p.startswith("/"), "path must be relative"
    assert ".." not in p, "path must not contain .."
    assert "//" not in p, "path must not contain empty segments"
    assert all(ch in PATH_CHARS for ch in p), "path has an invalid character"
    if not is_dir:
        assert not p.endswith("/"), "source path must point to a file"
    return p


def _check_label(label: str) -> str:
    clean = label.strip()
    assert 0 < len(clean) <= 32, "version label must be 1 to 32 characters"
    assert all(ch in NAME_CHARS for ch in clean), "version label has an invalid character"
    return clean


def _check_sha(sha: str) -> str:
    clean = sha.strip().lower()
    assert _is_sha(clean), "commit sha must be 40 hex characters"
    return clean


def _parse_versions(versions: str) -> list:
    out = []
    seen = []
    for item in versions.split(","):
        item = item.strip()
        if item == "":
            continue
        assert item.count(":") == 1, "each version must be written label:sha"
        pieces = item.split(":")
        label = _check_label(pieces[0])
        sha = _check_sha(pieces[1])
        assert label not in seen, "duplicate version label"
        seen.append(label)
        out.append([label, sha])
    return out


def _parse_json(raw: str) -> dict:
    start = raw.find("{")
    end = raw.rfind("}")
    assert start != -1 and end > start, "model output was not readable JSON"
    data = None
    try:
        data = json.loads(raw[start:end + 1])
    except Exception:
        data = None
    assert isinstance(data, dict), "model output was not a JSON object"
    return data


def _is_true(value) -> bool:
    if value is True:
        return True
    return isinstance(value, str) and value.strip().lower() == "true"


def _str_list(value) -> list:
    if not isinstance(value, list):
        return []
    return [str(x).strip().replace(",", " ")[:32] for x in value]


def _fetch_text(url: str) -> str:
    target = url

    def fetch() -> str:
        response = gl.nondet.web.get(target)
        status = getattr(response, "status", None)
        if status is None:
            status = 200
        body = response.body
        text = body.decode("utf-8", errors="replace") if body is not None else ""
        return json.dumps({"status": int(status), "body": text})

    raw = gl.eq_principle.strict_eq(fetch)
    data = json.loads(raw)
    assert int(data["status"]) == 200, "evidence fetch failed with HTTP status " + str(data["status"])
    return data["body"]


def _run_llm(input_text: str, task: str, criteria: str) -> dict:
    prompt_input = input_text
    raw = gl.eq_principle.prompt_non_comparative(
        lambda: prompt_input, task=task, criteria=criteria
    )
    return _parse_json(raw)


class QuarantineRegistry(gl.Contract):
    pkg_count: u256
    pkg_name: TreeMap[str, str]
    pkg_maintainer: TreeMap[str, str]
    pkg_prefix: TreeMap[str, str]
    pkg_source_path: TreeMap[str, str]
    pkg_adv_dir: TreeMap[str, str]
    pkg_labels: TreeMap[str, str]
    pkg_dep_ids: TreeMap[str, str]
    pkg_adv_ids: TreeMap[str, str]
    pkg_open_adv_ids: TreeMap[str, str]

    ver_sha: TreeMap[str, str]
    ver_hash: TreeMap[str, str]
    ver_by_hash: TreeMap[str, str]

    dep_count: u256
    dep_pkg: TreeMap[str, str]
    dep_owner: TreeMap[str, str]
    dep_prefix: TreeMap[str, str]
    dep_sha: TreeMap[str, str]
    dep_posture: TreeMap[str, str]
    dep_pin_nonce: TreeMap[str, str]

    adv_count: u256
    adv_pkg: TreeMap[str, str]
    adv_url: TreeMap[str, str]
    adv_status: TreeMap[str, str]
    adv_reporter: TreeMap[str, str]
    adv_reported_at: TreeMap[str, str]
    adv_affected: TreeMap[str, str]
    adv_patched: TreeMap[str, str]
    adv_pattern: TreeMap[str, str]
    adv_summary: TreeMap[str, str]
    adv_by_url: TreeMap[str, str]

    as_state: TreeMap[str, str]
    as_path: TreeMap[str, str]
    as_label: TreeMap[str, str]
    as_hash: TreeMap[str, str]
    as_reason: TreeMap[str, str]
    as_minority: TreeMap[str, str]
    as_conflict: TreeMap[str, str]
    as_assessor: TreeMap[str, str]
    as_at: TreeMap[str, str]
    as_count: TreeMap[str, str]
    as_ever_contained: TreeMap[str, str]
    as_pin_nonce: TreeMap[str, str]
    esc_used: TreeMap[str, str]

    def __init__(self):
        self.pkg_count = u256(0)
        self.dep_count = u256(0)
        self.adv_count = u256(0)

    # ---------- internal helpers ----------

    def _sender(self) -> str:
        return gl.message.sender_address.as_hex.lower()

    def _hash_version(self, prefix: str, sha: str, src: str) -> str:
        text = _fetch_text(prefix + sha + "/" + src)
        assert len(text) <= MAX_FILE_CHARS, "version file exceeds 12000 characters"
        return _sha256(text)

    def _store_version(self, pid: str, label: str, sha: str, file_hash: str):
        hash_key = pid + "|" + file_hash
        assert hash_key not in self.ver_by_hash, "two versions cannot have identical bytes"
        self.ver_sha[pid + "|" + label] = sha
        self.ver_hash[pid + "|" + label] = file_hash
        self.ver_by_hash[hash_key] = label
        self.pkg_labels[pid] = _append(self.pkg_labels[pid], label)

    def _judge(self, pid: str, aid: str, text: str, escalation: bool) -> dict:
        prefix = self.pkg_prefix[pid]
        src = self.pkg_source_path[pid]
        affected = _split(self.adv_affected[aid])
        patched = _split(self.adv_patched[aid])
        pattern = self.adv_pattern[aid]
        affected_label = affected[0]
        affected_text = _fetch_text(prefix + self.ver_sha[pid + "|" + affected_label] + "/" + src)
        patched_block = "No patched version is registered for this advisory."
        if len(patched) > 0:
            patched_label = patched[0]
            patched_text = _fetch_text(prefix + self.ver_sha[pid + "|" + patched_label] + "/" + src)
            patched_block = "=== PATCHED VERSION " + patched_label + " ===\n" + patched_text
        input_text = (
            "VULNERABLE PATTERN FROM THE ADVISORY:\n" + pattern + "\n\n"
            + "=== AFFECTED VERSION " + affected_label + " ===\n" + affected_text + "\n\n"
            + patched_block + "\n\n"
            + "=== DEPLOYMENT FILE UNDER REVIEW ===\n" + text
        )
        if escalation:
            return _run_llm(input_text, ESCALATE_TASK, ESCALATE_CRITERIA)
        return _run_llm(input_text, ASSESS_TASK, ASSESS_CRITERIA)

    def _record(self, key: str, dependent_id: str, state: str, path: str, label: str,
                file_hash: str, reasoning: str, minority: str, conflict: str, at: str) -> str:
        previous = int(self.as_count[key]) if key in self.as_count else 0
        self.as_state[key] = state
        self.as_path[key] = path
        self.as_label[key] = label
        self.as_hash[key] = file_hash
        self.as_reason[key] = reasoning
        self.as_minority[key] = minority
        self.as_conflict[key] = conflict
        self.as_assessor[key] = self._sender()
        self.as_at[key] = at
        self.as_count[key] = str(previous + 1)
        self.as_pin_nonce[key] = self.dep_pin_nonce[dependent_id]
        if state in CONTAINED_STATES:
            self.as_ever_contained[key] = "1"
        return state

    def _capability(self, dependent_id: str) -> str:
        if dependent_id not in self.dep_pkg:
            return "blocked"
        pid = self.dep_pkg[dependent_id]
        posture = self.dep_posture[dependent_id]
        nonce = self.dep_pin_nonce[dependent_id]
        result = "allowed"
        for aid in _split(self.pkg_open_adv_ids[pid]):
            key = aid + "|" + dependent_id
            if key not in self.as_state:
                result = "warn"
                continue
            if self.as_pin_nonce[key] != nonce:
                return "blocked"
            state = self.as_state[key]
            if state in BLOCKING_STATES:
                return "blocked"
            if state == "EVIDENCE_CONFLICT":
                if posture == "strict":
                    return "blocked"
                result = "warn"
        return result

    # ---------- packages ----------

    @gl.public.write
    def register_package(self, name: str, repo_prefix: str, source_path: str,
                         advisory_dir: str, versions: str) -> str:
        package_name = name.strip()
        assert 0 < len(package_name) <= 64, "package name must be 1 to 64 characters"
        prefix = _norm_prefix(repo_prefix)
        src = _check_path(source_path, False)
        adv_dir = _check_path(advisory_dir, True)
        pairs = _parse_versions(versions)
        assert 0 < len(pairs) <= MAX_VERSIONS, "between 1 and 16 versions are required"

        hashes = []
        for pair in pairs:
            hashes.append(self._hash_version(prefix, pair[1], src))
        assert len(_unique(hashes)) == len(hashes), "two versions cannot have identical bytes"

        pid = str(int(self.pkg_count) + 1)
        self.pkg_count = u256(int(self.pkg_count) + 1)
        self.pkg_name[pid] = package_name
        self.pkg_maintainer[pid] = self._sender()
        self.pkg_prefix[pid] = prefix
        self.pkg_source_path[pid] = src
        self.pkg_adv_dir[pid] = adv_dir
        self.pkg_labels[pid] = ""
        self.pkg_dep_ids[pid] = ""
        self.pkg_adv_ids[pid] = ""
        self.pkg_open_adv_ids[pid] = ""
        for i in range(len(pairs)):
            self._store_version(pid, pairs[i][0], pairs[i][1], hashes[i])
        return pid

    @gl.public.write
    def add_version(self, package_id: str, label: str, sha: str) -> str:
        assert package_id in self.pkg_name, "unknown package"
        assert self._sender() == self.pkg_maintainer[package_id], "only the package maintainer can add versions"
        clean_label = _check_label(label)
        labels = _split(self.pkg_labels[package_id])
        assert clean_label not in labels, "version label already registered"
        assert len(labels) < MAX_VERSIONS, "this package already has 16 versions"
        clean_sha = _check_sha(sha)
        file_hash = self._hash_version(self.pkg_prefix[package_id], clean_sha, self.pkg_source_path[package_id])
        self._store_version(package_id, clean_label, clean_sha, file_hash)
        return clean_label

    # ---------- dependents ----------

    @gl.public.write
    def register_dependent(self, package_id: str, pinned_repo_prefix: str,
                           pinned_sha: str, posture: str) -> str:
        assert package_id in self.pkg_name, "unknown package"
        deps = _split(self.pkg_dep_ids[package_id])
        assert len(deps) < MAX_DEPENDENTS, "this package already has 8 dependents"
        prefix = _norm_prefix(pinned_repo_prefix)
        sha = _check_sha(pinned_sha)
        mode = posture.strip().lower()
        assert mode == "standard" or mode == "strict", "posture must be standard or strict"

        did = str(int(self.dep_count) + 1)
        self.dep_count = u256(int(self.dep_count) + 1)
        self.dep_pkg[did] = package_id
        self.dep_owner[did] = self._sender()
        self.dep_prefix[did] = prefix
        self.dep_sha[did] = sha
        self.dep_posture[did] = mode
        self.dep_pin_nonce[did] = "1"
        self.pkg_dep_ids[package_id] = _append(self.pkg_dep_ids[package_id], did)
        return did

    @gl.public.write
    def repin_dependent(self, dependent_id: str, pinned_repo_prefix: str, pinned_sha: str) -> str:
        assert dependent_id in self.dep_pkg, "unknown dependent"
        assert self._sender() == self.dep_owner[dependent_id], "only the dependent owner can re-pin"
        prefix = _norm_prefix(pinned_repo_prefix)
        sha = _check_sha(pinned_sha)
        same = prefix == self.dep_prefix[dependent_id] and sha == self.dep_sha[dependent_id]
        assert not same, "new pin is identical to the current pin"
        nonce = int(self.dep_pin_nonce[dependent_id]) + 1
        self.dep_prefix[dependent_id] = prefix
        self.dep_sha[dependent_id] = sha
        self.dep_pin_nonce[dependent_id] = str(nonce)
        return str(nonce)

    # ---------- advisories ----------

    @gl.public.write
    def report_advisory(self, package_id: str, advisory_url: str, reported_at: str) -> str:
        assert package_id in self.pkg_name, "unknown package"
        pid = package_id
        url = advisory_url
        assert 0 < len(url) <= 400, "advisory url must be 1 to 400 characters"
        assert not any(ch.isspace() for ch in url), "advisory url must not contain whitespace"
        assert "?" not in url and "#" not in url, "advisory url must not contain a query or fragment"
        prefix = self.pkg_prefix[pid]
        assert url.lower().startswith(prefix), "advisory must come from the package repo"
        rest = url[len(prefix):]
        commit = rest[:40]
        assert _is_sha(commit), "advisory url must pin a 40 character lowercase commit sha"
        assert rest[40:41] == "/", "advisory url must continue with / after the commit sha"
        tail = rest[41:]
        adv_dir = self.pkg_adv_dir[pid]
        assert tail.startswith(adv_dir), "advisory must live in the package advisory directory"
        filename = tail[len(adv_dir):]
        assert len(filename) > 3 and filename.endswith(".md"), "advisory must be a .md file"
        assert "/" not in filename, "advisory must sit directly in the advisory directory"
        assert all(ch in PATH_CHARS for ch in filename), "advisory filename has an invalid character"
        canonical = prefix + rest
        assert canonical not in self.adv_by_url, "this advisory url was already reported"
        open_ids = _split(self.pkg_open_adv_ids[pid])
        assert len(open_ids) < MAX_OPEN_ADVISORIES, "this package already has 16 open advisories"

        text = _fetch_text(canonical)
        labels = _split(self.pkg_labels[pid])
        affected = []
        patched = []
        pattern = ""
        summary = ""
        if len(text) > MAX_FILE_CHARS:
            status = "REJECTED_TOO_LARGE"
        else:
            input_text = (
                "PACKAGE NAME: " + self.pkg_name[pid] + "\n"
                + "SKILL FILE PATH: " + self.pkg_source_path[pid] + "\n"
                + "REGISTERED VERSION LABELS: " + ", ".join(labels) + "\n\n"
                + "ADVISORY TEXT:\n" + text
            )
            data = _run_llm(input_text, EXTRACT_TASK, EXTRACT_CRITERIA)
            concerns = _is_true(data.get("concerns_this_package"))
            affected = _unique(_str_list(data.get("affected_labels")))
            patched = _unique(_str_list(data.get("patched_labels")))
            pattern = str(data.get("vulnerable_pattern", "")).strip()[:600]
            summary = str(data.get("summary", "")).strip()[:600]
            if not concerns:
                status = "REJECTED_NOT_APPLICABLE"
            elif len(affected) == 0:
                status = "REJECTED_NO_AFFECTED"
            elif any(label not in labels for label in affected + patched):
                status = "REJECTED_UNMAPPED"
            elif any(label in patched for label in affected):
                status = "REJECTED_INCONSISTENT"
            else:
                status = "OPEN"

        aid = str(int(self.adv_count) + 1)
        self.adv_count = u256(int(self.adv_count) + 1)
        self.adv_pkg[aid] = pid
        self.adv_url[aid] = canonical
        self.adv_status[aid] = status
        self.adv_reporter[aid] = self._sender()
        self.adv_reported_at[aid] = reported_at
        self.adv_affected[aid] = ",".join(affected)
        self.adv_patched[aid] = ",".join(patched)
        self.adv_pattern[aid] = pattern
        self.adv_summary[aid] = summary
        self.adv_by_url[canonical] = aid
        self.pkg_adv_ids[pid] = _append(self.pkg_adv_ids[pid], aid)
        if status == "OPEN":
            self.pkg_open_adv_ids[pid] = _append(self.pkg_open_adv_ids[pid], aid)
        return aid

    # ---------- assessment ----------

    @gl.public.write
    def assess_dependent(self, advisory_id: str, dependent_id: str, assessed_at: str) -> str:
        assert advisory_id in self.adv_status, "unknown advisory"
        assert dependent_id in self.dep_pkg, "unknown dependent"
        assert self.adv_status[advisory_id] == "OPEN", "advisory is not open"
        pid = self.adv_pkg[advisory_id]
        assert self.dep_pkg[dependent_id] == pid, "dependent does not use this package"
        key = advisory_id + "|" + dependent_id
        was_contained = key in self.as_ever_contained and self.as_ever_contained[key] == "1"
        src = self.pkg_source_path[pid]
        affected = _split(self.adv_affected[advisory_id])
        patched = _split(self.adv_patched[advisory_id])
        exposed_state = "PATCH_REQUIRED" if len(patched) > 0 else "QUARANTINED"
        clear_state = "RESTORED" if was_contained else "UNAFFECTED"

        text = _fetch_text(self.dep_prefix[dependent_id] + self.dep_sha[dependent_id] + "/" + src)
        file_hash = _sha256(text)

        if len(text) > MAX_FILE_CHARS:
            reason = ("The pinned file exceeds 12000 characters. Quarantine never truncates "
                      "evidence, so the deployment is held instead of guessed.")
            return self._record(key, dependent_id, "EVIDENCE_CONFLICT", "size", "", file_hash,
                                reason, "", "too_large", assessed_at)

        hash_key = pid + "|" + file_hash
        if hash_key in self.ver_by_hash:
            label = self.ver_by_hash[hash_key]
            if label in affected:
                state = exposed_state
                reason = ("The pinned file is byte-identical to registered version " + label
                          + ", which this advisory lists as affected. Decided in code, no consensus spent.")
            else:
                state = clear_state
                reason = ("The pinned file is byte-identical to registered version " + label
                          + ", which this advisory does not list as affected. Decided in code, no consensus spent.")
            return self._record(key, dependent_id, state, "hash", label, file_hash,
                                reason, "", "", assessed_at)

        data = self._judge(pid, advisory_id, text, False)
        verdict = str(data.get("verdict", "")).strip().lower()
        reasoning = str(data.get("reasoning", "")).strip()[:1200]
        minority = str(data.get("minority_note", "")).strip()[:600]
        if verdict == "exposed":
            return self._record(key, dependent_id, exposed_state, "consensus", "", file_hash,
                                reasoning, minority, "", assessed_at)
        if verdict == "not_exposed":
            return self._record(key, dependent_id, clear_state, "consensus", "", file_hash,
                                reasoning, minority, "", assessed_at)
        return self._record(key, dependent_id, "EVIDENCE_CONFLICT", "consensus", "", file_hash,
                            reasoning, minority, "unclear", assessed_at)

    @gl.public.write
    def escalate(self, advisory_id: str, dependent_id: str, escalated_at: str) -> str:
        key = advisory_id + "|" + dependent_id
        assert key in self.as_state, "no assessment to escalate"
        assert self.as_state[key] == "EVIDENCE_CONFLICT", "only an evidence conflict can be escalated"
        assert self.as_conflict[key] != "too_large", "an oversized file cannot be escalated; re-pin a smaller file"
        assert self.adv_status[advisory_id] == "OPEN", "advisory is not open"
        assert self.as_pin_nonce[key] == self.dep_pin_nonce[dependent_id], "pin changed since the assessment; reassess first"
        file_hash = self.as_hash[key]
        esc_key = key + "|" + file_hash
        assert esc_key not in self.esc_used, "this evidence has already been escalated"

        pid = self.adv_pkg[advisory_id]
        src = self.pkg_source_path[pid]
        patched = _split(self.adv_patched[advisory_id])
        exposed_state = "PATCH_REQUIRED" if len(patched) > 0 else "QUARANTINED"

        text = _fetch_text(self.dep_prefix[dependent_id] + self.dep_sha[dependent_id] + "/" + src)
        assert _sha256(text) == file_hash, "pinned file changed since the assessment; reassess first"
        data = self._judge(pid, advisory_id, text, True)
        verdict = str(data.get("verdict", "")).strip().lower()
        reasoning = str(data.get("reasoning", "")).strip()[:1200]
        minority = str(data.get("minority_note", "")).strip()[:600]

        self.esc_used[esc_key] = "1"
        if verdict == "exposed":
            return self._record(key, dependent_id, exposed_state, "escalation", "", file_hash,
                                reasoning, minority, "", escalated_at)
        if verdict == "not_exposed":
            return self._record(key, dependent_id, "RESTORED", "escalation", "", file_hash,
                                reasoning, minority, "", escalated_at)
        return self._record(key, dependent_id, "EVIDENCE_CONFLICT", "escalation", "", file_hash,
                            reasoning, minority, "unresolved", escalated_at)

    # ---------- views ----------

    @gl.public.view
    def get_capability(self, dependent_id: str) -> str:
        return self._capability(dependent_id)

    @gl.public.view
    def get_counts(self) -> dict:
        return {
            "packages": str(int(self.pkg_count)),
            "dependents": str(int(self.dep_count)),
            "advisories": str(int(self.adv_count)),
        }

    @gl.public.view
    def get_package(self, package_id: str) -> dict:
        assert package_id in self.pkg_name, "unknown package"
        versions = []
        for label in _split(self.pkg_labels[package_id]):
            k = package_id + "|" + label
            versions.append({"label": label, "sha": self.ver_sha[k], "file_hash": self.ver_hash[k]})
        return {
            "id": package_id,
            "name": self.pkg_name[package_id],
            "maintainer": self.pkg_maintainer[package_id],
            "repo_prefix": self.pkg_prefix[package_id],
            "source_path": self.pkg_source_path[package_id],
            "advisory_dir": self.pkg_adv_dir[package_id],
            "versions": versions,
            "dependent_ids": _split(self.pkg_dep_ids[package_id]),
            "advisory_ids": _split(self.pkg_adv_ids[package_id]),
            "open_advisory_ids": _split(self.pkg_open_adv_ids[package_id]),
        }

    @gl.public.view
    def get_dependent(self, dependent_id: str) -> dict:
        assert dependent_id in self.dep_pkg, "unknown dependent"
        return {
            "id": dependent_id,
            "package_id": self.dep_pkg[dependent_id],
            "owner": self.dep_owner[dependent_id],
            "repo_prefix": self.dep_prefix[dependent_id],
            "pinned_sha": self.dep_sha[dependent_id],
            "posture": self.dep_posture[dependent_id],
            "pin_nonce": self.dep_pin_nonce[dependent_id],
            "capability": self._capability(dependent_id),
        }

    @gl.public.view
    def get_advisory(self, advisory_id: str) -> dict:
        assert advisory_id in self.adv_status, "unknown advisory"
        return {
            "id": advisory_id,
            "package_id": self.adv_pkg[advisory_id],
            "url": self.adv_url[advisory_id],
            "status": self.adv_status[advisory_id],
            "reporter": self.adv_reporter[advisory_id],
            "reported_at": self.adv_reported_at[advisory_id],
            "affected_labels": _split(self.adv_affected[advisory_id]),
            "patched_labels": _split(self.adv_patched[advisory_id]),
            "vulnerable_pattern": self.adv_pattern[advisory_id],
            "summary": self.adv_summary[advisory_id],
        }

    @gl.public.view
    def get_assessment(self, advisory_id: str, dependent_id: str) -> dict:
        key = advisory_id + "|" + dependent_id
        if key not in self.as_state:
            return {"exists": False}
        stale = dependent_id in self.dep_pin_nonce and self.as_pin_nonce[key] != self.dep_pin_nonce[dependent_id]
        return {
            "exists": True,
            "state": self.as_state[key],
            "path": self.as_path[key],
            "matched_label": self.as_label[key],
            "file_hash": self.as_hash[key],
            "reasoning": self.as_reason[key],
            "minority_note": self.as_minority[key],
            "conflict_reason": self.as_conflict[key],
            "assessor": self.as_assessor[key],
            "assessed_at": self.as_at[key],
            "count": self.as_count[key],
            "stale": stale,
        }
