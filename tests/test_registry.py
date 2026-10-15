"""
Quarantine registry tests, real contract code on the gltest direct runner.

Each test names the trust property it proves. See TESTING.md for the map.
"""

import ast

import pytest

from qhelp import (
    REGISTRY, PKG, FORK, SRC, T, ADV_URL, ADV_BIG_URL,
    SHA_10, SHA_11, SHA_12, SHA_ADV, SHA_FORK_UNFIXED, SHA_FORK_FIXED, SHA_SPARE,
    V10, V11, V12,
    MAINTAINER, OWNER_A, OWNER_B, BYSTANDER, DEPLOYER,
    hx, sha, set_sender, new_vm, deploy_registry, serve, file_url, tag_url, serve_all,
    llm, verdict, extract, register_package, open_advisory, add_dependent,
    assess, escalate, repin,
)


def _boot(sender=MAINTAINER):
    vm = new_vm(sender)
    c = deploy_registry(vm)
    serve_all(vm)
    return vm, c


# ---------- registration ----------

def test_register_package_locks_sources_and_version_hashes():
    vm, c = _boot()
    with vm.activate():
        assert register_package(c) == "1"
        p = c.get_package("1")
        assert p["maintainer"] == hx(MAINTAINER)
        assert p["repo_prefix"] == PKG
        assert p["source_path"] == SRC
        assert p["advisory_dir"] == "security/"
        assert [v["label"] for v in p["versions"]] == ["1.0", "1.1", "1.2"]
        assert [v["sha"] for v in p["versions"]] == [SHA_10, SHA_11, SHA_12]
        assert [v["file_hash"] for v in p["versions"]] == [sha(V10), sha(V11), sha(V12)]


def test_two_versions_with_identical_bytes_are_rejected():
    vm = new_vm()
    c = deploy_registry(vm)
    serve(vm, file_url(PKG, SHA_10), V10)
    serve(vm, file_url(PKG, SHA_11), V10)
    serve(vm, tag_url(PKG, "1.0"), V10)
    serve(vm, tag_url(PKG, "1.1"), V10)
    with vm.activate():
        with pytest.raises(AssertionError):
            c.register_package("payout_skill", PKG, SRC, "security",
                               "1.0:" + SHA_10 + ",1.1:" + SHA_11, "", "")


def test_only_the_maintainer_can_add_a_version():
    vm, c = _boot()
    serve(vm, file_url(PKG, SHA_SPARE), "def extra():\n    return 1\n")
    serve(vm, tag_url(PKG, "1.3"), "def extra():\n    return 1\n")
    with vm.activate():
        register_package(c)
        set_sender(vm, BYSTANDER)
        with pytest.raises(AssertionError):
            c.add_version("1", "1.3", SHA_SPARE)
        set_sender(vm, MAINTAINER)
        assert c.add_version("1", "1.3", SHA_SPARE) == "1.3"
        assert c.get_package("1")["versions"][-1]["label"] == "1.3"


def test_only_the_owner_can_repin_a_dependent():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        set_sender(vm, BYSTANDER)
        with pytest.raises(AssertionError):
            c.repin_dependent(did, PKG, SHA_12)
        assert c.get_dependent(did)["pinned_sha"] == SHA_11


# ---------- advisory intake ----------

def test_advisory_outside_the_locked_repo_is_rejected():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        with pytest.raises(AssertionError):
            c.report_advisory("1", FORK + SHA_ADV + "/security/ADV-001.md", T)


@pytest.mark.parametrize("bad_url", [
    ADV_URL + " extra",
    ADV_URL + ".bak",
    ADV_URL + "?raw=1",
    ADV_URL + "#top",
    PKG + SHA_ADV[:39] + "/security/ADV-001.md",
    PKG + SHA_ADV.upper() + "/security/ADV-001.md",
    PKG + SHA_ADV + "/docs/ADV-001.md",
    PKG + SHA_ADV + "/security/nested/ADV-001.md",
])
def test_malformed_advisory_url_is_rejected_before_any_consensus(bad_url):
    vm, c = _boot()
    calls = []
    with vm.activate():
        register_package(c)
        vm._gl_call_hook = llm(extract(), calls)
        with pytest.raises(AssertionError):
            c.report_advisory("1", bad_url, T)
        assert calls == []


def test_replaying_the_same_advisory_url_reverts():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        assert open_advisory(vm, c) == "1"
        vm._gl_call_hook = llm(extract())
        with pytest.raises(AssertionError):
            c.report_advisory("1", ADV_URL, T)


def test_advisory_naming_unknown_versions_is_rejected_unmapped():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        aid = open_advisory(vm, c, extract(affected_labels=["1.1", "1.9"]))
        assert c.get_advisory(aid)["status"] == "REJECTED_UNMAPPED"
        assert c.get_package("1")["open_advisory_ids"] == []
        assert c.get_capability(did) == "allowed"


def test_advisory_about_another_package_is_rejected_not_applicable():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        aid = open_advisory(vm, c, extract(concerns_this_package=False))
        assert c.get_advisory(aid)["status"] == "REJECTED_NOT_APPLICABLE"
        assert c.get_package("1")["open_advisory_ids"] == []


def test_oversized_advisory_is_rejected_without_consensus():
    vm, c = _boot()
    serve(vm, ADV_BIG_URL, "x" * 12001)
    calls = []
    with vm.activate():
        register_package(c)
        vm._gl_call_hook = llm(extract(), calls)
        aid = c.report_advisory("1", ADV_BIG_URL, T)
        assert c.get_advisory(aid)["status"] == "REJECTED_TOO_LARGE"
        assert calls == []


def test_fenced_json_opens_and_string_false_is_not_truthy():
    vm, c = _boot()
    serve(vm, PKG + SHA_ADV + "/security/ADV-002.md", "second advisory text\n")
    import json
    with vm.activate():
        register_package(c)
        fenced_ok = "```json\n" + json.dumps(extract()) + "\n```"
        aid = open_advisory(vm, c, fenced_ok)
        assert c.get_advisory(aid)["status"] == "OPEN"
        fenced_false = "```json\n" + json.dumps(extract(concerns_this_package="false")) + "\n```"
        aid2 = open_advisory(vm, c, fenced_false, PKG + SHA_ADV + "/security/ADV-002.md")
        assert c.get_advisory(aid2)["status"] == "REJECTED_NOT_APPLICABLE"


def test_unreadable_model_output_reverts():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        vm._gl_call_hook = llm("I could not read the advisory.")
        with pytest.raises(AssertionError):
            c.report_advisory("1", ADV_URL, T)


# ---------- hash path: decided in code, no consensus spent ----------

def test_registered_affected_pin_is_patch_required_and_llm_is_never_called():
    vm, c = _boot()
    calls = []
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        aid = open_advisory(vm, c)
        assert c.get_capability(did) == "warn"
        state = assess(vm, c, aid, did, verdict("not_exposed"), calls)
        assert state == "PATCH_REQUIRED"
        assert calls == []
        a = c.get_assessment(aid, did)
        assert a["path"] == "hash"
        assert a["matched_label"] == "1.1"
        assert a["file_hash"] == sha(V11)
        assert c.get_capability(did) == "blocked"


def test_affected_pin_with_no_patch_is_quarantined():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        aid = open_advisory(vm, c, extract(patched_labels=[]))
        assert assess(vm, c, aid, did) == "QUARANTINED"
        assert c.get_capability(did) == "blocked"


def test_unaffected_registered_pin_is_never_contained():
    vm, c = _boot()
    calls = []
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_10)
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did, verdict("exposed"), calls) == "UNAFFECTED"
        assert calls == []
        assert c.get_capability(did) == "allowed"


def test_fork_byte_identical_to_affected_version_resolves_by_hash():
    vm, c = _boot()
    serve(vm, file_url(FORK, SHA_SPARE), V11)
    calls = []
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_SPARE)
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did, verdict("not_exposed"), calls) == "PATCH_REQUIRED"
        assert calls == []
        assert c.get_assessment(aid, did)["matched_label"] == "1.1"


# ---------- consensus path: divergent forks ----------

def test_divergent_fork_judged_exposed_is_patch_required():
    vm, c = _boot()
    calls = []
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_FORK_UNFIXED)
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did, verdict("exposed"), calls) == "PATCH_REQUIRED"
        assert len(calls) == 1
        a = c.get_assessment(aid, did)
        assert a["path"] == "consensus"
        assert a["minority_note"] != ""
        assert c.get_capability(did) == "blocked"


def test_divergent_fork_judged_not_exposed_is_unaffected():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_FORK_FIXED)
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did, verdict("not_exposed")) == "UNAFFECTED"
        assert c.get_capability(did) == "allowed"


def test_unclear_verdict_is_held_as_evidence_conflict_not_disabled():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_FORK_UNFIXED)
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did, verdict("unclear")) == "EVIDENCE_CONFLICT"
        assert c.get_assessment(aid, did)["conflict_reason"] == "unclear"
        assert c.get_capability(did) == "warn"


def test_strict_posture_blocks_on_evidence_conflict():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_FORK_UNFIXED, "strict")
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did, verdict("unclear")) == "EVIDENCE_CONFLICT"
        assert c.get_capability(did) == "blocked"


def test_oversized_dependent_file_is_held_and_never_truncated():
    vm, c = _boot()
    serve(vm, file_url(FORK, SHA_SPARE), "x" * 12001)
    calls = []
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_SPARE)
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did, verdict("exposed"), calls) == "EVIDENCE_CONFLICT"
        assert calls == []
        assert c.get_assessment(aid, did)["conflict_reason"] == "too_large"
        vm._gl_call_hook = llm(verdict("not_exposed"))
        with pytest.raises(AssertionError):
            c.escalate(aid, did, T)


# ---------- escalation ----------

def test_escalation_commits_and_restores_a_held_deployment():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_FORK_FIXED)
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did, verdict("unclear")) == "EVIDENCE_CONFLICT"
        assert escalate(vm, c, aid, did, verdict("not_exposed"), BYSTANDER) == "RESTORED"
        assert c.get_assessment(aid, did)["path"] == "escalation"
        assert c.get_capability(did) == "allowed"


def test_escalation_can_commit_to_exposed():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_FORK_UNFIXED)
        aid = open_advisory(vm, c)
        assess(vm, c, aid, did, verdict("unclear"))
        assert escalate(vm, c, aid, did, verdict("exposed")) == "PATCH_REQUIRED"
        assert c.get_capability(did) == "blocked"


def test_unresolved_escalation_keeps_conflict_and_cannot_be_replayed():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, FORK, SHA_FORK_UNFIXED)
        aid = open_advisory(vm, c)
        assess(vm, c, aid, did, verdict("unclear"))
        assert escalate(vm, c, aid, did, verdict("unresolved")) == "EVIDENCE_CONFLICT"
        assert c.get_assessment(aid, did)["conflict_reason"] == "unresolved"
        vm._gl_call_hook = llm(verdict("not_exposed"))
        with pytest.raises(AssertionError):
            c.escalate(aid, did, T)


def test_only_an_evidence_conflict_can_be_escalated():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        aid = open_advisory(vm, c)
        assess(vm, c, aid, did)
        vm._gl_call_hook = llm(verdict("not_exposed"))
        with pytest.raises(AssertionError):
            c.escalate(aid, did, T)
        assert c.get_capability(did) == "blocked"


# ---------- re-pin semantics ----------

def test_repin_alone_never_unblocks():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        aid = open_advisory(vm, c)
        assess(vm, c, aid, did)
        repin(vm, c, did, OWNER_A, PKG, SHA_12)
        assert c.get_capability(did) == "blocked"
        a = c.get_assessment(aid, did)
        assert a["state"] == "PATCH_REQUIRED"
        assert a["stale"] is True


def test_repin_to_patched_then_reassess_restores():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        aid = open_advisory(vm, c)
        assess(vm, c, aid, did)
        repin(vm, c, did, OWNER_A, PKG, SHA_12)
        assert assess(vm, c, aid, did, who=BYSTANDER) == "RESTORED"
        assert c.get_capability(did) == "allowed"


def test_repin_to_another_affected_version_stays_blocked():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        aid = open_advisory(vm, c, extract(affected_labels=["1.0", "1.1"]))
        assess(vm, c, aid, did)
        repin(vm, c, did, OWNER_A, PKG, SHA_10)
        assert assess(vm, c, aid, did) == "PATCH_REQUIRED"
        assert c.get_capability(did) == "blocked"


def test_repin_away_from_a_cleared_pin_blocks_until_reassessed():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        did = add_dependent(vm, c, OWNER_A, PKG, SHA_10)
        aid = open_advisory(vm, c)
        assert assess(vm, c, aid, did) == "UNAFFECTED"
        repin(vm, c, did, OWNER_A, PKG, SHA_11)
        assert c.get_capability(did) == "blocked"
        assert assess(vm, c, aid, did) == "PATCH_REQUIRED"


# ---------- no operator, anywhere ----------

def test_bystander_assessment_matches_a_party_assessment():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        d1 = add_dependent(vm, c, OWNER_A, FORK, SHA_FORK_UNFIXED)
        d2 = add_dependent(vm, c, OWNER_B, FORK, SHA_FORK_UNFIXED)
        aid = open_advisory(vm, c)
        s1 = assess(vm, c, aid, d1, verdict("exposed"), who=OWNER_A)
        s2 = assess(vm, c, aid, d2, verdict("exposed"), who=BYSTANDER)
        assert s1 == s2 == "PATCH_REQUIRED"
        assert c.get_assessment(aid, d1)["assessor"] == hx(OWNER_A)
        assert c.get_assessment(aid, d2)["assessor"] == hx(BYSTANDER)


def test_deployer_has_no_status_power():
    vm, c = _boot(DEPLOYER)
    with vm.activate():
        set_sender(vm, MAINTAINER)
        register_package(c)
        d1 = add_dependent(vm, c, OWNER_A, PKG, SHA_10)
        d2 = add_dependent(vm, c, OWNER_B, PKG, SHA_10)
        aid = open_advisory(vm, c)
        s1 = assess(vm, c, aid, d1, who=DEPLOYER)
        s2 = assess(vm, c, aid, d2, who=BYSTANDER)
        assert s1 == s2 == "UNAFFECTED"


def test_contract_exposes_no_status_setter():
    with open(REGISTRY, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    writes = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if ast.unparse(dec) == "gl.public.write":
                    writes.add(node.name)
    assert writes == {
        "register_package", "add_version", "register_dependent", "repin_dependent",
        "report_advisory", "report_followup", "propagate", "escalate_propagation",
        "assess_dependent", "escalate",
    }
