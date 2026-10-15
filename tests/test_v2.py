"""
Quarantine V2 tests, real contract code on the gltest direct runner.

Tag-verified labels, transitive exposure through vendored upstreams, and
advisory withdrawal and amendment. See TESTING.md for the map.
"""

import pytest

from qhelp import (
    PKG, WRAP, SRC, WSRC, WVEN, T,
    ADV2_URL, ADV2W_URL,
    SHA_10, SHA_11, SHA_W20, SHA_W21, SHA_W22, SHA_SPARE,
    V10, V11, V12, W22_SRC, WRAPPER_VERSIONS,
    MAINTAINER, OWNER_A, OWNER_B,
    new_vm, deploy_registry, serve, serve_status, file_url, tag_url, serve_all,
    llm, verdict, extract, relation, register_package, register_wrapper, open_advisory,
    add_dependent, wrapper_dependent, assess, propagate, escalate_prop, followup,
)


def _boot():
    vm = new_vm(MAINTAINER)
    c = deploy_registry(vm)
    serve_all(vm)
    return vm, c


def _wrapper_setup(vm, c):
    register_package(c)
    register_wrapper(c)
    return open_advisory(vm, c)


def _judged(vm, c, aid, first="exposed", second="neutralized"):
    did = propagate(vm, c, aid, "2.0", verdict(first))
    propagate(vm, c, aid, "2.1", verdict(second))
    return did


# ---------- tag-verified labels ----------

def test_a_version_must_match_the_repo_tag_of_the_same_name():
    vm = new_vm()
    c = deploy_registry(vm)
    serve(vm, file_url(PKG, SHA_10), V10)
    serve(vm, file_url(PKG, SHA_11), V11)
    serve(vm, tag_url(PKG, "1.0"), V10)
    serve(vm, tag_url(PKG, "1.1"), V12)
    with vm.activate():
        with pytest.raises(AssertionError):
            c.register_package("payout_skill", PKG, SRC, "security",
                               "1.0:" + SHA_10 + ",1.1:" + SHA_11, "", "")


def test_a_missing_tag_rejects_the_version():
    vm = new_vm()
    c = deploy_registry(vm)
    serve(vm, file_url(PKG, SHA_10), V10)
    serve(vm, file_url(PKG, SHA_11), V11)
    serve(vm, tag_url(PKG, "1.0"), V10)
    serve_status(vm, tag_url(PKG, "1.1"), 404)
    with vm.activate():
        with pytest.raises(AssertionError):
            c.register_package("payout_skill", PKG, SRC, "security",
                               "1.0:" + SHA_10 + ",1.1:" + SHA_11, "", "")


# ---------- vendoring ----------

def test_wrapper_registration_detects_vendored_versions_by_hash():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        assert register_wrapper(c) == "2"
        p = c.get_package("2")
        assert p["upstream"] == "1"
        assert p["vendor_path"] == WVEN
        assert [v["vendored"] for v in p["versions"]] == ["1.1", "1.1", "1.2"]


def test_a_vendor_path_needs_a_known_upstream_and_its_own_path():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        with pytest.raises(AssertionError):
            c.register_package("batch_payout", WRAP, WSRC, "security", WRAPPER_VERSIONS, "", WVEN)
        with pytest.raises(AssertionError):
            c.register_package("batch_payout", WRAP, WSRC, "security", WRAPPER_VERSIONS, "9", WVEN)
        with pytest.raises(AssertionError):
            c.register_package("batch_payout", WRAP, WSRC, "security", WRAPPER_VERSIONS, "1", WSRC)


def test_swapping_only_the_vendored_file_never_matches_a_clean_version():
    vm, c = _boot()
    serve(vm, file_url(WRAP, SHA_SPARE, WSRC), W22_SRC)
    serve(vm, file_url(WRAP, SHA_SPARE, WVEN), V11)
    calls = []
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        did = _judged(vm, c, aid)
        d = wrapper_dependent(vm, c, OWNER_A, SHA_SPARE)
        assert assess(vm, c, did, d, verdict("exposed"), calls) == "PATCH_REQUIRED"
        assert len(calls) == 1
        assert c.get_assessment(did, d)["path"] == "consensus"


# ---------- propagation ----------

def test_propagation_starts_pending_and_clears_clean_versions_without_consensus():
    vm, c = _boot()
    calls = []
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        d = wrapper_dependent(vm, c, OWNER_A, SHA_W20)
        did = propagate(vm, c, aid, "", verdict("exposed"), calls)
        assert calls == []
        prop = c.get_propagation(did)
        assert prop["status"] == "PENDING"
        assert [(r["label"], r["state"]) for r in prop["versions"]] == [
            ("2.0", "todo"), ("2.1", "todo"), ("2.2", "clean"),
        ]
        assert c.get_derived(aid, "2") == did
        assert c.get_capability(d) == "warn"
        with pytest.raises(AssertionError):
            c.assess_dependent(did, d, T)


def test_propagation_verdicts_open_the_derived_advisory():
    vm, c = _boot()
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        did = _judged(vm, c, aid)
        a = c.get_advisory(did)
        assert a["status"] == "OPEN"
        assert a["kind"] == "derived"
        assert a["parent"] == aid
        assert a["affected_labels"] == ["2.0"]
        assert a["patched_labels"] == ["2.1", "2.2"]
        assert a["uncertain_labels"] == []
        assert did in c.get_package("2")["open_advisory_ids"]


def test_wrapper_deployments_resolve_by_hash_under_the_derived_advisory():
    vm, c = _boot()
    calls = []
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        did = _judged(vm, c, aid)
        d0 = wrapper_dependent(vm, c, OWNER_A, SHA_W20)
        d1 = wrapper_dependent(vm, c, OWNER_B, SHA_W21)
        d2 = wrapper_dependent(vm, c, OWNER_A, SHA_W22)
        assert assess(vm, c, did, d0, verdict("not_exposed"), calls) == "PATCH_REQUIRED"
        assert assess(vm, c, did, d1, verdict("exposed"), calls) == "UNAFFECTED"
        assert assess(vm, c, did, d2, verdict("exposed"), calls) == "UNAFFECTED"
        assert calls == []
        assert c.get_capability(d0) == "blocked"
        assert c.get_capability(d1) == "allowed"
        assert c.get_capability(d2) == "allowed"


def test_clean_versions_are_never_judged_and_verdicts_are_never_rejudged():
    vm, c = _boot()
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        propagate(vm, c, aid, "2.0", verdict("exposed"))
        vm._gl_call_hook = llm(verdict("neutralized"))
        with pytest.raises(AssertionError):
            c.propagate(aid, "2", "2.2", T)
        with pytest.raises(AssertionError):
            c.propagate(aid, "2", "2.0", T)
        with pytest.raises(AssertionError):
            c.propagate(aid, "2", "", T)


def test_an_unclear_wrapper_is_held_and_only_propagation_escalation_settles_it():
    vm, c = _boot()
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        did = _judged(vm, c, aid, first="unclear")
        a = c.get_advisory(did)
        assert a["status"] == "OPEN"
        assert a["uncertain_labels"] == ["2.0"]
        assert a["affected_labels"] == []
        d0 = wrapper_dependent(vm, c, OWNER_A, SHA_W20)
        assert assess(vm, c, did, d0) == "EVIDENCE_CONFLICT"
        assert c.get_assessment(did, d0)["conflict_reason"] == "inherited_unclear"
        assert c.get_capability(d0) == "warn"
        vm._gl_call_hook = llm(verdict("not_exposed"))
        with pytest.raises(AssertionError):
            c.escalate(did, d0, T)
        assert escalate_prop(vm, c, did, "2.0", verdict("exposed")) == "OPEN"
        assert c.get_advisory(did)["affected_labels"] == ["2.0"]
        assert assess(vm, c, did, d0) == "PATCH_REQUIRED"
        assert c.get_capability(d0) == "blocked"
        vm._gl_call_hook = llm(verdict("neutralized"))
        with pytest.raises(AssertionError):
            c.escalate_propagation(did, "2.0", T)


def test_an_unresolved_propagation_escalation_stays_held_and_runs_once():
    vm, c = _boot()
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        did = _judged(vm, c, aid, first="unclear")
        assert escalate_prop(vm, c, did, "2.0", verdict("unresolved")) == "OPEN"
        assert c.get_advisory(did)["uncertain_labels"] == ["2.0"]
        vm._gl_call_hook = llm(verdict("exposed"))
        with pytest.raises(AssertionError):
            c.escalate_propagation(did, "2.0", T)


def test_a_fully_neutralized_wrapper_inherits_nothing():
    vm, c = _boot()
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        did = _judged(vm, c, aid, first="neutralized")
        assert c.get_advisory(did)["status"] == "CLEAR"
        assert did not in c.get_package("2")["open_advisory_ids"]
        d0 = wrapper_dependent(vm, c, OWNER_A, SHA_W20)
        assert c.get_capability(d0) == "allowed"


def test_propagation_only_reaches_packages_that_vendor_the_upstream():
    vm, c = _boot()
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        vm._gl_call_hook = llm(verdict("exposed"))
        with pytest.raises(AssertionError):
            c.propagate(aid, "1", "", T)


def test_withdrawing_the_upstream_advisory_lifts_every_inherited_block():
    vm, c = _boot()
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        did = _judged(vm, c, aid)
        d0 = wrapper_dependent(vm, c, OWNER_A, SHA_W20)
        assert assess(vm, c, did, d0) == "PATCH_REQUIRED"
        assert c.get_capability(d0) == "blocked"
        fid = followup(vm, c, aid, ADV2W_URL, relation("withdraws"))
        assert c.get_advisory(fid)["status"] == "WITHDRAWAL"
        assert c.get_advisory(aid)["status"] == "WITHDRAWN"
        assert c.get_advisory(did)["in_force"] is False
        assert c.get_capability(d0) == "allowed"
        vm._gl_call_hook = llm(verdict("exposed"))
        with pytest.raises(AssertionError):
            c.assess_dependent(did, d0, T)


# ---------- follow-up advisories ----------

def test_a_withdrawal_releases_a_false_positive():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        b = add_dependent(vm, c, OWNER_B, PKG, SHA_10)
        adv2 = open_advisory(vm, c, extract(affected_labels=["1.0"], patched_labels=["1.2"]), ADV2_URL)
        assert assess(vm, c, adv2, b) == "PATCH_REQUIRED"
        assert c.get_capability(b) == "blocked"
        fid = followup(vm, c, adv2, ADV2W_URL, relation("withdraws"))
        assert c.get_advisory(adv2)["status"] == "WITHDRAWN"
        assert c.get_advisory(fid)["parent"] == adv2
        assert c.get_capability(b) == "allowed"
        assert adv2 not in c.get_package("1")["open_advisory_ids"]


def test_an_unrelated_followup_is_rejected_and_changes_nothing():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        a = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        adv = open_advisory(vm, c)
        assess(vm, c, adv, a)
        fid = followup(vm, c, adv, ADV2W_URL, relation("unrelated"))
        assert c.get_advisory(fid)["status"] == "REJECTED_UNRELATED"
        assert c.get_advisory(adv)["status"] == "OPEN"
        assert c.get_capability(a) == "blocked"


def test_an_amendment_keeps_old_blocks_until_the_successor_assesses():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        a = add_dependent(vm, c, OWNER_A, PKG, SHA_11)
        adv = open_advisory(vm, c)
        assert assess(vm, c, adv, a) == "PATCH_REQUIRED"
        new = followup(vm, c, adv, ADV2_URL, relation("amends", ["1.0"], ["1.2"], "skim in 1.0"))
        assert c.get_advisory(new)["status"] == "OPEN"
        assert c.get_advisory(new)["kind"] == "amendment"
        assert c.get_advisory(adv)["status"] == "SUPERSEDED"
        assert c.get_advisory(adv)["successor"] == new
        assert c.get_capability(a) == "blocked"
        assert assess(vm, c, new, a) == "UNAFFECTED"
        assert c.get_capability(a) == "allowed"


def test_a_widening_amendment_never_unblocks_and_flags_new_versions():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        b = add_dependent(vm, c, OWNER_B, PKG, SHA_10)
        adv = open_advisory(vm, c)
        assert assess(vm, c, adv, b) == "UNAFFECTED"
        assert c.get_capability(b) == "allowed"
        new = followup(vm, c, adv, ADV2_URL, relation("amends", ["1.0", "1.1"], ["1.2"]))
        assert c.get_capability(b) == "warn"
        assert assess(vm, c, new, b) == "PATCH_REQUIRED"
        assert c.get_capability(b) == "blocked"


def test_a_withdrawn_advisory_takes_no_followup():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        adv = open_advisory(vm, c)
        followup(vm, c, adv, ADV2W_URL, relation("withdraws"))
        vm._gl_call_hook = llm(relation("amends", ["1.1"], ["1.2"]))
        with pytest.raises(AssertionError):
            c.report_followup(adv, ADV2_URL, T)


def test_a_derived_advisory_takes_no_followup():
    vm, c = _boot()
    with vm.activate():
        aid = _wrapper_setup(vm, c)
        did = _judged(vm, c, aid)
        vm._gl_call_hook = llm(relation("withdraws"))
        with pytest.raises(AssertionError):
            c.report_followup(did, ADV2W_URL, T)


def test_a_followup_url_cannot_be_replayed():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        adv = open_advisory(vm, c)
        adv2 = open_advisory(vm, c, extract(affected_labels=["1.0"]), ADV2_URL)
        followup(vm, c, adv2, ADV2W_URL, relation("unrelated"))
        vm._gl_call_hook = llm(relation("withdraws"))
        with pytest.raises(AssertionError):
            c.report_followup(adv, ADV2W_URL, T)


def test_an_amendment_naming_unknown_versions_is_rejected():
    vm, c = _boot()
    with vm.activate():
        register_package(c)
        adv = open_advisory(vm, c)
        new = followup(vm, c, adv, ADV2_URL, relation("amends", ["1.9"], ["1.2"]))
        assert c.get_advisory(new)["status"] == "REJECTED_UNMAPPED"
        assert c.get_advisory(adv)["status"] == "OPEN"
