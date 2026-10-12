"""
Skill runner tests, real contract code on the gltest direct runner.

The runner's view reads of the registry are answered through vm._gl_call_hook,
so the runner's own mint, bind and execute logic runs untouched.
"""

import pytest

from qhelp import (
    ISSUER, OWNER_A, BYSTANDER, PKG, SHA_11,
    hx, set_sender, new_vm, deploy_runner,
)

REG = "0x" + "11" * 20
RECIP = "0x" + "aa" * 20


def registry_view(owner_hex, capability):
    box = {"cap": capability}

    def hook(vm, request):
        from genlayer.py import calldata
        if isinstance(request, dict) and "CallContract" in request:
            m = request["CallContract"]["calldata"]["method"]
            if m == "get_dependent":
                return bytes([0]) + calldata.encode({
                    "id": "1", "package_id": "1", "owner": owner_hex,
                    "repo_prefix": PKG, "pinned_sha": SHA_11, "posture": "standard",
                    "pin_nonce": "1", "capability": box["cap"],
                })
            if m == "get_capability":
                return bytes([0]) + calldata.encode(box["cap"])
        return None

    return hook, box


def _boot(max_supply=1000):
    vm = new_vm(ISSUER)
    r = deploy_runner(vm, REG, hx(ISSUER), max_supply)
    return vm, r


def _bound(vm, r, capability):
    hook, box = registry_view(hx(OWNER_A), capability)
    vm._gl_call_hook = hook
    set_sender(vm, ISSUER)
    r.mint(100)
    set_sender(vm, OWNER_A)
    r.bind_skill("1")
    return box


def test_mint_is_issuer_only_and_capped():
    vm, r = _boot()
    with vm.activate():
        assert r.mint(600) == "600"
        set_sender(vm, BYSTANDER)
        with pytest.raises(AssertionError):
            r.mint(1)
        set_sender(vm, ISSUER)
        with pytest.raises(AssertionError):
            r.mint(401)
        assert r.mint(400) == "1000"
        assert r.get_config()["minted"] == "1000"


def test_only_the_registry_owner_can_bind():
    vm, r = _boot()
    with vm.activate():
        hook, _ = registry_view(hx(OWNER_A), "allowed")
        vm._gl_call_hook = hook
        set_sender(vm, BYSTANDER)
        with pytest.raises(AssertionError):
            r.bind_skill("1")
        set_sender(vm, OWNER_A)
        assert r.bind_skill("1") == hx(OWNER_A)
        assert r.get_operator("1") == hx(OWNER_A)


def test_allowed_skill_executes_with_exact_conservation():
    vm, r = _boot()
    with vm.activate():
        _bound(vm, r, "allowed")
        assert r.execute("1", RECIP, 30, "2026-10-12T09:00:00Z") == "allowed"
        cfg = r.get_config()
        assert cfg["vault"] == "70"
        assert r.balance_of(RECIP) == "30"
        assert int(cfg["minted"]) == int(cfg["vault"]) + int(r.balance_of(RECIP))
        assert r.get_execution("1")["capability"] == "allowed"


def test_blocked_skill_reverts_and_vault_is_untouched():
    vm, r = _boot()
    with vm.activate():
        _bound(vm, r, "blocked")
        with pytest.raises(AssertionError):
            r.execute("1", RECIP, 30, "2026-10-12T09:00:00Z")
        assert r.get_config()["vault"] == "100"
        assert r.balance_of(RECIP) == "0"
        assert r.get_config()["executions"] == "0"


def test_non_operator_cannot_execute():
    vm, r = _boot()
    with vm.activate():
        _bound(vm, r, "allowed")
        set_sender(vm, BYSTANDER)
        with pytest.raises(AssertionError):
            r.execute("1", RECIP, 30, "2026-10-12T09:00:00Z")
        assert r.get_config()["vault"] == "100"


def test_warn_executes_and_is_recorded_as_warn():
    vm, r = _boot()
    with vm.activate():
        _bound(vm, r, "warn")
        assert r.execute("1", RECIP, 10, "2026-10-12T09:00:00Z") == "warn"
        assert r.get_execution("1")["capability"] == "warn"


def test_restored_skill_executes_again():
    vm, r = _boot()
    with vm.activate():
        box = _bound(vm, r, "blocked")
        with pytest.raises(AssertionError):
            r.execute("1", RECIP, 10, "2026-10-12T09:00:00Z")
        box["cap"] = "allowed"
        assert r.execute("1", RECIP, 10, "2026-10-12T09:00:00Z") == "allowed"
        assert r.get_config()["vault"] == "90"


def test_unknown_capability_fails_closed():
    vm, r = _boot()
    with vm.activate():
        _bound(vm, r, "maybe")
        with pytest.raises(AssertionError):
            r.execute("1", RECIP, 10, "2026-10-12T09:00:00Z")
        assert r.get_config()["vault"] == "100"


def test_execute_cannot_overdraw_the_vault():
    vm, r = _boot()
    with vm.activate():
        _bound(vm, r, "allowed")
        with pytest.raises(AssertionError):
            r.execute("1", RECIP, 101, "2026-10-12T09:00:00Z")
        assert r.get_config()["vault"] == "100"
