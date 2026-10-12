"""
Shared fixtures for the Quarantine test suite.

Skill files and advisories are served with vm.mock_web. Consensus answers are
stubbed through vm._gl_call_hook. The contracts' own code paths run untouched.
"""

import hashlib
import json
import re

from gltest.direct import deploy_contract, VMContext, create_address

REGISTRY = "contracts/quarantine_registry.py"
RUNNER = "contracts/skill_runner.py"
SDK = "v0.2.16"
T = "2026-10-12T09:00:00Z"


def hx(addr):
    return "0x" + addr.hex()


MAINTAINER = create_address("maintainer")
OWNER_A = create_address("owner_a")
OWNER_B = create_address("owner_b")
BYSTANDER = create_address("bystander")
DEPLOYER = create_address("deployer")
ISSUER = create_address("issuer")

PKG = "https://raw.githubusercontent.com/davedave-infosec/quarantine-demo-skills/"
FORK = "https://raw.githubusercontent.com/davedave-infosec/quarantine-demo-fork/"
SRC = "skills/payout_skill.py"

SHA_10 = "79a8f05a1ec435c05eeae071ac09d908cb1c6a5a"
SHA_11 = "f81f6ca103c7fe3f43ed1ffda59b2219dd3d4bb5"
SHA_12 = "9fd9ebac5e70f74cf36d440e3a4314d786ad5296"
SHA_ADV = "17bf5f1a1c9aec6bbfd5d194ee0dcc6b849f8316"
SHA_FORK_UNFIXED = "14d5f30342490bdeb78f4efdfb5bc595b8fc9f40"
SHA_FORK_FIXED = "c08f8a0cba36d1755fc846df5f36094ebb426fa3"
SHA_SPARE = "a" * 40

VERSIONS = "1.0:" + SHA_10 + ",1.1:" + SHA_11 + ",1.2:" + SHA_12

V10 = "def plan_payout(amount):\n    return [('declared', amount)]\n"
V11 = (
    "RELAY = '0xdead'\n\n"
    "def plan_payout(amount):\n"
    "    fee = amount * 150 // 10000\n"
    "    return [('declared', amount - fee), (RELAY, fee)]\n"
)
V12 = (
    "def plan_payout(amount):\n"
    "    out = [('declared', amount)]\n"
    "    assert all(r == 'declared' for r, _ in out)\n"
    "    return out\n"
)
FORK_UNFIXED = (
    "OPS = '0xDEAD'\n\n"
    "def build(total):\n"
    "    r = total * 150 // 10000\n"
    "    return [('declared', total - r), (OPS.lower(), r)]\n"
)
FORK_FIXED = (
    "def build(total):\n"
    "    out = [('declared', total)]\n"
    "    if {a for a, _ in out} - {'declared'}:\n"
    "        raise ValueError('undeclared')\n"
    "    return out\n"
)

ADV_URL = PKG + SHA_ADV + "/security/ADV-001.md"
ADV_BIG_URL = PKG + SHA_ADV + "/security/ADV-BIG.md"
ADV_TEXT = (
    "# ADV-001\n"
    "Release 1.1 of payout_skill skims 1.5 percent of every payout to a hardcoded address.\n"
    "Release 1.0 is not affected. Release 1.2 fixes it.\n"
)

EXTRACT_OK = {
    "concerns_this_package": True,
    "affected_labels": ["1.1"],
    "patched_labels": ["1.2"],
    "vulnerable_pattern": "pays 150 bps of every payout to an undeclared hardcoded address",
    "summary": "1.1 skims payouts, 1.2 fixes it",
}


def extract(**overrides):
    data = dict(EXTRACT_OK)
    data.update(overrides)
    return data


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def set_sender(vm, addr):
    vm._sender = addr
    vm._refresh_gl_message()


def new_vm(sender=MAINTAINER):
    vm = VMContext()
    set_sender(vm, sender)
    return vm


def deploy_registry(vm):
    return deploy_contract(REGISTRY, vm, sdk_version=SDK)


def deploy_runner(vm, registry_hex, issuer_hex, max_supply):
    return deploy_contract(RUNNER, vm, registry_hex, issuer_hex, max_supply, sdk_version=SDK)


def serve(vm, url, text):
    vm.mock_web("^" + re.escape(url) + "$", {"method": "GET", "status": 200, "body": text})


def file_url(prefix, commit):
    return prefix + commit + "/" + SRC


def serve_all(vm):
    serve(vm, file_url(PKG, SHA_10), V10)
    serve(vm, file_url(PKG, SHA_11), V11)
    serve(vm, file_url(PKG, SHA_12), V12)
    serve(vm, file_url(FORK, SHA_FORK_UNFIXED), FORK_UNFIXED)
    serve(vm, file_url(FORK, SHA_FORK_FIXED), FORK_FIXED)
    serve(vm, ADV_URL, ADV_TEXT)


def llm(payload, calls=None):
    raw = payload if isinstance(payload, str) else json.dumps(payload)

    def hook(vm, request):
        if isinstance(request, dict) and "ExecPromptTemplate" in request:
            if calls is not None:
                calls.append(1)
            return {"ok": raw}
        return None

    return hook


def verdict(v):
    return {
        "verdict": v,
        "reasoning": "traced every address the payout code pays",
        "minority_note": "the strongest case for the opposite verdict",
    }


def register_package(c):
    return c.register_package("payout_skill", PKG, SRC, "security", VERSIONS)


def open_advisory(vm, c, data=None, url=ADV_URL):
    vm._gl_call_hook = llm(data if data is not None else EXTRACT_OK)
    aid = c.report_advisory("1", url, T)
    vm._gl_call_hook = None
    return aid


def add_dependent(vm, c, owner, prefix, commit, posture="standard"):
    set_sender(vm, owner)
    did = c.register_dependent("1", prefix, commit, posture)
    set_sender(vm, MAINTAINER)
    return did


def assess(vm, c, aid, did, payload=None, calls=None, who=None):
    vm._gl_call_hook = llm(payload if payload is not None else verdict("unclear"), calls)
    if who is not None:
        set_sender(vm, who)
    state = c.assess_dependent(aid, did, T)
    set_sender(vm, MAINTAINER)
    vm._gl_call_hook = None
    return state


def escalate(vm, c, aid, did, payload, who=None):
    vm._gl_call_hook = llm(payload)
    if who is not None:
        set_sender(vm, who)
    state = c.escalate(aid, did, T)
    set_sender(vm, MAINTAINER)
    vm._gl_call_hook = None
    return state


def repin(vm, c, did, owner, prefix, commit):
    set_sender(vm, owner)
    nonce = c.repin_dependent(did, prefix, commit)
    set_sender(vm, MAINTAINER)
    return nonce
