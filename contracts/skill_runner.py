# v0.1.0
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""
Quarantine skill runner.

The capability host. Holds an internal GEN ledger and executes payouts
through a registered skill deployment only when the Quarantine registry
says the deployment is not blocked. All registry access is view-only.
"""

from genlayer import *

VAULT_KEY = "__vault__"
HEX_CHARS = "0123456789abcdef"


def _check_address(value: str) -> str:
    clean = value.strip().lower()
    assert len(clean) == 42 and clean.startswith("0x"), "address must be 0x followed by 40 hex characters"
    assert all(ch in HEX_CHARS for ch in clean[2:]), "address must be 0x followed by 40 hex characters"
    return clean


class SkillRunner(gl.Contract):
    registry: str
    issuer: str
    max_supply: u256
    minted: u256

    balances: TreeMap[str, u256]
    operator: TreeMap[str, str]

    exec_count: u256
    exec_dependent: TreeMap[str, str]
    exec_operator: TreeMap[str, str]
    exec_recipient: TreeMap[str, str]
    exec_amount: TreeMap[str, str]
    exec_capability: TreeMap[str, str]
    exec_at: TreeMap[str, str]

    def __init__(self, registry_address: str, issuer: str, max_supply: int):
        assert max_supply > 0, "max supply must be positive"
        self.registry = _check_address(registry_address)
        self.issuer = _check_address(issuer)
        self.max_supply = u256(int(max_supply))
        self.minted = u256(0)
        self.exec_count = u256(0)
        self.balances[VAULT_KEY] = u256(0)

    def _sender(self) -> str:
        return gl.message.sender_address.as_hex.lower()

    def _registry(self):
        return gl.get_contract_at(Address(self.registry)).view()

    def _balance(self, key: str) -> int:
        if key in self.balances:
            return int(self.balances[key])
        return 0

    # ---------- supply ----------

    @gl.public.write
    def mint(self, amount: int) -> str:
        assert self._sender() == self.issuer, "only the issuer can mint"
        assert amount > 0, "amount must be positive"
        new_minted = int(self.minted) + int(amount)
        assert new_minted <= int(self.max_supply), "mint would exceed max supply"
        self.minted = u256(new_minted)
        self.balances[VAULT_KEY] = u256(self._balance(VAULT_KEY) + int(amount))
        return str(self._balance(VAULT_KEY))

    # ---------- binding ----------

    @gl.public.write
    def bind_skill(self, dependent_id: str) -> str:
        dep = self._registry().get_dependent(dependent_id)
        owner = str(dep["owner"]).lower()
        caller = self._sender()
        assert caller == owner, "only the dependent owner can bind this skill"
        self.operator[dependent_id] = caller
        return caller

    # ---------- execution ----------

    @gl.public.write
    def execute(self, dependent_id: str, recipient: str, amount: int, executed_at: str) -> str:
        assert dependent_id in self.operator, "skill is not bound"
        caller = self._sender()
        assert caller == self.operator[dependent_id], "only the bound operator can execute this skill"
        to = _check_address(recipient)
        assert amount > 0, "amount must be positive"

        capability = str(self._registry().get_capability(dependent_id))
        assert capability != "blocked", "skill is quarantined"
        assert capability == "allowed" or capability == "warn", "unknown capability from registry"

        vault = self._balance(VAULT_KEY)
        assert vault >= int(amount), "vault balance is too low"
        self.balances[VAULT_KEY] = u256(vault - int(amount))
        self.balances[to] = u256(self._balance(to) + int(amount))

        eid = str(int(self.exec_count) + 1)
        self.exec_count = u256(int(self.exec_count) + 1)
        self.exec_dependent[eid] = dependent_id
        self.exec_operator[eid] = caller
        self.exec_recipient[eid] = to
        self.exec_amount[eid] = str(int(amount))
        self.exec_capability[eid] = capability
        self.exec_at[eid] = executed_at
        return capability

    # ---------- views ----------

    @gl.public.view
    def get_config(self) -> dict:
        return {
            "registry": self.registry,
            "issuer": self.issuer,
            "max_supply": str(int(self.max_supply)),
            "minted": str(int(self.minted)),
            "vault": str(self._balance(VAULT_KEY)),
            "executions": str(int(self.exec_count)),
        }

    @gl.public.view
    def balance_of(self, account: str) -> str:
        return str(self._balance(account.strip().lower()))

    @gl.public.view
    def get_operator(self, dependent_id: str) -> str:
        if dependent_id in self.operator:
            return self.operator[dependent_id]
        return ""

    @gl.public.view
    def get_execution(self, execution_id: str) -> dict:
        assert execution_id in self.exec_dependent, "unknown execution"
        return {
            "id": execution_id,
            "dependent_id": self.exec_dependent[execution_id],
            "operator": self.exec_operator[execution_id],
            "recipient": self.exec_recipient[execution_id],
            "amount": self.exec_amount[execution_id],
            "capability": self.exec_capability[execution_id],
            "executed_at": self.exec_at[execution_id],
        }
