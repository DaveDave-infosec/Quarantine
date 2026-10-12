# Testing

48 tests, 0 skipped. Every test drives the real contract code.

## Run

```
pip install "genlayer-test[sim]" pytest
python -m pytest tests/ -v
```

## Harness

- gltest **direct** in-process runner (`gltest.direct`), fully offline, no keys, no gas.
- GenVM SDK pinned to `v0.2.16` in `tests/qhelp.py` (later release tags renamed the runner asset).
- Skill files and advisories are served with `vm.mock_web`, matched on the exact commit-pinned URL.
- Consensus answers are supplied through `vm._gl_call_hook` by answering the `ExecPromptTemplate` request. The contract's own parsing, validation and state logic runs on that answer.
- The runner's view reads of the registry are answered through `vm._gl_call_hook` on `CallContract`, so the runner's own mint, bind and execute logic runs untouched.
- Hash-path tests pass a hook that records every LLM request and assert the record is empty. That is how "no consensus spent" is proven, not assumed.
- Root `conftest.py` holds two runner fixes only: a Windows temp-file unlink shim and a contract-cache reset between tests.
- Contract asserts surface as `AssertionError`.

## What each test proves

### Registry: registration and caller binding

| Test | Property |
|---|---|
| `test_register_package_locks_sources_and_version_hashes` | Repo prefix, file path and advisory dir are locked; each version's sha256 is stored from fetched bytes; caller is maintainer |
| `test_two_versions_with_identical_bytes_are_rejected` | Hash-to-label mapping is never ambiguous |
| `test_only_the_maintainer_can_add_a_version` | Caller binding on versions |
| `test_only_the_owner_can_repin_a_dependent` | Caller binding on pins |

### Registry: advisory intake

| Test | Property |
|---|---|
| `test_advisory_outside_the_locked_repo_is_rejected` | Evidence source locked to the package repo |
| `test_malformed_advisory_url_is_rejected_before_any_consensus` (8 cases) | Trailing text, wrong extension, query, fragment, short sha, uppercase sha, wrong directory and nested path all revert before any LLM call |
| `test_replaying_the_same_advisory_url_reverts` | Replay closed |
| `test_advisory_naming_unknown_versions_is_rejected_unmapped` | An advisory naming versions the registry does not know contains nobody |
| `test_advisory_about_another_package_is_rejected_not_applicable` | Off-target advisories contain nobody |
| `test_oversized_advisory_is_rejected_without_consensus` | Size cap enforced before consensus |
| `test_fenced_json_opens_and_string_false_is_not_truthy` | Fenced model output parses; `"false"` is never true |
| `test_unreadable_model_output_reverts` | Unreadable output never becomes a verdict |

### Registry: hash path, decided in code

| Test | Property |
|---|---|
| `test_registered_affected_pin_is_patch_required_and_llm_is_never_called` | Exact pin resolves by hash with zero LLM calls; unassessed reports `warn`, assessed reports `blocked` |
| `test_affected_pin_with_no_patch_is_quarantined` | No patch available means `QUARANTINED` |
| `test_unaffected_registered_pin_is_never_contained` | False-positive guard, with zero LLM calls |
| `test_fork_byte_identical_to_affected_version_resolves_by_hash` | A fork copied byte for byte is caught by hash, not consensus |

### Registry: consensus path, divergent forks

| Test | Property |
|---|---|
| `test_divergent_fork_judged_exposed_is_patch_required` | Exactly one consensus call; minority note stored |
| `test_divergent_fork_judged_not_exposed_is_unaffected` | Real fixes clear |
| `test_unclear_verdict_is_held_as_evidence_conflict_not_disabled` | Uncertainty is held, standard posture warns |
| `test_strict_posture_blocks_on_evidence_conflict` | The deployment's own chosen risk tolerance applies |
| `test_oversized_dependent_file_is_held_and_never_truncated` | Never judged on a fragment; cannot be escalated |

### Registry: escalation

| Test | Property |
|---|---|
| `test_escalation_commits_and_restores_a_held_deployment` | Forcing pass resolves a conflict, run by a bystander |
| `test_escalation_can_commit_to_exposed` | Forcing pass can contain |
| `test_unresolved_escalation_keeps_conflict_and_cannot_be_replayed` | Honest deadlock stays held; one escalation per evidence |
| `test_only_an_evidence_conflict_can_be_escalated` | Escalation cannot reopen a decided case |

### Registry: re-pin semantics

| Test | Property |
|---|---|
| `test_repin_alone_never_unblocks` | Re-pin leaves the state in place and marks it stale; still blocked |
| `test_repin_to_patched_then_reassess_restores` | Bystander reassessment restores |
| `test_repin_to_another_affected_version_stays_blocked` | Hopping between affected versions does not escape |
| `test_repin_away_from_a_cleared_pin_blocks_until_reassessed` | A cleared deployment cannot quietly switch to an affected pin |

### Registry: no operator, anywhere

| Test | Property |
|---|---|
| `test_bystander_assessment_matches_a_party_assessment` | Permissionless assessment; assessor recorded |
| `test_deployer_has_no_status_power` | Deployer gets the same result as a bystander |
| `test_contract_exposes_no_status_setter` | Parses the contract and asserts the exact set of write methods; no setter exists |

### Skill runner

| Test | Property |
|---|---|
| `test_mint_is_issuer_only_and_capped` | Scarce issuance |
| `test_only_the_registry_owner_can_bind` | Operator binding is read from the registry |
| `test_allowed_skill_executes_with_exact_conservation` | minted = vault + paid |
| `test_blocked_skill_reverts_and_vault_is_untouched` | The host obeys the registry |
| `test_non_operator_cannot_execute` | Caller binding on execution |
| `test_warn_executes_and_is_recorded_as_warn` | Held-but-standard deployments run and the record says so |
| `test_restored_skill_executes_again` | Restoration is real |
| `test_unknown_capability_fails_closed` | Anything but allowed or warn refuses |
| `test_execute_cannot_overdraw_the_vault` | Conservation enforced as a precondition |
