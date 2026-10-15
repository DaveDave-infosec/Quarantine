# Testing

70 tests, 0 skipped. Every test drives the real contract code.

## Run

```
pip install "genlayer-test[sim]" pytest
python -m pytest tests/ -v
```

## Harness

- gltest **direct** in-process runner (`gltest.direct`), fully offline, no keys, no gas.
- GenVM SDK pinned to `v0.2.16` in `tests/qhelp.py` (later release tags renamed the runner asset).
- Skill files, vendored copies, tag paths and advisories are served with `vm.mock_web`, matched on the exact URL.
- Consensus answers are supplied through `vm._gl_call_hook` by answering the `ExecPromptTemplate` request. The contract's own parsing, validation and state logic runs on that answer.
- The runner's view reads of the registry are answered through `vm._gl_call_hook` on `CallContract`.
- Hash-path and propagation tests pass a hook that records every model request and assert the record is empty where no consensus should be spent. "No consensus spent" is proven, not assumed.
- Root `conftest.py` holds two runner fixes only: a Windows temp-file unlink shim and a contract-cache reset between tests.
- Contract asserts surface as `AssertionError`.

## What each test proves

### Registry: registration and caller binding (`tests/test_registry.py`)

| Test | Property |
|---|---|
| `test_register_package_locks_sources_and_version_hashes` | Sources locked; each version's sha256 stored from fetched bytes; caller is maintainer |
| `test_two_versions_with_identical_bytes_are_rejected` | Hash-to-label mapping is never ambiguous |
| `test_only_the_maintainer_can_add_a_version` | Caller binding on versions |
| `test_only_the_owner_can_repin_a_dependent` | Caller binding on pins |

### Registry: advisory intake

| Test | Property |
|---|---|
| `test_advisory_outside_the_locked_repo_is_rejected` | Evidence source locked |
| `test_malformed_advisory_url_is_rejected_before_any_consensus` (8 cases) | Bad URLs revert before any model call |
| `test_replaying_the_same_advisory_url_reverts` | Replay closed |
| `test_advisory_naming_unknown_versions_is_rejected_unmapped` | Unknown versions contain nobody |
| `test_advisory_about_another_package_is_rejected_not_applicable` | Off-target advisories contain nobody |
| `test_oversized_advisory_is_rejected_without_consensus` | Size cap before consensus |
| `test_fenced_json_opens_and_string_false_is_not_truthy` | Fenced output parses; `"false"` is never true |
| `test_unreadable_model_output_reverts` | Unreadable output never becomes a verdict |

### Registry: hash path

| Test | Property |
|---|---|
| `test_registered_affected_pin_is_patch_required_and_llm_is_never_called` | Exact pin resolves by hash with zero model calls |
| `test_affected_pin_with_no_patch_is_quarantined` | No patch means `QUARANTINED` |
| `test_unaffected_registered_pin_is_never_contained` | False-positive guard |
| `test_fork_byte_identical_to_affected_version_resolves_by_hash` | A byte-copied fork is caught by hash |

### Registry: consensus path

| Test | Property |
|---|---|
| `test_divergent_fork_judged_exposed_is_patch_required` | One consensus call; minority note stored |
| `test_divergent_fork_judged_not_exposed_is_unaffected` | Real fixes clear |
| `test_unclear_verdict_is_held_as_evidence_conflict_not_disabled` | Uncertainty is held |
| `test_strict_posture_blocks_on_evidence_conflict` | The deployment's own risk tolerance applies |
| `test_oversized_dependent_file_is_held_and_never_truncated` | Never judged on a fragment |

### Registry: escalation

| Test | Property |
|---|---|
| `test_escalation_commits_and_restores_a_held_deployment` | Forcing pass resolves, run by a bystander |
| `test_escalation_can_commit_to_exposed` | Forcing pass can contain |
| `test_unresolved_escalation_keeps_conflict_and_cannot_be_replayed` | Honest deadlock; one escalation per evidence |
| `test_only_an_evidence_conflict_can_be_escalated` | Escalation cannot reopen a decided case |

### Registry: re-pin semantics

| Test | Property |
|---|---|
| `test_repin_alone_never_unblocks` | Re-pin marks stale and stays blocked |
| `test_repin_to_patched_then_reassess_restores` | Bystander reassessment restores |
| `test_repin_to_another_affected_version_stays_blocked` | Hopping between affected versions does not escape |
| `test_repin_away_from_a_cleared_pin_blocks_until_reassessed` | A cleared deployment cannot quietly switch pins |

### Registry: no operator, anywhere

| Test | Property |
|---|---|
| `test_bystander_assessment_matches_a_party_assessment` | Permissionless assessment; assessor recorded |
| `test_deployer_has_no_status_power` | Deployer gets the same result as a bystander |
| `test_contract_exposes_no_status_setter` | Parses the contract and asserts the exact set of ten write methods |

### V2: tag-verified labels (`tests/test_v2.py`)

| Test | Property |
|---|---|
| `test_a_version_must_match_the_repo_tag_of_the_same_name` | A label whose tag points at other bytes is rejected |
| `test_a_missing_tag_rejects_the_version` | No tag, no version |

### V2: vendoring

| Test | Property |
|---|---|
| `test_wrapper_registration_detects_vendored_versions_by_hash` | Which upstream version each release carries is a hash match |
| `test_a_vendor_path_needs_a_known_upstream_and_its_own_path` | Vendoring must name a real upstream and a distinct path |
| `test_swapping_only_the_vendored_file_never_matches_a_clean_version` | Version identity covers the vendored file too |

### V2: propagation

| Test | Property |
|---|---|
| `test_propagation_starts_pending_and_clears_clean_versions_without_consensus` | Clean releases cleared by hash, zero model calls; pending warns |
| `test_propagation_verdicts_open_the_derived_advisory` | Verdicts open the derived advisory with the right lists |
| `test_wrapper_deployments_resolve_by_hash_under_the_derived_advisory` | Wrapper deployments resolve by hash, zero model calls |
| `test_clean_versions_are_never_judged_and_verdicts_are_never_rejudged` | No re-judging, no judging what is clean |
| `test_an_unclear_wrapper_is_held_and_only_propagation_escalation_settles_it` | Inherited uncertainty holds; only the wrapper-level escalation settles it, once |
| `test_an_unresolved_propagation_escalation_stays_held_and_runs_once` | Honest deadlock at the wrapper level |
| `test_a_fully_neutralized_wrapper_inherits_nothing` | Neutralized releases clear the whole wrapper |
| `test_propagation_only_reaches_packages_that_vendor_the_upstream` | Propagation cannot target unrelated packages |
| `test_withdrawing_the_upstream_advisory_lifts_every_inherited_block` | Withdrawal cascades through derived advisories |

### V2: follow-up advisories

| Test | Property |
|---|---|
| `test_a_withdrawal_releases_a_false_positive` | A false positive is released through consensus |
| `test_an_unrelated_followup_is_rejected_and_changes_nothing` | Unrelated follow-ups have no effect |
| `test_an_amendment_keeps_old_blocks_until_the_successor_assesses` | An amendment never quietly unblocks |
| `test_a_widening_amendment_never_unblocks_and_flags_new_versions` | Newly named versions warn, then block when assessed |
| `test_a_withdrawn_advisory_takes_no_followup` | Follow-ups apply to advisories in force |
| `test_a_derived_advisory_takes_no_followup` | Inheritance follows its upstream only |
| `test_a_followup_url_cannot_be_replayed` | Replay closed for follow-ups |
| `test_an_amendment_naming_unknown_versions_is_rejected` | Amendments obey the same label validation |

### Skill runner (`tests/test_runner.py`)

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
