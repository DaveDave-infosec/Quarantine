# Quarantine

**One package gets compromised. Who is exposed?**

When an agent skill is compromised, Quarantine decides which registered deployments are materially exposed, and the capability host refuses to run them until a verified fix is pinned.

Validators read the code. The host obeys.

Live on GenLayer Studio Network (chainId 61999).

---

## Why this needs GenLayer

Supply-chain compromise is a contested-truth problem.

A maintainer says only 1.1 is affected.
A fork says it cherry-picked the fix.
A deployment says it is on a patched commit.

Someone has to decide which of those claims is true before capabilities are cut or restored. Today that is a security team, a registry operator or a single scanner. Any of them can be wrong, slow or captured.

Quarantine moves that decision to independent validators reading the actual code and the actual advisory, and the capability host obeys the result.

Remove GenLayer and a trusted operator decides who gets disabled. The trust model collapses.

## The honest boundary: hash or consensus

Where a deployment pins exact bytes that match a registered version, exposure is decided **in code**, by sha256 match. No consensus is spent.

Consensus is reserved for the three questions code cannot answer:

1. **Prose advisories.** Agent-skill ecosystems publish advisories as markdown, not structured feeds. Validators turn the prose into affected and patched versions, and code applies them.
2. **Divergent forks.** A deployment pins a fork commit whose bytes match no registered version. Validators read that code and judge whether the vulnerable pattern is still present.
3. **Unverified patches.** A fork claims to fix the issue. Validators judge the executable code only. Comments, docstrings and version strings carry no weight.

Where a structured feed such as OSV exists and every dependent pins a registered version, a plain contract would do. Quarantine says so. The hash path exists precisely so consensus is only spent where it is load-bearing.

## The five states

| State | Meaning | Capability |
|---|---|---|
| `QUARANTINED` | Exposed, and no patched version exists | blocked |
| `PATCH_REQUIRED` | Exposed, and a patched version exists | blocked |
| `UNAFFECTED` | Not exposed | allowed |
| `EVIDENCE_CONFLICT` | Validators could not decide, or the file is too large to judge without truncation | warn (standard posture) or blocked (strict posture) |
| `RESTORED` | Was contained under this advisory, now verified clear | allowed |

Uncertain cases are **held**, never auto-disabled, unless the deployment itself chose `strict` posture at registration.

## Architecture

Two Python Intelligent Contracts.

**`contracts/quarantine_registry.py`** decides exposure.

- `register_package` locks the repo prefix, skill file path and advisory directory forever, fetches every version and stores the sha256 of its bytes. The caller becomes the maintainer.
- `add_version` (maintainer only) fetches and hashes another version.
- `register_dependent` registers a deployment pinned to a commit in the package repo or a fork, with a `standard` or `strict` posture. The caller becomes the owner.
- `repin_dependent` (owner only) changes the pin. **It changes no status.** Every existing assessment goes stale and a stale assessment blocks until reassessed.
- `report_advisory` (permissionless) accepts only a commit-pinned `.md` file inside the locked advisory directory of the locked repo, rejects replays, and runs consensus extraction into affected labels, patched labels and the vulnerable pattern.
- `assess_dependent` (permissionless) fetches the pinned file. Hash match decides in code. No match goes to validators with the advisory pattern, the affected version, the patched version and the deployment file.
- `escalate` (permissionless) runs a sharper forcing pass on an `EVIDENCE_CONFLICT`. It must commit to exposed or not exposed, or honestly return unresolved. One escalation per piece of evidence.
- `get_capability` returns `allowed`, `warn` or `blocked`.

**`contracts/skill_runner.py`** is the capability host, where value is at stake.

- Internal GEN ledger with an issuer-only, capped mint. No open faucet.
- `bind_skill` binds a wallet as a deployment's operator only if the registry says that wallet owns it.
- `execute` reads `get_capability` from the registry before every payout. `blocked` reverts with `skill is quarantined` and the vault is untouched.
- Every cross-contract call is a view read. Zero cross-contract writes.

## Deployed contracts (Studio, chainId 61999)

| Contract | Address |
|---|---|
| Registry | `0xbE5BeB80AE04F5F363F2bf371607EAd61cbC894a` |
| Skill runner | `0xE7d2f39B6CC7F3Bdeb71f53D26CB206153644A5a` |

The runner was deployed with the registry address as its constructor argument, issuer `0x7BbCac9c77aABC2acA19Cd34F944fbC015F06a54`, max supply 10000.

## Live proof run

The whole primitive in eight on-chain steps, run on the contracts above.

| Step | Action | Result |
|---|---|---|
| 1 | Register `payout_skill` with versions 1.0, 1.1, 1.2 | package `1`, three hashes stored |
| 2 | Register four dependents | A on 1.1, B on 1.0, C on fork-unfixed (strict), D on fork-fixed |
| 3 | Report ADV-001 | `OPEN`, affected `1.1`, patched `1.2` |
| 4 | Assess all four | A `PATCH_REQUIRED` by hash, B `UNAFFECTED` by hash, C `PATCH_REQUIRED` by consensus, D `UNAFFECTED` by consensus |
| 5 | Execute through A, then B | A reverts `skill is quarantined`, B pays |
| 6 | A re-pins to 1.2, execute again | still reverts `skill is quarantined` |
| 7 | A bystander wallet reassesses A | `RESTORED` |
| 8 | Execute through A | pays |

Final ledger: minted 1000, vault 900, paid out 100 across 2 executions. Exact conservation.

**Bystander restore receipt.** Wallet `0xD7cd43cBc01f767A74909943Cec29e20dB4e7cc3` is not the maintainer, not a dependent owner, not the issuer and not the deployer. It reassessed Dependent A and restored it:

https://explorer-studio.genlayer.com/tx/0x92972310f8d2b37d0038216bb6d58fc2361c95dbdc245c6d1c1336c23344fd74

## Trust model

- **Caller binding everywhere.** Maintainer, owner and operator are always `gl.message.sender_address`, never a passed argument.
- **No status setter exists.** No method lets anyone, including the deployer, write a state directly. A test parses the contract and asserts the full list of write methods.
- **Evidence sources are locked at registration.** Reporters cannot point the contract at arbitrary URLs. Every URL is commit-pinned, so the bytes cannot change underneath a verdict.
- **Re-pin cannot unblock.** Only a fresh assessment can.
- **Replay is closed.** A duplicate advisory URL reverts. One escalation per assessed file hash.
- **Never truncates evidence.** A file over 12,000 characters is held as `EVIDENCE_CONFLICT`, not judged on a fragment.
- **Model output is parsed defensively.** Markdown fences are stripped, unreadable output reverts, and the string `"false"` is never treated as true.
- **Scarce issuance.** Only the issuer mints, never past max supply.
- **Permissionless assessment.** Proven in tests and by the bystander receipt above.

## Reviewer guide: guards that revert by design

These are deliberate refusals, not crashes.

| Message | Why it reverts |
|---|---|
| `skill is quarantined` | The registry reports this deployment as blocked |
| `skill is not bound` | The deployment owner has not called `bind_skill` on the runner |
| `only the bound operator can execute this skill` | Caller is not the bound operator |
| `only the dependent owner can bind this skill` | Caller does not own the deployment in the registry |
| `only the issuer can mint` / `mint would exceed max supply` | Scarce issuance |
| `vault balance is too low` | A fresh runner starts empty. The issuer must mint first |
| `advisory is not open` | The advisory was rejected at intake, so it cannot contain anyone |
| `dependent does not use this package` | Advisory and deployment belong to different packages |
| `this advisory url was already reported` | Replay |
| `advisory must come from the package repo` / `...advisory directory` / `...lowercase commit sha` | Evidence source is locked |
| `only an evidence conflict can be escalated` | Escalation exists only to resolve held cases |
| `this evidence has already been escalated` | One forcing pass per piece of evidence |
| `pin changed since the assessment; reassess first` | Escalation applies to the assessed pin only |
| `only the package maintainer can add versions` / `only the dependent owner can re-pin` | Caller binding |

## Demo fixtures

Package repo: https://github.com/DaveDave-infosec/quarantine-demo-skills

| Label | Commit | Content |
|---|---|---|
| 1.0 | `79a8f05a1ec435c05eeae071ac09d908cb1c6a5a` | safe |
| 1.1 | `f81f6ca103c7fe3f43ed1ffda59b2219dd3d4bb5` | skims 150 bps to a hardcoded address as a "relay fee" |
| 1.2 | `9fd9ebac5e70f74cf36d440e3a4314d786ad5296` | patched, plus a declared-recipients-only guard |
| ADV-001 | `17bf5f1a1c9aec6bbfd5d194ee0dcc6b849f8316` | prose advisory in `security/` |

Fork repo: https://github.com/DaveDave-infosec/quarantine-demo-fork

| Name | Commit | Content |
|---|---|---|
| fork-unfixed | `14d5f30342490bdeb78f4efdfb5bc595b8fc9f40` | renamed and restyled, skim kept as an "ops reserve" |
| fork-fixed | `c08f8a0cba36d1755fc846df5f36094ebb426fa3` | fix cherry-picked in a different style |

## Tests

48 tests, 0 skipped, all against the real contract code on the gltest direct runner. See [TESTING.md](TESTING.md) for the map from each test to the trust property it proves.

```
pip install "genlayer-test[sim]" pytest
python -m pytest tests/ -v
```

## Honest limitations

- V1 handles one skill file per package and direct dependents only. Transitive exposure is V2.
- Version label to commit mapping is asserted by the maintainer at registration. The contract proves each commit exists and hashes it, but it does not prove the label is semantically correct.
- Assessment is triggered by a transaction. Nothing wakes itself. An open advisory that has not yet been assessed for a deployment reports `warn`, not `allowed`.
- No advisory withdrawal in V1. Restoration happens only through a verified re-pin or a committed escalation.
- Consensus judges whether a described vulnerable pattern is present. It does not execute code and does not claim to find new vulnerabilities.
- Timestamps are client-supplied labels for display, not consensus inputs.

## V2 roadmap

**Transitive exposure.** V1 judges direct dependents. V2 lets dependents themselves be packages and adds consensus over propagation: if A is compromised, B vendors A, and C depends on B, is C materially exposed? B may have wrapped the vulnerable call, shimmed it or patched it locally. That is a new load-bearing consensus question.

Alongside it: advisory supersede and withdrawal with fetched proof, multi-file skills, and a reporter bond if griefing appears in practice.
