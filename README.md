# Quarantine

**One package gets compromised. Who is exposed?**

When an agent skill is compromised, Quarantine decides which registered deployments are materially exposed, including wrapper skills that vendor it, and the capability host refuses to run them until a verified fix is pinned.

Validators read the code. The host obeys.

Live on GenLayer Studio Network (chainId 61999).

**Live app:** https://quarantine-genlayer.vercel.app

- `/` the primitive at a glance, with the animated Containment Map
- `/console` the product: every package, advisory, propagation and deployment read live from chain, plus every write action
- `/how-it-works` the pipeline, the four decision tables, every guard and the honest limitations
- `/guide` both live runs, then a twelve-step path any reviewer can run with the built-in demo wallet, no install and no funds

> **Reviewers:** the fastest proof is the Guide's "Run it yourself" path. A demo wallet registers its own deployment on the compromised 1.1, is blocked by hash, is refused at payout with `skill is quarantined`, re-pins and stays blocked, is restored by reassessment, then pays with exact conservation. Steps 9 to 12 show a wrapper inheriting exposure, and two wrapper releases carrying identical vendored bytes ending with opposite outcomes. Every refusal you see is a deliberate guard, and the table under "Reviewer guide" lists them all.

---

## What V2 adds

V1 (accepted) contained direct deployments. V2 adds one new load-bearing consensus question and closes two published limitations.

**Transitive exposure (new consensus question).** A wrapper skill vendors a copy of an upstream package. Which upstream version each wrapper release carries is decided in code, by hash. Whether the wrapper still exposes a vendored flaw to its callers, or neutralizes it, is something code cannot answer, so validators read the wrapper's own code and its vendored copy. On chain, two wrapper releases carrying the identical compromised file were judged opposite ways: one exposed, one neutralized.

**Tag-verified labels (closes a V1 limitation).** Every version is fetched at its commit and at its git tag of the same name. The bytes must match, so a maintainer can no longer call any commit "1.2".

**Advisory withdrawal and amendment (closes a V1 limitation).** A follow-up advisory can withdraw or amend an open one. Validators judge which. A withdrawal lifts containment, including everything inherited through wrappers. An amendment opens a successor, and the old advisory's blocks hold for each deployment until the successor has assessed it, so an amendment can never quietly unblock anything.

## Why this needs GenLayer

Supply-chain compromise is a contested-truth problem.

A maintainer says only 1.1 is affected.
A fork says it cherry-picked the fix.
A wrapper says it vendors the package but filters the output.

Someone has to decide which of those claims is true before capabilities are cut or restored. Today that is a security team, a registry operator or a single scanner. Any of them can be wrong, slow or captured.

Quarantine moves that decision to independent validators reading the actual code and the actual advisory, and the capability host obeys the result.

Remove GenLayer and a trusted operator decides who gets disabled. The trust model collapses.

## The honest boundary: hash or consensus

Where a deployment pins exact bytes that match a registered version, exposure is decided **in code**, by sha256 match. Which upstream version a wrapper vendors is decided the same way. No consensus is spent.

Consensus is reserved for the five questions code cannot answer:

1. **Prose advisories.** Validators turn markdown into affected and patched versions, and code applies them.
2. **Divergent forks.** A deployment pins bytes that match no registered version. Validators judge whether the vulnerable pattern is still present.
3. **Claimed patches.** Validators judge executable code only. Comments, docstrings and version strings carry no weight.
4. **Wrappers.** Validators judge whether a wrapper exposes or neutralizes the flaw in what it vendors.
5. **Follow-ups.** Validators judge whether a new advisory withdraws, amends or is unrelated to an earlier one.

Where a structured feed such as OSV exists and every dependent pins a registered version, a plain contract would do. Quarantine says so.

## The five states

| State | Meaning | Capability |
|---|---|---|
| `QUARANTINED` | Exposed, and no patched version exists | blocked |
| `PATCH_REQUIRED` | Exposed, and a patched version exists | blocked |
| `UNAFFECTED` | Not exposed | allowed |
| `EVIDENCE_CONFLICT` | Validators could not decide, the file is too large to judge whole, or the wrapper release's inherited exposure is still unclear | warn (standard posture) or blocked (strict posture) |
| `RESTORED` | Was contained under this advisory, now verified clear | allowed |

Uncertain cases are **held**, never auto-disabled, unless the deployment itself chose `strict` posture at registration. A derived advisory that is still waiting for wrapper verdicts makes its deployments **warn**, never block.

## Architecture

Two Python Intelligent Contracts. The V1 registry is archived byte for byte at `contracts/v1/quarantine_registry.py`.

**`contracts/quarantine_registry.py`** (V2) decides exposure.

- `register_package` locks the repo, skill file path and advisory folder, fetches every version at its commit and at its tag and requires identical bytes. A wrapper also names an upstream package and a locked vendor path; each release's vendored copy is hash-matched against the upstream's registered sources. A vendoring package's version identity covers the skill file and the vendored file together.
- `add_version` (maintainer only) does the same for one more version.
- `register_dependent` registers a deployment pinned to a commit, with a `standard` or `strict` posture. The caller becomes the owner.
- `repin_dependent` (owner only) changes the pin. It changes no status. Every existing assessment goes stale and a stale assessment blocks until reassessed.
- `report_advisory` (permissionless) accepts only a commit-pinned `.md` file inside the locked advisory folder of the locked repo, rejects replays, and runs consensus extraction.
- `report_followup` (permissionless) runs consensus on how a new advisory relates to an open one: withdraws, amends or unrelated.
- `propagate` (permissionless) creates a derived advisory on a wrapper. Releases vendoring a clean upstream are cleared by hash. Each release vendoring an affected upstream is judged by validators: exposed, neutralized or unclear. The derived advisory stays pending until every release has a verdict.
- `escalate_propagation` (permissionless) runs a forcing pass on an unclear wrapper release. One per release.
- `assess_dependent` (permissionless) fetches the pinned code. Hash match decides in code. No match goes to validators.
- `escalate` (permissionless) runs a forcing pass on an evidence conflict. One per piece of evidence.
- `get_capability` returns `allowed`, `warn` or `blocked`, following superseded advisories until their successor has assessed a deployment and ignoring anything withdrawn.

**`contracts/skill_runner.py`** is the capability host, unchanged from V1.

- Internal GEN ledger with an issuer-only, capped mint.
- `bind_skill` binds a wallet as operator only if the registry says that wallet owns the deployment.
- `execute` reads `get_capability` before every payout. `blocked` reverts with `skill is quarantined` and the vault is untouched.
- Every cross-contract call is a view read. Zero cross-contract writes.

## Deployed contracts (Studio, chainId 61999)

| Contract | V2 (live product) | V1 (accepted, kept live) |
|---|---|---|
| Registry | `0xbf8f8d22155083fA06a5Efe866c7aB029368086D` | `0xbE5BeB80AE04F5F363F2bf371607EAd61cbC894a` |
| Skill runner | `0x14f4CdeAFB5F2EFF51a31538D647F558fDA800F5` | `0xE7d2f39B6CC7F3Bdeb71f53D26CB206153644A5a` |

Each runner was deployed with its registry address as the constructor argument, issuer `0x7BbCac9c77aABC2acA19Cd34F944fbC015F06a54`, max supply 10000.

## Live proof runs

### V1, on the V1 contracts

| Step | Action | Result |
|---|---|---|
| 1 | Register `payout_skill` with versions 1.0, 1.1, 1.2 | three hashes stored |
| 2 | Register four dependents | A on 1.1, B on 1.0, C on fork-unfixed (strict), D on fork-fixed |
| 3 | Report ADV-001 | `OPEN`, affected `1.1`, patched `1.2` |
| 4 | Assess all four | A `PATCH_REQUIRED` by hash, B `UNAFFECTED` by hash, C `PATCH_REQUIRED` by consensus, D `UNAFFECTED` by consensus |
| 5 | Execute through A, then B | A reverts `skill is quarantined`, B pays |
| 6 | A re-pins to 1.2, executes again | still reverts |
| 7 | A bystander wallet reassesses A | `RESTORED` |
| 8 | Execute through A | pays |

**V1 bystander restore receipt:** https://explorer-studio.genlayer.com/tx/0x92972310f8d2b37d0038216bb6d58fc2361c95dbdc245c6d1c1336c23344fd74

### V2, on the V2 contracts

| Step | Action | Result |
|---|---|---|
| 1 | Register `payout_skill` (package 2) | every version's bytes matched at its commit and its tag |
| 2 | Register wrapper `batch_payout` (package 3) vendoring package 2 | vendored versions detected by hash: 2.0 and 2.1 carry 1.1, 2.2 carries 1.2 |
| 3 | Register deployments | B on 1.0, W0 on 2.0, W1 on 2.1, W2 on 2.2 |
| 4 | Report ADV-001 | `OPEN` |
| 5 | Propagate ADV-001 into the wrapper | 2.2 clean by hash; validators judged 2.0 `exposed` and 2.1 `neutralized` |
| 6 | Assess the wrapper deployments | W0 `PATCH_REQUIRED`, W1 and W2 `UNAFFECTED`, all by hash, no consensus |
| 7 | Execute through W0, then W1 | W0 reverts `skill is quarantined`, W1 pays |
| 8 | Report ADV-002 and ADV-003, which wrongly name 1.0 | B `PATCH_REQUIRED` by hash: the false positive |
| 9 | Withdraw both through follow-ups | validators judged both full withdrawals; B released |

Package 1 on the V2 registry is an identical registration of `payout_skill` by a different wallet. The registry is open to anyone, so that is allowed. The run used package 2.

**V2 bystander withdrawal receipt.** The same wallet with no role filed the ADV-003 withdrawal that released B:

https://explorer-studio.genlayer.com/tx/0x0e2c31c7d906ffa41e6138fdfdeb2131c6555d661ce4c6273fdc7a89180750cb

## Trust model

- **Caller binding everywhere.** Maintainer, owner and operator are always `gl.message.sender_address`, never a passed argument.
- **No status setter exists.** A test parses the contract and asserts the full list of write methods.
- **Evidence sources are locked.** Repo, skill path, vendor path and advisory folder are fixed at registration. Every URL is commit-pinned.
- **Labels are tag-verified.** A version's bytes must match at its commit and at its tag.
- **Vendoring is proven, not asserted.** Which upstream version a wrapper carries is a hash match.
- **Nothing unblocks quietly.** Re-pins go stale and block. Amendments hold old blocks until the successor assesses. Pending derived advisories warn.
- **Replay is closed.** Advisory and follow-up URLs are one-shot. One escalation per piece of evidence and per wrapper release.
- **Never truncates evidence.** A file over 12,000 characters is held, not judged on a fragment.
- **Model output is parsed defensively.** Fences stripped, unreadable output reverts, the string `"false"` is never true.
- **Scarce issuance.** Only the issuer mints, never past max supply.
- **Permissionless lifecycle.** Proven in tests and by two bystander receipts.

## Reviewer guide: guards that revert by design

| Message | Why it reverts |
|---|---|
| `skill is quarantined` | The registry reports this deployment as blocked |
| `skill is not bound` / `only the bound operator can execute this skill` | Operator binding on the runner |
| `only the dependent owner can bind this skill` | Ownership is read from the registry |
| `only the issuer can mint` / `mint would exceed max supply` | Scarce issuance |
| `vault balance is too low` | A fresh runner starts empty until the issuer mints |
| `version X does not match the repo tag X` | The label's git tag points at different bytes |
| `a vendor path needs an upstream package` / `unknown upstream package` | Vendoring must name a real upstream |
| `advisory is not open` | Rejected, pending, withdrawn or superseded advisories contain no one |
| `the upstream advisory is no longer in force` | The inheritance lapsed because the upstream was withdrawn |
| `that package does not vendor this advisory's package` | Propagation only reaches real wrappers |
| `this version needs no judgment` | A clean or already-judged wrapper release is never re-judged |
| `only an unclear version can be escalated` | Propagation escalation only settles held releases |
| `this conflict is inherited; escalate the wrapper version's propagation instead` | The fix lives one level up |
| `only an open advisory can be withdrawn or amended` / `a derived advisory follows its upstream advisory` | Follow-ups apply to root advisories in force |
| `this advisory url was already reported` | Replay, for advisories and follow-ups alike |
| `only an evidence conflict can be escalated` / `this evidence has already been escalated` | Escalation discipline |
| `pin changed since the assessment; reassess first` | Escalation applies to the assessed pin only |
| `only the package maintainer can add versions` / `only the dependent owner can re-pin` | Caller binding |

## Demo fixtures

Package repo: https://github.com/DaveDave-infosec/quarantine-demo-skills (tags `1.0`, `1.1`, `1.2`)

| Label | Commit | Content |
|---|---|---|
| 1.0 | `79a8f05a1ec435c05eeae071ac09d908cb1c6a5a` | safe |
| 1.1 | `f81f6ca103c7fe3f43ed1ffda59b2219dd3d4bb5` | skims 150 bps to a hardcoded address as a "relay fee" |
| 1.2 | `9fd9ebac5e70f74cf36d440e3a4314d786ad5296` | patched, plus a declared-recipients-only guard |
| ADV-001 | `17bf5f1a1c9aec6bbfd5d194ee0dcc6b849f8316` | prose advisory: 1.1 affected, 1.2 fixed |
| ADV-002 | `b506da1bae7affa07f515c049c18bdbea585ff17` | mistaken: claims 1.0 is affected |
| ADV-002-withdrawn | `541bdd74b8d9f887e736b6a7204c3b71fde185e5` | retracts ADV-002 |
| ADV-003 | `1415f3685216a9eccae15fad3acdb36c339b1092` | mistaken scanner report on 1.0 |
| ADV-003-withdrawn | `b4099d931efce9cc9125d3ebd2b4dbabce53564c` | retracts ADV-003 |

Fork repo: https://github.com/DaveDave-infosec/quarantine-demo-fork

| Name | Commit | Content |
|---|---|---|
| fork-unfixed | `14d5f30342490bdeb78f4efdfb5bc595b8fc9f40` | renamed and restyled, skim kept as an "ops reserve" |
| fork-fixed | `c08f8a0cba36d1755fc846df5f36094ebb426fa3` | fix cherry-picked in a different style |

Wrapper repo: https://github.com/DaveDave-infosec/quarantine-demo-wrapper (tags `2.0`, `2.1`, `2.2`)

| Label | Commit | Content |
|---|---|---|
| 2.0 | `762e39abe834bd450eef6ff898d2289813060cb9` | vendors 1.1 and calls it raw |
| 2.1 | `95dc3370af01cdeda28a6bc7ca2a0c23e45370a1` | vendors 1.1, keeps only transfers to declared recipients |
| 2.2 | `37688b756a50583d148e13444de5cd4a81c54417` | vendors 1.2 |

## Tests

70 tests, 0 skipped, all against the real contract code on the gltest direct runner: 39 registry tests carried over from V1 and run against the V2 contract, 22 V2 tests, and 9 skill runner tests. See [TESTING.md](TESTING.md) for the map from each test to the property it proves.

```
pip install "genlayer-test[sim]" pytest
python -m pytest tests/ -v
```

## Honest limitations

- A package is one skill file, plus one vendored upstream file for a wrapper. Multi-file skills are future work.
- Chains work hop by hop: a wrapper of a wrapper needs its own propagate call. Nothing propagates by itself.
- Assessment and propagation are triggered by transactions. An open advisory that has not assessed a deployment reports warn, never allowed.
- A follow-up must come from the package's own locked advisory folder, so the repo's maintainer can still author a withdrawal. Validators judge what it says, not who wrote it.
- Consensus judges whether a described vulnerable pattern is present or neutralized. It does not execute code and does not claim to find new vulnerabilities.
- Timestamps are client-supplied labels for display, not consensus inputs.

## V3 roadmap

- **Multi-file skills,** with the version identity covering a locked manifest of files.
- **Sweeps,** one permissionless call that propagates and assesses a whole dependency subtree within a bounded budget.
- **Reporter bonds,** if griefing with mistaken advisories appears in practice.
