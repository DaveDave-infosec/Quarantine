import { Link } from "react-router-dom";
import Shell from "../components/Shell";
import {
  REGISTRY_ADDRESS,
  RUNNER_ADDRESS,
  V1_REGISTRY_ADDRESS,
  V1_RUNNER_ADDRESS,
  CHAIN_LABEL,
  BYSTANDER_RECEIPT_TX,
  WITHDRAW_RECEIPT_TX,
  REPO_URL,
  txUrl,
} from "../lib/contracts";
import "../docs.css";

const STAGES = [
  {
    n: "01",
    actor: "Anyone",
    open: true,
    method: "registry.register_package",
    title: "Register a package",
    body: "Locks the repo, the skill file path and the advisory folder forever. Every version is fetched at its commit and at its git tag of the same name, and the bytes must match. A wrapper also names its upstream package and a locked vendor path, and which upstream version each release carries is decided by hash. The caller becomes the maintainer.",
  },
  {
    n: "02",
    actor: "Anyone",
    open: true,
    method: "registry.register_dependent",
    title: "Register a deployment",
    body: "Pins a commit in the package repo or in a fork, and chooses a posture: standard (an evidence conflict warns) or strict (an evidence conflict blocks). The caller becomes the owner.",
  },
  {
    n: "03",
    actor: "Anyone",
    open: true,
    method: "registry.report_advisory",
    title: "Report an advisory",
    body: "Only a commit-pinned .md file inside the locked advisory folder of the locked repo is accepted. Validators turn the prose into affected versions, patched versions and the vulnerable pattern. Code then checks every label against the registered versions: anything unknown rejects the advisory instead of guessing.",
  },
  {
    n: "04",
    actor: "Anyone",
    open: true,
    method: "registry.propagate",
    title: "Propagate to wrappers",
    body: "Creates a derived advisory on a wrapper that vendors the advisory's package. Releases vendoring a clean upstream are cleared by hash at once. For each release vendoring an affected upstream, validators read the wrapper's own code and its vendored copy: exposed, neutralized or unclear. Until every release has a verdict, the derived advisory is pending and its deployments warn.",
  },
  {
    n: "05",
    actor: "Anyone",
    open: true,
    method: "registry.assess_dependent",
    title: "Assess a deployment",
    body: "Fetches the pinned code. If its hash matches a registered version, code decides with no consensus spent. If it matches nothing, validators read the executable code against the advisory and the affected and patched versions.",
  },
  {
    n: "06",
    actor: "Anyone",
    open: true,
    method: "registry.escalate / escalate_propagation",
    title: "Escalate a held case",
    body: "Only an evidence conflict, or an unclear wrapper release, can be escalated. A sharper forcing pass must commit, or honestly return unresolved. One escalation per piece of evidence.",
  },
  {
    n: "07",
    actor: "Anyone",
    open: true,
    method: "registry.report_followup",
    title: "File a follow-up",
    body: "Validators decide whether a new advisory withdraws an open one, amends it, or is unrelated. A withdrawal lifts containment, including everything inherited from it. An amendment opens a successor, and the old advisory's blocks hold for each deployment until the successor has assessed it.",
  },
  {
    n: "08",
    actor: "Bound operator",
    open: false,
    method: "skill_runner.execute",
    title: "The host obeys",
    body: "Before every payout the runner reads the deployment's capability from the registry. Blocked reverts with \"skill is quarantined\" and the vault is untouched. Allowed and warn pay, with exact conservation.",
  },
];

const TABLES: { badge: string; title: string; rows: [string, string][] }[] = [
  {
    badge: "#",
    title: "Hash path, decided in code",
    rows: [
      ["Matches an affected version, a patch exists", "PATCH_REQUIRED"],
      ["Matches an affected version, no patch", "QUARANTINED"],
      ["Matches a version whose inherited exposure is unclear", "EVIDENCE_CONFLICT"],
      ["Matches an unaffected version, never contained", "UNAFFECTED"],
      ["Matches an unaffected version, contained before", "RESTORED"],
    ],
  },
  {
    badge: "•••",
    title: "Consensus path, divergent forks",
    rows: [
      ["Validators judge it exposed", "PATCH_REQUIRED or QUARANTINED"],
      ["Validators judge it not exposed", "UNAFFECTED or RESTORED"],
      ["Validators cannot decide", "EVIDENCE_CONFLICT"],
      ["Pinned file over 12,000 characters", "EVIDENCE_CONFLICT, never truncated"],
    ],
  },
  {
    badge: "•••",
    title: "Propagation, wrapper releases",
    rows: [
      ["Release vendors a clean upstream", "clean, by hash"],
      ["Validators judge the wrapper still exposes it", "exposed"],
      ["Validators judge the wrapper neutralizes it", "neutralized"],
      ["Validators cannot decide", "unclear, held"],
    ],
  },
  {
    badge: "•••",
    title: "Follow-ups, advisory lifecycle",
    rows: [
      ["Validators judge it a full retraction", "WITHDRAWN"],
      ["Validators judge it a correction", "SUPERSEDED, successor OPEN"],
      ["Validators judge it unrelated", "rejected, nothing changes"],
    ],
  },
];

const GUARDS: [string, string][] = [
  ["skill is quarantined", "The registry reports this deployment as blocked"],
  ["skill is not bound", "The owner has not bound the deployment on the runner"],
  ["only the bound operator can execute this skill", "Caller is not the bound operator"],
  ["only the dependent owner can bind this skill", "Caller does not own the deployment in the registry"],
  ["only the issuer can mint / mint would exceed max supply", "Scarce issuance"],
  ["version X does not match the repo tag X", "The label's git tag points at different bytes"],
  ["a vendor path needs an upstream package", "Vendoring must name what it vendors"],
  ["advisory is not open", "Rejected, pending, withdrawn or superseded advisories contain no one"],
  ["the upstream advisory is no longer in force", "Its upstream was withdrawn, so the inheritance lapsed"],
  ["that package does not vendor this advisory's package", "Propagation only reaches real wrappers"],
  ["this version needs no judgment", "A clean or already-judged release is never re-judged"],
  ["only an unclear version can be escalated", "Escalation exists only to settle held releases"],
  ["this conflict is inherited; escalate the wrapper version's propagation instead", "The fix lives one level up"],
  ["only an open advisory can be withdrawn or amended", "Follow-ups apply to advisories in force"],
  ["a derived advisory follows its upstream advisory", "Withdraw the upstream, and the inheritance follows"],
  ["this advisory url was already reported", "Replay, for advisories and follow-ups alike"],
  ["this evidence has already been escalated", "One forcing pass per piece of evidence"],
  ["only the dependent owner can re-pin", "Caller binding"],
];

const LIMITS = [
  "A package is one skill file, plus one vendored upstream file for a wrapper. Multi-file skills are future work.",
  "Chains work hop by hop: a wrapper of a wrapper needs its own propagate call. Nothing propagates by itself.",
  "Assessment and propagation are triggered by transactions. An open advisory that has not assessed a deployment reports warn, never allowed.",
  "A follow-up must come from the package's own locked advisory folder, so the repo's maintainer can still author a withdrawal. Validators judge what it says, not who wrote it.",
  "Consensus judges whether a described vulnerable pattern is present or neutralized. It does not execute code and does not claim to find new vulnerabilities.",
];

export default function HowItWorks() {
  return (
    <Shell variant="marketing">
      <section className="container page doc">
        <header className="page-head">
          <p className="eyebrow">
            <span className="eyebrow-dot" />
            How it works
          </p>
          <h1>The pipeline, step by step.</h1>
          <p className="lede">
            Two contracts. The registry decides exposure, including exposure inherited through a vendored dependency. The
            skill runner obeys. Every step below is a real contract method, and no step lets anyone set a status directly.
          </p>
        </header>

        <ol className="pipeline">
          {STAGES.map((s) => (
            <li className="stage" key={s.n}>
              <span className="stage-n">{s.n}</span>
              <div>
                <div className="stage-top">
                  <h3>{s.title}</h3>
                  <span className={"actor" + (s.open ? " anyone" : "")}>{s.actor}</span>
                </div>
                <p className="method mono">{s.method}</p>
                <p>{s.body}</p>
              </div>
            </li>
          ))}
        </ol>

        <section className="doc-block">
          <h2>How each question is decided</h2>
          <p>
            Every verdict records which path produced it, so you can always see whether a decision needed consensus.
          </p>
          <div className="decide-grid">
            {TABLES.map((t) => (
              <div className="decide" key={t.title}>
                <div className="decide-h">
                  <span className="badge-sm">{t.badge}</span>
                  {t.title}
                </div>
                <ul>
                  {t.rows.map(([when, then]) => (
                    <li key={when}>
                      <span>{when}</span>
                      <span>{then}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <p className="doc-after">
            A re-pin changes no state. It marks every existing assessment stale, and a stale assessment blocks until someone
            reassesses the new pin.
          </p>
        </section>

        <section className="doc-block">
          <h2>Guards that revert by design</h2>
          <p>These are deliberate refusals, not crashes. The console shows each one in the contract's own words.</p>
          <div className="doc-table-wrap">
            <table className="doc-table">
              <thead>
                <tr>
                  <th>Message</th>
                  <th>Why it reverts</th>
                </tr>
              </thead>
              <tbody>
                {GUARDS.map(([msg, why]) => (
                  <tr key={msg}>
                    <td className="mono">{msg}</td>
                    <td>{why}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="doc-block">
          <h2>Honest limitations</h2>
          <ul className="doc-list">
            {LIMITS.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </section>

        <section className="doc-block">
          <h2>Verify it yourself</h2>
          <div className="verify">
            <dl>
              <dt>V2 registry</dt>
              <dd className="mono">{REGISTRY_ADDRESS}</dd>
              <dt>V2 skill runner</dt>
              <dd className="mono">{RUNNER_ADDRESS}</dd>
              <dt>V1 registry</dt>
              <dd className="mono">{V1_REGISTRY_ADDRESS}</dd>
              <dt>V1 skill runner</dt>
              <dd className="mono">{V1_RUNNER_ADDRESS}</dd>
              <dt>Network</dt>
              <dd>{CHAIN_LABEL}</dd>
              <dt>V1 bystander restore</dt>
              <dd>
                <a href={txUrl(BYSTANDER_RECEIPT_TX)} target="_blank" rel="noreferrer">
                  View the receipt on the explorer
                </a>
              </dd>
              <dt>V2 bystander withdrawal</dt>
              <dd>
                <a href={txUrl(WITHDRAW_RECEIPT_TX)} target="_blank" rel="noreferrer">
                  View the receipt on the explorer
                </a>
              </dd>
              <dt>Source and tests</dt>
              <dd>
                <a href={REPO_URL} target="_blank" rel="noreferrer">
                  GitHub: contracts, 70 tests, TESTING.md
                </a>
              </dd>
            </dl>
            <div className="verify-actions">
              <Link to="/guide" className="btn btn-ink btn-sm">
                Walk the live run
              </Link>
              <Link to="/console" className="btn btn-ghost btn-sm">
                Open console
              </Link>
            </div>
          </div>
        </section>
      </section>
    </Shell>
  );
}
