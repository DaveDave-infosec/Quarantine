import { Link } from "react-router-dom";
import Shell from "../components/Shell";
import {
  REGISTRY_ADDRESS,
  RUNNER_ADDRESS,
  CHAIN_LABEL,
  BYSTANDER_RECEIPT_TX,
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
    body: "Locks the repo, the skill file path and the advisory folder forever. The contract fetches every version at its commit and stores the sha256 of the bytes. The caller becomes the maintainer.",
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
    method: "registry.assess_dependent",
    title: "Assess a deployment",
    body: "Fetches the pinned file. If its hash matches a registered version, code decides with no consensus spent. If it matches nothing, validators read the executable code against the advisory and the affected and patched versions.",
  },
  {
    n: "05",
    actor: "Anyone",
    open: true,
    method: "registry.escalate",
    title: "Escalate a held case",
    body: "Only an evidence conflict can be escalated. A sharper forcing pass must commit to exposed or not exposed, or honestly return unresolved. One escalation per piece of evidence.",
  },
  {
    n: "06",
    actor: "Bound operator",
    open: false,
    method: "skill_runner.execute",
    title: "The host obeys",
    body: "Before every payout the runner reads the deployment's capability from the registry. Blocked reverts with \"skill is quarantined\" and the vault is untouched. Allowed and warn pay, with exact conservation.",
  },
];

const HASH_RULES: [string, string][] = [
  ["Matches an affected version, and a patch exists", "PATCH_REQUIRED"],
  ["Matches an affected version, and no patch exists", "QUARANTINED"],
  ["Matches an unaffected version, was never contained", "UNAFFECTED"],
  ["Matches an unaffected version, was contained before", "RESTORED"],
];

const CONSENSUS_RULES: [string, string][] = [
  ["Validators judge it exposed", "PATCH_REQUIRED or QUARANTINED"],
  ["Validators judge it not exposed", "UNAFFECTED or RESTORED"],
  ["Validators cannot decide", "EVIDENCE_CONFLICT"],
  ["File over 12,000 characters", "EVIDENCE_CONFLICT, never truncated"],
];

const GUARDS: [string, string][] = [
  ["skill is quarantined", "The registry reports this deployment as blocked"],
  ["skill is not bound", "The owner has not bound the deployment on the runner"],
  ["only the bound operator can execute this skill", "Caller is not the bound operator"],
  ["only the dependent owner can bind this skill", "Caller does not own the deployment in the registry"],
  ["only the issuer can mint / mint would exceed max supply", "Scarce issuance"],
  ["vault balance is too low", "A fresh runner starts empty until the issuer mints"],
  ["advisory is not open", "The advisory was rejected at intake, so it contains no one"],
  ["this advisory url was already reported", "Replay"],
  ["advisory must come from the package repo", "Evidence source is locked"],
  ["only an evidence conflict can be escalated", "Escalation exists only to resolve held cases"],
  ["this evidence has already been escalated", "One forcing pass per piece of evidence"],
  ["only the dependent owner can re-pin", "Caller binding"],
];

const LIMITS = [
  "V1 handles one skill file per package and direct dependents only. Transitive exposure is the V2 roadmap.",
  "The label to commit mapping is asserted by the maintainer. The contract proves each commit exists and hashes it, but does not prove a label is semantically right.",
  "Assessment is triggered by a transaction. Nothing wakes itself. An open advisory that has not been assessed for a deployment reports warn, not allowed.",
  "There is no advisory withdrawal in V1. Restoration happens only through a verified re-pin or a committed escalation.",
  "Consensus judges whether a described vulnerable pattern is present. It does not execute code and does not claim to find new vulnerabilities.",
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
            Two contracts. The registry decides exposure. The skill runner obeys. Every step below is a real contract
            method, and no step lets anyone set a status directly.
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
          <h2>How an assessment decides</h2>
          <p>
            The same call takes one of two paths. Which path ran is stored with every verdict, so you can always see whether
            a decision needed consensus.
          </p>
          <div className="decide-grid">
            <div className="decide">
              <div className="decide-h">
                <span className="badge-sm">#</span>Hash path, decided in code
              </div>
              <ul>
                {HASH_RULES.map(([when, then]) => (
                  <li key={when}>
                    <span>{when}</span>
                    <span>{then}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="decide">
              <div className="decide-h">
                <span className="badge-sm">{"•••"}</span>Consensus path, decided by validators
              </div>
              <ul>
                {CONSENSUS_RULES.map(([when, then]) => (
                  <li key={when}>
                    <span>{when}</span>
                    <span>{then}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <p className="doc-after">
            A re-pin changes no state. It marks every existing assessment stale, and a stale assessment blocks until
            someone reassesses the new pin.
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
              <dt>Registry</dt>
              <dd className="mono">{REGISTRY_ADDRESS}</dd>
              <dt>Skill runner</dt>
              <dd className="mono">{RUNNER_ADDRESS}</dd>
              <dt>Network</dt>
              <dd>{CHAIN_LABEL}</dd>
              <dt>Bystander restore</dt>
              <dd>
                <a href={txUrl(BYSTANDER_RECEIPT_TX)} target="_blank" rel="noreferrer">
                  View the receipt on the explorer
                </a>
              </dd>
              <dt>Source and tests</dt>
              <dd>
                <a href={REPO_URL} target="_blank" rel="noreferrer">
                  GitHub: contracts, 48 tests, TESTING.md
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
