import { useState } from "react";
import type { Run } from "../../lib/useTx";
import type { DepView } from "../../lib/useRegistry";
import type { Package, State } from "../../lib/contracts";
import { assessDependent, escalate, repinDependent, bindSkill, executeSkill } from "../../lib/contracts";
import { STATE_COLOR, STATE_LABEL } from "../ContainmentMap";
import type { MapState } from "../ContainmentMap";
import { short, blobUrl, isSha, isAddr, isRawPrefix } from "../../lib/format";

interface Props {
  view: DepView;
  letter: string;
  pkg: Package;
  advisoryId: string;
  pinLabel: string;
  address: string | null;
  busy: boolean;
  run: Run;
}

const CAP_TEXT: Record<string, string> = {
  allowed: "Runs it",
  warn: "Runs it, flagged",
  blocked: "Refuses to run it",
};

const VIA_TEXT: Record<string, string> = {
  hash: "Decided in code by hash match, no consensus spent",
  consensus: "Decided by validator consensus",
  escalation: "Decided by a forcing pass",
  size: "Held: the file is too large to judge without truncating it",
};

export default function DependentCard({ view, letter, pkg, advisoryId, pinLabel, address, busy, run }: Props) {
  const { dep, assessments, operator } = view;
  const a = advisoryId ? assessments[advisoryId] : undefined;
  const exists = !!a && a.exists;
  const stale = !!a && !!a.stale;
  const state: MapState = exists && !stale && a?.state ? a.state : "PENDING";
  const color = state === "PENDING" ? "var(--faint)" : STATE_COLOR[state as State];
  const isOwner = !!address && address === dep.owner;
  const isOperator = !!address && address === operator;
  const canEscalate =
    exists && !stale && a?.state === "EVIDENCE_CONFLICT" && a?.conflict_reason !== "too_large";

  const [why, setWhy] = useState(false);
  const [tool, setTool] = useState<"" | "repin" | "execute">("");
  const [prefix, setPrefix] = useState(dep.repo_prefix);
  const [sha, setSha] = useState("");
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("10");
  const [formError, setFormError] = useState("");

  async function doRepin() {
    if (!isRawPrefix(prefix)) {
      setFormError("Repo prefix must be https://raw.githubusercontent.com/owner/repo/");
      return;
    }
    if (!isSha(sha)) {
      setFormError("The commit must be 40 hex characters.");
      return;
    }
    setFormError("");
    const ok = await run(`Re-pin deployment ${letter}`, () =>
      repinDependent(dep.id, prefix.trim(), sha.trim().toLowerCase()),
    );
    if (ok) {
      setSha("");
      setTool("");
    }
  }

  async function doExecute() {
    if (!isAddr(recipient)) {
      setFormError("Recipient must be 0x followed by 40 hex characters.");
      return;
    }
    const n = Number(amount);
    if (!Number.isInteger(n) || n <= 0) {
      setFormError("Amount must be a whole number above zero.");
      return;
    }
    setFormError("");
    await run(`Execute through deployment ${letter}`, () =>
      executeSkill(dep.id, recipient.trim().toLowerCase(), n),
    );
  }

  return (
    <article className={`dep-card s-${state.toLowerCase()}`}>
      <div className="dep-banner" style={{ borderTopColor: color }}>
        <span className="dep-state" style={{ color }}>
          {STATE_LABEL[state]}
        </span>
        <span className={`cap cap-${dep.capability}`}>{dep.capability}</span>
      </div>

      <div className="dep-body">
        <div className="dep-title">
          <span className="dep-letter">{letter}</span>
          <div>
            <div className="dep-name">
              Deployment {letter} <span className="mono dep-id">#{dep.id}</span>
            </div>
            <a
              className="mono dep-pin"
              href={blobUrl(dep.repo_prefix, dep.pinned_sha, pkg.source_path)}
              target="_blank"
              rel="noreferrer"
            >
              {pinLabel}
            </a>
          </div>
        </div>

        <dl className="dep-facts">
          <div>
            <dt>Posture</dt>
            <dd>{dep.posture}</dd>
          </div>
          <div>
            <dt>Owner</dt>
            <dd className="mono">
              {short(dep.owner)}
              {isOwner ? " (you)" : ""}
            </dd>
          </div>
          <div>
            <dt>Host</dt>
            <dd>{CAP_TEXT[dep.capability] ?? dep.capability}</dd>
          </div>
        </dl>

        {exists && !stale && a?.path && (
          <p className="dep-via">
            {VIA_TEXT[a.path] ?? a.path}.
            {a.matched_label ? ` Byte-identical to registered ${a.matched_label}.` : ""}
          </p>
        )}
        {stale && (
          <p className="dep-stale">Re-pinned since its last assessment. Blocked until someone reassesses it.</p>
        )}
        {!exists && advisoryId && (
          <p className="dep-via">Not assessed against advisory {advisoryId} yet. Anyone can assess it.</p>
        )}

        {exists && (
          <button className="why-toggle" onClick={() => setWhy(!why)} aria-expanded={why}>
            {why ? "Hide reasoning" : "Why this state"}
          </button>
        )}
        {why && exists && a && (
          <div className="why">
            {a.reasoning && <p>{a.reasoning}</p>}
            {a.minority_note && (
              <div className="minority">
                <span className="mono minority-k">MINORITY NOTE</span>
                <p>{a.minority_note}</p>
              </div>
            )}
            <p className="mono why-meta">
              assessed by {short(a.assessor ?? "")} · {a.assessed_at} · assessment #{a.count}
            </p>
          </div>
        )}
      </div>

      <div className="dep-actions">
        {advisoryId && (
          <button
            className="btn btn-ink btn-sm"
            disabled={busy || !address}
            onClick={() => run(`Assess deployment ${letter}`, () => assessDependent(advisoryId, dep.id))}
          >
            {exists ? "Reassess" : "Assess"}
          </button>
        )}
        {canEscalate && (
          <button
            className="btn btn-ghost btn-sm"
            disabled={busy || !address}
            onClick={() => run(`Escalate deployment ${letter}`, () => escalate(advisoryId, dep.id))}
          >
            Escalate
          </button>
        )}
        {isOwner && (
          <button
            className="btn btn-ghost btn-sm"
            disabled={busy}
            onClick={() => setTool(tool === "repin" ? "" : "repin")}
          >
            Re-pin
          </button>
        )}
        {isOwner && !isOperator && (
          <button
            className="btn btn-ghost btn-sm"
            disabled={busy}
            onClick={() => run(`Bind deployment ${letter} to the runner`, () => bindSkill(dep.id))}
          >
            Bind to runner
          </button>
        )}
        {isOperator && (
          <button
            className="btn btn-ghost btn-sm"
            disabled={busy}
            onClick={() => setTool(tool === "execute" ? "" : "execute")}
          >
            Execute payout
          </button>
        )}
      </div>

      {tool === "repin" && (
        <div className="dep-tool">
          <label className="field">
            <span>Repo prefix</span>
            <input className="mono" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
          </label>
          <label className="field">
            <span>New commit (40 hex)</span>
            <input className="mono" value={sha} onChange={(e) => setSha(e.target.value)} />
          </label>
          <div className="form-actions">
            <button className="btn btn-ink btn-sm" disabled={busy} onClick={doRepin}>
              Re-pin
            </button>
          </div>
          <p className="hint">Re-pinning changes no status. The deployment stays blocked until someone reassesses it.</p>
        </div>
      )}

      {tool === "execute" && (
        <div className="dep-tool">
          <label className="field">
            <span>Recipient</span>
            <input className="mono" value={recipient} onChange={(e) => setRecipient(e.target.value)} placeholder="0x..." />
          </label>
          <label className="field">
            <span>Amount</span>
            <input className="mono" value={amount} onChange={(e) => setAmount(e.target.value)} />
          </label>
          <div className="form-actions">
            <button className="btn btn-ink btn-sm" disabled={busy} onClick={doExecute}>
              Execute
            </button>
          </div>
          <p className="hint">
            The runner asks the registry first. A blocked deployment reverts with "skill is quarantined" and the vault is
            untouched.
          </p>
        </div>
      )}

      {formError && <p className="form-error dep-error">{formError}</p>}
    </article>
  );
}
