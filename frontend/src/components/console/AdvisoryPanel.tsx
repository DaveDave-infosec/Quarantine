import { useState } from "react";
import type { Run } from "../../lib/useTx";
import type { Package, Advisory } from "../../lib/contracts";
import { reportAdvisory, reportFollowup } from "../../lib/contracts";
import { rawToBlob, statusClass } from "../../lib/format";

interface Props {
  pkg: Package;
  advisories: Advisory[];
  activeId: string;
  onSelect: (id: string) => void;
  address: string | null;
  busy: boolean;
  run: Run;
}

function kindLine(a: Advisory): string {
  if (a.kind === "derived") return `Inherited from upstream advisory ${a.parent} through the vendored copy.`;
  if (a.kind === "amendment") return `Amends advisory ${a.parent}.`;
  if (a.kind === "followup") return `Follow-up to advisory ${a.parent}.`;
  return "";
}

export default function AdvisoryPanel({ pkg, advisories, activeId, onSelect, address, busy, run }: Props) {
  const [url, setUrl] = useState("");
  const [err, setErr] = useState("");
  const [followFor, setFollowFor] = useState("");
  const [followUrl, setFollowUrl] = useState("");
  const [followErr, setFollowErr] = useState("");
  const example = `${pkg.repo_prefix}<40-char commit>/${pkg.advisory_dir}ADV-001.md`;

  function urlProblem(u: string): string {
    if (!u.toLowerCase().startsWith(pkg.repo_prefix)) {
      return "The advisory must come from this package's repo: " + pkg.repo_prefix;
    }
    if (!u.endsWith(".md")) return "The advisory must be a .md file.";
    return "";
  }

  async function report() {
    const u = url.trim();
    const problem = urlProblem(u);
    if (problem) {
      setErr(problem);
      return;
    }
    setErr("");
    const ok = await run("Report advisory", () => reportAdvisory(pkg.id, u));
    if (ok) setUrl("");
  }

  async function follow(aid: string) {
    const u = followUrl.trim();
    const problem = urlProblem(u);
    if (problem) {
      setFollowErr(problem);
      return;
    }
    setFollowErr("");
    const ok = await run(`Follow up advisory ${aid}`, () => reportFollowup(aid, u));
    if (ok) {
      setFollowUrl("");
      setFollowFor("");
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2 className="panel-title">Advisories</h2>
        <span className="panel-sub">Prose in, structure out. Validators extract versions and judge follow-ups.</span>
      </div>
      {advisories.length === 0 ? (
        <p className="empty">No advisories on this package yet.</p>
      ) : (
        <ul className="adv-list">
          {advisories
            .slice()
            .reverse()
            .map((a) => {
              const open = a.status === "OPEN";
              const canFollow = open && a.kind !== "derived";
              return (
                <li key={a.id} className={"adv" + (a.id === activeId ? " active" : "")}>
                  <div className="adv-top">
                    <span className="mono adv-id">ADVISORY {a.id}</span>
                    <span className={`adv-status ${statusClass(a.status)}`}>{a.status.replace(/_/g, " ")}</span>
                    {open && a.id !== activeId && (
                      <button className="link-btn" onClick={() => onSelect(a.id)}>
                        Show on map
                      </button>
                    )}
                    {open && a.id === activeId && <span className="adv-active mono">ON MAP</span>}
                  </div>
                  {kindLine(a) && <p className="adv-kind">{kindLine(a)}</p>}
                  {a.successor && <p className="adv-kind">Superseded by advisory {a.successor}.</p>}
                  {a.summary && <p className="adv-summary">{a.summary}</p>}
                  <div className="adv-labels">
                    {a.affected_labels.map((l) => (
                      <span key={"a" + l} className="chip chip-bad mono">
                        affected {l}
                      </span>
                    ))}
                    {(a.uncertain_labels ?? []).map((l) => (
                      <span key={"u" + l} className="chip chip-mid mono">
                        unclear {l}
                      </span>
                    ))}
                    {a.patched_labels.map((l) => (
                      <span key={"p" + l} className="chip chip-good mono">
                        safe {l}
                      </span>
                    ))}
                  </div>
                  {a.vulnerable_pattern && (
                    <p className="adv-pattern">
                      <span className="mono">PATTERN</span>
                      {a.vulnerable_pattern}
                    </p>
                  )}
                  <div className="adv-foot">
                    {a.url && (
                      <a className="mono adv-link" href={rawToBlob(a.url)} target="_blank" rel="noreferrer">
                        Read the advisory source
                      </a>
                    )}
                    {canFollow && (
                      <button
                        className="link-btn"
                        onClick={() => {
                          setFollowFor(followFor === a.id ? "" : a.id);
                          setFollowErr("");
                        }}
                      >
                        {followFor === a.id ? "Cancel" : "Withdraw or amend"}
                      </button>
                    )}
                  </div>
                  {followFor === a.id && (
                    <div className="follow-form">
                      <div className="inline-form">
                        <label className="field">
                          <span>Follow-up advisory URL (anyone can file it)</span>
                          <input
                            className="mono"
                            value={followUrl}
                            onChange={(e) => setFollowUrl(e.target.value)}
                            placeholder={example}
                          />
                        </label>
                        <button
                          className="btn btn-ink btn-sm"
                          disabled={busy || !address || !followUrl.trim()}
                          onClick={() => follow(a.id)}
                        >
                          Submit
                        </button>
                      </div>
                      <p className="hint">
                        Validators decide whether it withdraws advisory {a.id}, amends it, or is unrelated. A withdrawal
                        lifts containment. An amendment opens a successor, and this advisory's blocks hold until the
                        successor assesses each deployment.
                      </p>
                      {followErr && <p className="form-error">{followErr}</p>}
                    </div>
                  )}
                </li>
              );
            })}
        </ul>
      )}
      <div className="inline-form">
        <label className="field">
          <span>Report an advisory (anyone can)</span>
          <input className="mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder={example} />
        </label>
        <button className="btn btn-ink btn-sm" disabled={busy || !address || !url.trim()} onClick={report}>
          Report
        </button>
      </div>
      <p className="hint">
        Only a commit-pinned .md file inside <span className="mono">{pkg.advisory_dir}</span> of the locked repo is
        accepted. Reporting the same URL twice reverts.
      </p>
      {err && <p className="form-error">{err}</p>}
    </section>
  );
}
