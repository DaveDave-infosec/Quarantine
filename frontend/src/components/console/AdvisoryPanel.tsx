import { useState } from "react";
import type { Run } from "../../lib/useTx";
import type { Package, Advisory } from "../../lib/contracts";
import { reportAdvisory } from "../../lib/contracts";
import { rawToBlob } from "../../lib/format";

interface Props {
  pkg: Package;
  advisories: Advisory[];
  activeId: string;
  onSelect: (id: string) => void;
  address: string | null;
  busy: boolean;
  run: Run;
}

export default function AdvisoryPanel({ pkg, advisories, activeId, onSelect, address, busy, run }: Props) {
  const [url, setUrl] = useState("");
  const [err, setErr] = useState("");
  const example = `${pkg.repo_prefix}<40-char commit>/${pkg.advisory_dir}ADV-001.md`;

  async function report() {
    const u = url.trim();
    if (!u.toLowerCase().startsWith(pkg.repo_prefix)) {
      setErr("The advisory must come from this package's repo: " + pkg.repo_prefix);
      return;
    }
    if (!u.endsWith(".md")) {
      setErr("The advisory must be a .md file.");
      return;
    }
    setErr("");
    const ok = await run("Report advisory", () => reportAdvisory(pkg.id, u));
    if (ok) setUrl("");
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2 className="panel-title">Advisories</h2>
        <span className="panel-sub">Prose in, structure out. Validators extract affected and patched versions.</span>
      </div>
      {advisories.length === 0 ? (
        <p className="empty">No advisories reported for this package yet.</p>
      ) : (
        <ul className="adv-list">
          {advisories
            .slice()
            .reverse()
            .map((a) => {
              const open = a.status === "OPEN";
              return (
                <li key={a.id} className={"adv" + (a.id === activeId ? " active" : "")}>
                  <div className="adv-top">
                    <span className="mono adv-id">ADVISORY {a.id}</span>
                    <span className={`adv-status ${open ? "open" : "rejected"}`}>{a.status.replace(/_/g, " ")}</span>
                    {open && a.id !== activeId && (
                      <button className="link-btn" onClick={() => onSelect(a.id)}>
                        Show on map
                      </button>
                    )}
                    {open && a.id === activeId && <span className="adv-active mono">ON MAP</span>}
                  </div>
                  {a.summary && <p className="adv-summary">{a.summary}</p>}
                  <div className="adv-labels">
                    {a.affected_labels.map((l) => (
                      <span key={"a" + l} className="chip chip-bad mono">
                        affected {l}
                      </span>
                    ))}
                    {a.patched_labels.map((l) => (
                      <span key={"p" + l} className="chip chip-good mono">
                        patched {l}
                      </span>
                    ))}
                  </div>
                  {a.vulnerable_pattern && (
                    <p className="adv-pattern">
                      <span className="mono">PATTERN</span>
                      {a.vulnerable_pattern}
                    </p>
                  )}
                  <a className="mono adv-link" href={rawToBlob(a.url)} target="_blank" rel="noreferrer">
                    Read the advisory source
                  </a>
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
