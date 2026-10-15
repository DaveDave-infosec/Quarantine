import { useState } from "react";
import type { Run } from "../../lib/useTx";
import type { PackageView, PropView } from "../../lib/useRegistry";
import type { PropagationRow } from "../../lib/contracts";
import { propagate, escalatePropagation } from "../../lib/contracts";
import { short, statusClass } from "../../lib/format";

const STATE_TEXT: Record<string, string> = {
  todo: "Awaiting validators",
  clean: "Clean by hash",
  exposed: "Exposed",
  neutralized: "Neutralized",
  unclear: "Unclear, held",
};

function Row({
  row,
  prop,
  pkgId,
  address,
  busy,
  run,
}: {
  row: PropagationRow;
  prop: PropView;
  pkgId: string;
  address: string | null;
  busy: boolean;
  run: Run;
}) {
  const [open, setOpen] = useState(false);
  const upstreamId = prop.upstreamAdvisory.id;
  return (
    <li className="prop-row">
      <div className="prop-main">
        <span className="prop-label mono">{row.label}</span>
        <span className="prop-vend mono">vendors {row.vendored || "unmatched bytes"}</span>
        <span className={`prop-state ps-${row.state}`}>{STATE_TEXT[row.state] ?? row.state}</span>
        <div className="prop-actions">
          {row.state === "todo" && (
            <button
              className="btn btn-ink btn-sm"
              disabled={busy || !address}
              onClick={() => run(`Ask validators about ${row.label}`, () => propagate(upstreamId, pkgId, row.label))}
            >
              Ask validators
            </button>
          )}
          {row.state === "unclear" && prop.derivedId && (
            <button
              className="btn btn-ghost btn-sm"
              disabled={busy || !address}
              onClick={() => run(`Escalate ${row.label}`, () => escalatePropagation(prop.derivedId, row.label))}
            >
              Escalate
            </button>
          )}
          {row.reasoning && (
            <button className="link-btn" onClick={() => setOpen(!open)}>
              {open ? "Hide" : "Why"}
            </button>
          )}
        </div>
      </div>
      {open && row.reasoning && (
        <div className="why prop-why">
          <p>{row.reasoning}</p>
          {row.minority_note && (
            <div className="minority">
              <span className="mono minority-k">MINORITY NOTE</span>
              <p>{row.minority_note}</p>
            </div>
          )}
          <p className="mono why-meta">
            {row.path} · by {short(row.assessor)} · {row.at}
          </p>
        </div>
      )}
    </li>
  );
}

export default function PropagationPanel({
  view,
  address,
  busy,
  run,
}: {
  view: PackageView;
  address: string | null;
  busy: boolean;
  run: Run;
}) {
  const { pkg } = view;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2 className="panel-title">Inherited exposure</h2>
        <span className="panel-sub">
          Vendors {view.upstreamName || "its upstream"} (package #{pkg.upstream}) at{" "}
          <span className="mono">{pkg.vendor_path}</span>
        </span>
      </div>
      <p className="panel-copy">
        Which upstream version each release carries is decided by hash. Validators only judge releases that carry an
        affected upstream: does this wrapper still expose the flaw to its callers, or neutralize it?
      </p>
      {view.upstreamFailed ? (
        <p className="form-error">Could not read the upstream package from chain right now. Press Refresh to try again.</p>
      ) : view.props.length === 0 ? (
        <p className="empty">No open advisory on the upstream package. Nothing to inherit.</p>
      ) : (
        <div className="prop-list">
          {view.props.map((p) => (
            <div className="prop-card" key={p.upstreamAdvisory.id}>
              <div className="prop-head">
                <span className="mono adv-id">FROM UPSTREAM ADVISORY {p.upstreamAdvisory.id}</span>
                <span className={`adv-status ${statusClass(p.propagation?.status ?? "")}`}>
                  {p.propagation ? p.propagation.status : "NOT PROPAGATED"}
                </span>
                {p.derivedId && <span className="mono prop-derived">derived advisory {p.derivedId}</span>}
              </div>
              {p.upstreamAdvisory.summary && <p className="adv-summary">{p.upstreamAdvisory.summary}</p>}
              {p.failed ? (
                <p className="form-error">Could not read this propagation from chain right now. Press Refresh to try again.</p>
              ) : !p.propagation ? (
                <div className="form-open-row">
                  <button
                    className="btn btn-ink btn-sm"
                    disabled={busy || !address}
                    onClick={() =>
                      run(`Propagate advisory ${p.upstreamAdvisory.id}`, () =>
                        propagate(p.upstreamAdvisory.id, pkg.id, ""),
                      )
                    }
                  >
                    Start propagation
                  </button>
                  {!address && <span className="hint">Connect MetaMask or use the demo wallet.</span>}
                </div>
              ) : (
                <ul className="prop-rows">
                  {p.propagation.versions.map((row) => (
                    <Row key={row.label} row={row} prop={p} pkgId={pkg.id} address={address} busy={busy} run={run} />
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
