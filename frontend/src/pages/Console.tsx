import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import Shell from "../components/Shell";
import ContainmentMap, { StateLegend } from "../components/ContainmentMap";
import type { MapNode, MapVersion } from "../components/ContainmentMap";
import { useRegistry } from "../lib/useRegistry";
import { useTx } from "../lib/useTx";
import { useWallet } from "../lib/useWallet";
import { getCounts, getPackage, DEFAULT_PACKAGE } from "../lib/contracts";
import type { Dependent } from "../lib/contracts";
import DependentCard from "../components/console/DependentCard";
import AdvisoryPanel from "../components/console/AdvisoryPanel";
import { RegisterPackageForm, RegisterDependentForm } from "../components/console/Forms";
import RunnerPanel from "../components/console/RunnerPanel";
import PropagationPanel from "../components/console/PropagationPanel";
import TxBar from "../components/console/TxBar";
import "../console.css";

export default function ConsolePage() {
  const [params, setParams] = useSearchParams();
  const selected = params.get("pkg") ?? DEFAULT_PACKAGE;
  const { address } = useWallet();
  const { summaries, view, runner, runnerError, loading, error, reload, reloadRunner } = useRegistry(
    selected,
    address,
  );
  const { tx, busy, run, dismiss } = useTx(reload);
  const [advChoice, setAdvChoice] = useState("");

  const openIds = view?.pkg.open_advisory_ids ?? [];
  const activeAdv = openIds.includes(advChoice) ? advChoice : openIds[0] ?? "";
  const activeAdvisory = view?.advisories.find((a) => a.id === activeAdv) ?? null;

  const labelBySha = useMemo(
    () => new Map<string, string>((view?.pkg.versions ?? []).map((v) => [v.sha, v.label])),
    [view],
  );

  function pinLabel(dep: Dependent): string {
    if (!view) return "";
    const label = labelBySha.get(dep.pinned_sha);
    return label && dep.repo_prefix === view.pkg.repo_prefix
      ? `pin ${label}`
      : `fork ${dep.pinned_sha.slice(0, 7)}`;
  }

  const versions: MapVersion[] = (view?.pkg.versions ?? []).map(
    (v): MapVersion => ({
      label: v.label,
      status: activeAdvisory?.affected_labels.includes(v.label)
        ? "affected"
        : activeAdvisory?.uncertain_labels?.includes(v.label)
          ? "uncertain"
          : activeAdvisory?.patched_labels.includes(v.label)
            ? "patched"
            : "clean",
    }),
  );

  const nodes: MapNode[] = (view?.deps ?? []).map((d, i): MapNode => {
    const a = activeAdv ? d.assessments[activeAdv] : undefined;
    const live = !!a && a.exists && !a.stale;
    return {
      id: d.dep.id,
      name: String.fromCharCode(65 + i),
      pin: pinLabel(d.dep),
      state: live && a?.state ? a.state : "PENDING",
      via: live && a?.path ? a.path : null,
    };
  });

  async function selectNewest(name: string, maintainer: string) {
    const c = await getCounts();
    const n = Number(c.packages);
    for (let i = n; i >= Math.max(1, n - 5); i--) {
      const p = await getPackage(String(i));
      if (p.name === name && p.maintainer === maintainer) {
        setParams({ pkg: p.id });
        return;
      }
    }
  }

  return (
    <Shell variant="app">
      <section className="container console">
        <header className="console-head">
          <div>
            <p className="eyebrow">
              <span className="eyebrow-dot" />
              Console
            </p>
            <h1>Live containment</h1>
            <p className="lede">
              Everything here is read from the registry and the skill runner on chain. Reading needs no wallet. Acting
              needs MetaMask or the demo wallet.
            </p>
          </div>
          <button
            className="btn btn-ghost btn-sm"
            disabled={busy || loading}
            onClick={() => {
              reload().catch(() => undefined);
            }}
          >
            Refresh
          </button>
        </header>

        {error && <p className="notice notice-error">Could not read from chain: {error}</p>}

        <div className="console-grid">
          <aside className="pkg-side">
            <h2 className="panel-title">Packages</h2>
            <ul className="pkg-list">
              {summaries.map((s) => (
                <li key={s.id}>
                  <button
                    className={"pkg-item" + (view?.pkg.id === s.id ? " active" : "")}
                    onClick={() => setParams({ pkg: s.id })}
                  >
                    <span className="pkg-name">{s.name}</span>
                    <span className="pkg-meta mono">
                      #{s.id} · {s.versions} versions · {s.dependents} deployments
                    </span>
                    {s.upstream && <span className="pkg-vendor mono">vendors package #{s.upstream}</span>}
                    {s.open > 0 && <span className="pkg-open mono">{s.open} open advisory</span>}
                  </button>
                </li>
              ))}
              {loading && summaries.length === 0 && <li className="pkg-skel">Reading packages{"…"}</li>}
            </ul>
            <RegisterPackageForm address={address} busy={busy} run={run} after={selectNewest} />
          </aside>

          <div className="console-main">
            {!view ? (
              <div className="map-card">
                <p className="map-status">
                  {loading
                    ? "Reading the registry from chain…"
                    : error
                      ? "Could not load this package from chain. Press Refresh to try again."
                      : "No packages registered yet."}
                </p>
              </div>
            ) : (
              <>
                <div className="map-card">
                  <div className="map-card-head mono">
                    <span>LIVE FROM CHAIN</span>
                    <span>
                      package {view.pkg.id} · {view.pkg.name}
                      {activeAdvisory ? ` · advisory ${activeAdvisory.id}` : ""}
                    </span>
                  </div>
                  <ContainmentMap
                    packageName={view.pkg.name}
                    versions={versions}
                    nodes={nodes}
                    ariaLabel="Live containment map read from the registry contract"
                  />
                  <StateLegend />
                </div>

                <AdvisoryPanel
                  pkg={view.pkg}
                  advisories={view.advisories}
                  activeId={activeAdv}
                  onSelect={setAdvChoice}
                  address={address}
                  busy={busy}
                  run={run}
                />

                {view.pkg.upstream && <PropagationPanel view={view} address={address} busy={busy} run={run} />}

                <section className="panel">
                  <div className="panel-head">
                    <h2 className="panel-title">Deployments</h2>
                    <span className="panel-sub">
                      {activeAdvisory
                        ? `States against advisory ${activeAdvisory.id}`
                        : "No open advisory. Every deployment is allowed."}
                    </span>
                  </div>
                  {view.deps.length === 0 ? (
                    <p className="empty">No deployments registered against this package yet.</p>
                  ) : (
                    <div className="dep-grid">
                      {view.deps.map((d, i) => (
                        <DependentCard
                          key={d.dep.id}
                          view={d}
                          letter={String.fromCharCode(65 + i)}
                          pkg={view.pkg}
                          advisoryId={activeAdv}
                          pinLabel={pinLabel(d.dep)}
                          address={address}
                          busy={busy}
                          run={run}
                        />
                      ))}
                    </div>
                  )}
                  <RegisterDependentForm key={view.pkg.id} pkg={view.pkg} address={address} busy={busy} run={run} />
                </section>

                <RunnerPanel
                  runner={runner}
                  error={runnerError}
                  onRetry={() => {
                    reloadRunner().catch(() => undefined);
                  }}
                  address={address}
                  busy={busy}
                  run={run}
                />
              </>
            )}
          </div>
        </div>
      </section>
      <TxBar tx={tx} onDismiss={dismiss} />
    </Shell>
  );
}
