import { useState } from "react";
import type { Run } from "../../lib/useTx";
import type { RunnerConfig } from "../../lib/contracts";
import { mint, RUNNER_ADDRESS } from "../../lib/contracts";
import { short } from "../../lib/format";

export default function RunnerPanel({
  runner,
  error,
  onRetry,
  address,
  busy,
  run,
}: {
  runner: RunnerConfig | null;
  error: string;
  onRetry: () => void;
  address: string | null;
  busy: boolean;
  run: Run;
}) {
  const [amount, setAmount] = useState("100");
  const [err, setErr] = useState("");
  const isIssuer = !!address && !!runner && address === runner.issuer;

  async function doMint() {
    const n = Number(amount);
    if (!Number.isInteger(n) || n <= 0) {
      setErr("Amount must be a whole number above zero.");
      return;
    }
    setErr("");
    await run("Mint into the runner vault", () => mint(n));
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2 className="panel-title">Skill runner</h2>
        <span className="panel-sub mono">{short(RUNNER_ADDRESS)}</span>
      </div>
      <p className="panel-copy">
        The capability host. Before every payout it asks the registry. Blocked deployments revert and the vault is
        untouched.
      </p>
      <div className="runner-stats">
        <div className="stat">
          <div className="stat-k">Vault</div>
          <div className="stat-v">{runner ? runner.vault : "…"}</div>
        </div>
        <div className="stat">
          <div className="stat-k">Minted / max</div>
          <div className="stat-v">{runner ? `${runner.minted} / ${runner.max_supply}` : "…"}</div>
        </div>
        <div className="stat">
          <div className="stat-k">Executions</div>
          <div className="stat-v">{runner ? runner.executions : "…"}</div>
        </div>
      </div>
      {!runner && error && (
        <div className="form-open-row runner-retry">
          <p className="form-error">Could not read the runner: {error}</p>
          <button className="btn btn-ghost btn-sm" disabled={busy} onClick={onRetry}>
            Retry runner
          </button>
        </div>
      )}
      {runner && (
        <p className="hint">
          Conservation: minted {runner.minted} = vault {runner.vault} + paid out{" "}
          {Number(runner.minted) - Number(runner.vault)}. Only the issuer {short(runner.issuer)} can mint, never past
          the max.
        </p>
      )}
      {isIssuer && (
        <div className="inline-form runner-mint">
          <label className="field">
            <span>Mint into the vault (issuer only)</span>
            <input className="mono" value={amount} onChange={(e) => setAmount(e.target.value)} />
          </label>
          <button className="btn btn-ink btn-sm" disabled={busy} onClick={doMint}>
            Mint
          </button>
        </div>
      )}
      {err && <p className="form-error">{err}</p>}
    </section>
  );
}
