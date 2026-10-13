import { useState } from "react";
import type { Run } from "../../lib/useTx";
import type { Package } from "../../lib/contracts";
import { registerPackage, registerDependent } from "../../lib/contracts";
import { isSha, isRawPrefix } from "../../lib/format";

export function RegisterPackageForm({
  address,
  busy,
  run,
  after,
}: {
  address: string | null;
  busy: boolean;
  run: Run;
  after: (name: string, maintainer: string) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [prefix, setPrefix] = useState("https://raw.githubusercontent.com/");
  const [path, setPath] = useState("skills/");
  const [dir, setDir] = useState("security");
  const [versions, setVersions] = useState("");
  const [err, setErr] = useState("");

  async function submit() {
    const lines = versions
      .split(/\r?\n|,/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    if (!name.trim()) {
      setErr("Name the package.");
      return;
    }
    if (!isRawPrefix(prefix)) {
      setErr("Repo prefix must be https://raw.githubusercontent.com/owner/repo/");
      return;
    }
    if (lines.length === 0) {
      setErr("Add at least one version as label:commit.");
      return;
    }
    for (const l of lines) {
      const parts = l.split(":");
      if (parts.length !== 2 || !parts[0].trim() || !isSha(parts[1])) {
        setErr(`"${l}" must look like 1.0:<40-char commit>`);
        return;
      }
    }
    setErr("");
    const me = address ?? "";
    const pkgName = name.trim();
    const ok = await run(
      "Register package",
      () => registerPackage(pkgName, prefix.trim(), path.trim(), dir.trim(), lines.join(",")),
      () => after(pkgName, me),
    );
    if (ok) {
      setOpen(false);
      setName("");
      setVersions("");
    }
  }

  if (!open) {
    return (
      <>
        <button className="btn btn-ghost btn-sm side-btn" disabled={!address} onClick={() => setOpen(true)}>
          Register a package
        </button>
        {!address && <p className="hint">Connect MetaMask or use the demo wallet to register.</p>}
      </>
    );
  }

  return (
    <div className="form-card">
      <h3>Register a package</h3>
      <label className="field">
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="payout_skill" />
      </label>
      <label className="field">
        <span>Repo prefix (locked forever)</span>
        <input className="mono" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
      </label>
      <label className="field">
        <span>Skill file path (locked forever)</span>
        <input className="mono" value={path} onChange={(e) => setPath(e.target.value)} />
      </label>
      <label className="field">
        <span>Advisory folder (locked forever)</span>
        <input className="mono" value={dir} onChange={(e) => setDir(e.target.value)} />
      </label>
      <label className="field">
        <span>Versions, one per line as label:commit</span>
        <textarea
          className="mono"
          rows={4}
          value={versions}
          onChange={(e) => setVersions(e.target.value)}
          placeholder={"1.0:<40-char commit>\n1.1:<40-char commit>"}
        />
      </label>
      <div className="form-actions">
        <button className="btn btn-ink btn-sm" disabled={busy} onClick={submit}>
          Register
        </button>
        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      <p className="hint">The contract fetches every version and stores the sha256 of its bytes. You become the maintainer.</p>
      {err && <p className="form-error">{err}</p>}
    </div>
  );
}

export function RegisterDependentForm({
  pkg,
  address,
  busy,
  run,
}: {
  pkg: Package;
  address: string | null;
  busy: boolean;
  run: Run;
}) {
  const [open, setOpen] = useState(false);
  const [prefix, setPrefix] = useState(pkg.repo_prefix);
  const [sha, setSha] = useState("");
  const [posture, setPosture] = useState<"standard" | "strict">("standard");
  const [err, setErr] = useState("");

  async function submit() {
    if (!isRawPrefix(prefix)) {
      setErr("Repo prefix must be https://raw.githubusercontent.com/owner/repo/");
      return;
    }
    if (!isSha(sha)) {
      setErr("The commit must be 40 hex characters.");
      return;
    }
    setErr("");
    const ok = await run("Register deployment", () =>
      registerDependent(pkg.id, prefix.trim(), sha.trim().toLowerCase(), posture),
    );
    if (ok) {
      setOpen(false);
      setSha("");
    }
  }

  if (!open) {
    return (
      <div className="form-open-row">
        <button className="btn btn-ghost btn-sm" disabled={!address} onClick={() => setOpen(true)}>
          Register a deployment
        </button>
        {!address && <span className="hint">Connect MetaMask or use the demo wallet to register.</span>}
      </div>
    );
  }

  return (
    <div className="form-card">
      <h3>Register a deployment of {pkg.name}</h3>
      <label className="field">
        <span>Repo prefix (the package repo or a fork)</span>
        <input className="mono" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
      </label>
      <label className="field">
        <span>Pinned commit (40 hex)</span>
        <input className="mono" value={sha} onChange={(e) => setSha(e.target.value)} />
      </label>
      <label className="field">
        <span>Posture (locked at registration)</span>
        <select value={posture} onChange={(e) => setPosture(e.target.value === "strict" ? "strict" : "standard")}>
          <option value="standard">standard: an evidence conflict warns but keeps running</option>
          <option value="strict">strict: an evidence conflict blocks</option>
        </select>
      </label>
      <div className="form-actions">
        <button className="btn btn-ink btn-sm" disabled={busy} onClick={submit}>
          Register
        </button>
        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      <p className="hint">The pinned file must sit at {pkg.source_path} in that repo. You become the owner.</p>
      {err && <p className="form-error">{err}</p>}
    </div>
  );
}
