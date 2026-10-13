import { Link, NavLink } from "react-router-dom";
import Logo from "./Logo";
import { REPO_URL } from "../lib/contracts";
import { useWallet } from "../lib/useWallet";

export default function Nav({ variant }: { variant: "marketing" | "app" }) {
  const { address, mode, connectMetaMask, useDemo, disconnect } = useWallet();
  const short = address ? address.slice(0, 6) + "…" + address.slice(-4) : "";

  return (
    <header className="nav">
      <div className="container nav-inner">
        <Link to="/" className="brand">
          <Logo size={26} />
          <span>Quarantine</span>
        </Link>
        <nav className="nav-links" aria-label="Primary">
          <NavLink to="/how-it-works">How it works</NavLink>
          <NavLink to="/console">Console</NavLink>
          <NavLink to="/guide">Guide</NavLink>
          <a href={REPO_URL} target="_blank" rel="noreferrer">
            Docs
          </a>
        </nav>
        <div className="nav-actions">
          {variant === "marketing" ? (
            <Link to="/console" className="btn btn-ink btn-sm">
              Open console
            </Link>
          ) : address ? (
            <div className="wallet-pill mono">
              <span className={`wallet-dot ${mode ?? ""}`} />
              {short}
              <span className="wallet-mode">{mode === "demo" ? "demo" : "wallet"}</span>
              <button className="link-btn" onClick={disconnect}>
                Disconnect
              </button>
            </div>
          ) : (
            <div className="wallet-actions">
              <button className="btn btn-ghost btn-sm" onClick={() => useDemo()}>
                Demo wallet
              </button>
              <button
                className="btn btn-ink btn-sm"
                onClick={() => {
                  connectMetaMask().catch(() => undefined);
                }}
              >
                Connect MetaMask
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
