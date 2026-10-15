import { Link } from "react-router-dom";
import Logo from "./Logo";
import {
  REGISTRY_ADDRESS,
  RUNNER_ADDRESS,
  CHAIN_LABEL,
  REPO_URL,
  DEMO_REPO_URL,
  DEMO_FORK_URL,
  DEMO_WRAPPER_URL,
  BYSTANDER_RECEIPT_TX,
  WITHDRAW_RECEIPT_TX,
  txUrl,
} from "../lib/contracts";

export default function Footer() {
  return (
    <footer className="footer">
      <div className="container footer-grid">
        <div>
          <Link to="/" className="brand">
            <Logo size={22} />
            <span>Quarantine</span>
          </Link>
          <p>Validators read the code. The host obeys.</p>
        </div>
        <div>
          <h4>Contracts (V2)</h4>
          <dl className="addr">
            <dt>Registry</dt>
            <dd className="mono">{REGISTRY_ADDRESS}</dd>
            <dt>Skill runner</dt>
            <dd className="mono">{RUNNER_ADDRESS}</dd>
            <dt>Network</dt>
            <dd>{CHAIN_LABEL}</dd>
          </dl>
        </div>
        <div>
          <h4>Proof</h4>
          <ul>
            <li>
              <a href={txUrl(BYSTANDER_RECEIPT_TX)} target="_blank" rel="noreferrer">
                Bystander restore receipt
              </a>
            </li>
            <li>
              <a href={txUrl(WITHDRAW_RECEIPT_TX)} target="_blank" rel="noreferrer">
                Bystander withdrawal receipt
              </a>
            </li>
            <li>
              <a href={REPO_URL} target="_blank" rel="noreferrer">
                Source and 70 tests
              </a>
            </li>
            <li>
              <a href={DEMO_REPO_URL} target="_blank" rel="noreferrer">
                Demo skill repo
              </a>
            </li>
            <li>
              <a href={DEMO_FORK_URL} target="_blank" rel="noreferrer">
                Demo fork repo
              </a>
            </li>
            <li>
              <a href={DEMO_WRAPPER_URL} target="_blank" rel="noreferrer">
                Demo wrapper repo
              </a>
            </li>
          </ul>
        </div>
      </div>
    </footer>
  );
}
