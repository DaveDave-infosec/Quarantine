import { useState } from "react";
import { Link } from "react-router-dom";
import Shell from "../components/Shell";
import {
  BYSTANDER_RECEIPT_TX,
  WITHDRAW_RECEIPT_TX,
  DEMO_REPO_URL,
  DEMO_FORK_URL,
  DEMO_WRAPPER_URL,
  txUrl,
} from "../lib/contracts";
import "../docs.css";

const PKG = "https://raw.githubusercontent.com/DaveDave-infosec/quarantine-demo-skills/";
const FORK = "https://raw.githubusercontent.com/DaveDave-infosec/quarantine-demo-fork/";
const WRAP = "https://raw.githubusercontent.com/DaveDave-infosec/quarantine-demo-wrapper/";
const SHA_11 = "f81f6ca103c7fe3f43ed1ffda59b2219dd3d4bb5";
const SHA_12 = "9fd9ebac5e70f74cf36d440e3a4314d786ad5296";
const SHA_FORK_UNFIXED = "14d5f30342490bdeb78f4efdfb5bc595b8fc9f40";
const SHA_FORK_FIXED = "c08f8a0cba36d1755fc846df5f36094ebb426fa3";
const SHA_W20 = "762e39abe834bd450eef6ff898d2289813060cb9";
const SHA_W21 = "95dc3370af01cdeda28a6bc7ca2a0c23e45370a1";
const ADV_URL = PKG + "17bf5f1a1c9aec6bbfd5d194ee0dcc6b849f8316/security/ADV-001.md";
const ADV3W_URL = PKG + "b4099d931efce9cc9125d3ebd2b4dbabce53564c/security/ADV-003-withdrawn.md";
const ANY_RECIPIENT = "0x4fb1e8d04735e104a25c2235e29ee2acc045fbe1";

const RUN_V1: [string, string][] = [
  ["Register payout_skill with versions 1.0, 1.1 and 1.2", "Three versions fetched and hashed on-chain"],
  ["Register four deployments", "A on 1.1, B on 1.0, C on fork-unfixed (strict), D on fork-fixed"],
  ["Report ADV-001", "OPEN: affected 1.1, patched 1.2, pattern extracted by validators"],
  ["Assess all four", "A patch required by hash, B unaffected by hash, C patch required by validators, D unaffected by validators"],
  ["Execute through A, then B", "A refused: skill is quarantined. B pays"],
  ["A re-pins to 1.2, executes again", "Still refused: re-pinning alone never unblocks"],
  ["A wallet with no role reassesses A", "RESTORED"],
  ["Execute through A", "Pays. Minted 1000 = vault 900 + paid 100"],
];

const RUN_V2: [string, string][] = [
  ["Register payout_skill with tag-verified versions", "Each version's bytes matched at its commit and at its git tag"],
  ["Register the wrapper batch_payout, vendoring payout_skill", "Vendored versions detected by hash: 2.0 and 2.1 carry 1.1, 2.2 carries 1.2"],
  ["Register four deployments", "B on 1.0, W0 on wrapper 2.0, W1 on 2.1, W2 on 2.2"],
  ["Report ADV-001", "OPEN"],
  ["Propagate ADV-001 into the wrapper", "2.2 clean by hash. Validators: 2.0 exposed, 2.1 neutralized"],
  ["Assess the three wrapper deployments", "W0 patch required, W1 and W2 unaffected, all by hash, no consensus"],
  ["Execute through W0, then W1", "W0 refused: skill is quarantined. W1 pays"],
  ["Report ADV-002 and ADV-003, which wrongly name 1.0", "B blocked by hash: the false positive"],
  ["Withdraw both", "Validators judge both full withdrawals. B released. The second was filed by a wallet with no role"],
];

function Copy({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  function copy() {
    try {
      navigator.clipboard
        .writeText(value)
        .then(() => {
          setDone(true);
          window.setTimeout(() => setDone(false), 1400);
        })
        .catch(() => undefined);
    } catch {
      // clipboard unavailable, the value stays selectable
    }
  }
  return (
    <span className="copy">
      <code className="mono" title={value}>
        {value}
      </code>
      <button className="copy-btn" onClick={copy}>
        {done ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="copy-row">
      <span>{label}</span>
      <Copy value={value} />
    </div>
  );
}

function RunTable({ rows }: { rows: [string, string][] }) {
  return (
    <div className="doc-table-wrap">
      <table className="doc-table run-table">
        <thead>
          <tr>
            <th>Step</th>
            <th>Action</th>
            <th>Result on chain</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([action, result], i) => (
            <tr key={action}>
              <td>{String(i + 1).padStart(2, "0")}</td>
              <td>{action}</td>
              <td>{result}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Guide() {
  return (
    <Shell variant="marketing">
      <section className="container page doc">
        <header className="page-head">
          <p className="eyebrow">
            <span className="eyebrow-dot" />
            Guide
          </p>
          <h1>Watch the live runs. Then run it yourself.</h1>
          <p className="lede">
            Everything below happened on GenLayer Studio, and every step can be repeated from your own browser with the demo
            wallet. No install, no funds, no setup.
          </p>
        </header>

        <section className="doc-block">
          <h2>V1: forks, re-pins and a bystander restore</h2>
          <p>
            The demo skill lives in <a href={DEMO_REPO_URL} target="_blank" rel="noreferrer">quarantine-demo-skills</a>:
            1.0 is safe, 1.1 skims 1.5 percent of every payout to a hardcoded address, 1.2 fixes it. The fork in{" "}
            <a href={DEMO_FORK_URL} target="_blank" rel="noreferrer">quarantine-demo-fork</a> has one commit that renames
            the skim and one that really removes it. Run on the V1 contracts.
          </p>
          <RunTable rows={RUN_V1} />
          <p className="doc-after">
            Step 7 was sent by a wallet that is not the maintainer, not an owner, not the issuer and not the deployer.{" "}
            <a href={txUrl(BYSTANDER_RECEIPT_TX)} target="_blank" rel="noreferrer">
              See the receipt
            </a>
            .
          </p>
        </section>

        <section className="doc-block">
          <h2>V2: inherited exposure and withdrawn false positives</h2>
          <p>
            The wrapper in <a href={DEMO_WRAPPER_URL} target="_blank" rel="noreferrer">quarantine-demo-wrapper</a> vendors
            payout_skill. 2.0 calls the skimming 1.1 raw. 2.1 vendors the same 1.1 but keeps only transfers to declared
            recipients. 2.2 vendors the fixed 1.2. Run on the V2 contracts, which the console reads.
          </p>
          <RunTable rows={RUN_V2} />
          <p className="doc-after">
            The final withdrawal was filed by the same wallet with no role.{" "}
            <a href={txUrl(WITHDRAW_RECEIPT_TX)} target="_blank" rel="noreferrer">
              See the receipt
            </a>
            . The V2 registry also lists package #1, an identical registration of payout_skill by a different wallet. The
            registry is open to anyone, so that is allowed. The live run used package #2.
          </p>
        </section>

        <section className="doc-block">
          <h2>Run it yourself, no setup</h2>
          <p className="callout">
            Each write waits for finalization before the console shows success, usually one to three minutes. The bar at the
            bottom of the console shows the real phase and links to the transaction.
          </p>
          <ol className="steps">
            <li className="step">
              <h3>Open the console and click Demo wallet</h3>
              <p>A throwaway key is created in your browser. It can sign on Studio straight away.</p>
              <p>
                <Link to="/console" className="btn btn-ink btn-sm">
                  Open console
                </Link>
              </p>
            </li>
            <li className="step">
              <h3>Register your own deployment on the compromised 1.1</h3>
              <p>On payout_skill #2, click Register a deployment, fill these in, choose standard, then Register.</p>
              <div className="copy-list">
                <Row label="Repo prefix" value={PKG} />
                <Row label="Pinned commit" value={SHA_11} />
              </div>
              <p className="expect">A new card appears that says you are its owner.</p>
            </li>
            <li className="step">
              <h3>Assess it</h3>
              <p>Click Assess on your new card.</p>
              <p className="expect">
                Expect <strong>Patch required</strong>, decided in code by hash match, no consensus spent.
              </p>
            </li>
            <li className="step">
              <h3>Bind it and try to pay</h3>
              <p>Click Bind to runner. Once that lands, click Execute payout and send 10 to any address.</p>
              <div className="copy-list">
                <Row label="Any recipient" value={ANY_RECIPIENT} />
              </div>
              <p className="expect">
                Expect <strong>Refused by the contract: skill is quarantined</strong>. The runner vault does not move.
              </p>
            </li>
            <li className="step">
              <h3>Re-pin to the fix, then try again</h3>
              <p>Click Re-pin, keep the repo prefix, and use the 1.2 commit. Then try Execute payout again.</p>
              <div className="copy-list">
                <Row label="1.2 commit" value={SHA_12} />
              </div>
              <p className="expect">Expect it to stay blocked until reassessed. The payout is still refused.</p>
            </li>
            <li className="step">
              <h3>Reassess, then pay</h3>
              <p>Click Reassess. When it lands, click Execute payout again.</p>
              <p className="expect">
                Expect <strong>Restored</strong>, then a successful payout. The runner vault drops by exactly your amount.
              </p>
            </li>
            <li className="step">
              <h3>Make validators read a fork</h3>
              <p>Register another deployment on the fork repo, using either fork commit, then Assess it.</p>
              <div className="copy-list">
                <Row label="Fork repo prefix" value={FORK} />
                <Row label="Skim kept, renamed" value={SHA_FORK_UNFIXED} />
                <Row label="Fix cherry-picked" value={SHA_FORK_FIXED} />
              </div>
              <p className="expect">
                Expect <strong>Patch required</strong> for the renamed skim and <strong>Unaffected</strong> for the real fix.
              </p>
            </li>
            <li className="step">
              <h3>Try to cheat</h3>
              <p>In the Advisories panel, report ADV-001 again.</p>
              <div className="copy-list">
                <Row label="Advisory URL" value={ADV_URL} />
              </div>
              <p className="expect">
                Expect <strong>Refused by the contract: this advisory url was already reported</strong>.
              </p>
            </li>
            <li className="step">
              <h3>See a wrapper inherit exposure</h3>
              <p>
                In the sidebar, open batch_payout #3. The Inherited exposure panel shows each release, what it vendors and
                its verdict. Click Why on 2.0 and on 2.1.
              </p>
              <p className="expect">
                Expect 2.0 <strong>Exposed</strong> and 2.1 <strong>Neutralized</strong>, though both vendor the same 1.1.
              </p>
            </li>
            <li className="step">
              <h3>Register on the exposed wrapper</h3>
              <p>On batch_payout #3, register a deployment with these values, then Assess it against advisory 2.</p>
              <div className="copy-list">
                <Row label="Repo prefix" value={WRAP} />
                <Row label="Wrapper 2.0 commit" value={SHA_W20} />
              </div>
              <p className="expect">
                Expect <strong>Patch required</strong> by hash. It never had an advisory of its own; it inherited one.
              </p>
            </li>
            <li className="step">
              <h3>Same vendored bytes, opposite outcome</h3>
              <p>Register one more on the wrapper at 2.1, then Assess it.</p>
              <div className="copy-list">
                <Row label="Wrapper 2.1 commit" value={SHA_W21} />
              </div>
              <p className="expect">
                Expect <strong>Unaffected</strong> by hash, because validators already judged 2.1 neutralizes the flaw.
              </p>
            </li>
            <li className="step">
              <h3>Try to replay a withdrawal</h3>
              <p>
                Back on payout_skill #2, find ADV-001 in the Advisories panel, click Withdraw or amend, and submit the
                withdrawal that was already used.
              </p>
              <div className="copy-list">
                <Row label="Used withdrawal" value={ADV3W_URL} />
              </div>
              <p className="expect">
                Expect <strong>Refused by the contract: this advisory url was already reported</strong>. ADV-001 stays in
                force.
              </p>
            </li>
          </ol>
        </section>
      </section>
    </Shell>
  );
}
