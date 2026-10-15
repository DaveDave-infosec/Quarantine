import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import Shell from "../components/Shell";
import ContainmentMap, { StateLegend, STATE_COLOR, STATE_LABEL } from "../components/ContainmentMap";
import { useDemoScript } from "../components/useDemoScript";
import type { State } from "../lib/contracts";
import {
  BYSTANDER_RECEIPT_TX,
  WITHDRAW_RECEIPT_TX,
  BYSTANDER_WALLET,
  REGISTRY_ADDRESS,
  REPO_URL,
  txUrl,
} from "../lib/contracts";
import { short } from "../lib/format";
import "../marketing.css";

// Real output from the V1 live run: Deployment C against advisory 1.
const C_REASONING =
  "The build_transfers function in the deployment file calculates a reserve amount using OPS_RESERVE_BPS (150) and subtracts it from the total payout. It then appends a transfer of this reserve amount to OPS_RESERVE_WALLET, which is a hardcoded address equivalent to the one in the affected version.";
const C_MINORITY =
  "One could argue that the deployment file uses different function and variable names such as build_transfers and OPS_RESERVE_WALLET, but the underlying logic of diverting 150 basis points to a hardcoded address remains functionally identical to the vulnerable pattern.";

// Real output from the V2 live run: wrapper batch_payout 2.0 and 2.1, both vendoring payout_skill 1.1.
const W20_REASONING =
  "The wrapper imports and calls plan_payout from the vendored payout_skill 1.1. The vendored code contains the vulnerable pattern where RELAY_FEE_BPS (150) is skimmed and sent to RELAY_ADDRESS. The wrapper's plan_batch function simply iterates over batches and returns the results of plan_payout without any filtering or validation.";
const W21_REASONING =
  "The wrapper's declared_only function filters out any transfers to undeclared recipients, which removes the relay fee transfer to the hardcoded RELAY_ADDRESS. The wrapper ensures only declared recipients receive funds and adjusts the first recipient's amount to account for any withheld relay fees, effectively neutralizing the vulnerability.";
const W21_MINORITY =
  "One might argue that because the vendored plan_payout still calculates and temporarily includes the relay fee, the flaw exists internally, even though it is removed before returning results.";

const CLAIMS = [
  { who: "The maintainer", says: "Only 1.1 is affected." },
  { who: "A fork", says: "We cherry-picked the fix." },
  { who: "A wrapper", says: "We vendor it, but we filter the output." },
];

const STATES: { s: State; meaning: string; host: string }[] = [
  { s: "QUARANTINED", meaning: "Exposed, and no patched version exists yet.", host: "Blocked" },
  {
    s: "PATCH_REQUIRED",
    meaning: "Exposed, and a patched version exists. Re-pin to it, then anyone can reassess.",
    host: "Blocked",
  },
  { s: "UNAFFECTED", meaning: "The pinned code does not carry the flaw.", host: "Runs" },
  {
    s: "EVIDENCE_CONFLICT",
    meaning: "Too close to call, or too large to judge whole. Held, never auto-disabled.",
    host: "Warns, or blocks under strict posture",
  },
  { s: "RESTORED", meaning: "Was contained under this advisory. Now verified clear.", host: "Runs" },
];

const CORE_FILL: Record<State, string> = {
  QUARANTINED: "#f8e9e6",
  PATCH_REQUIRED: "#f8f0e0",
  UNAFFECTED: "#e6f0ea",
  EVIDENCE_CONFLICT: "#ecebf5",
  RESTORED: "#e2eff6",
};

const TRUST = [
  {
    title: "Evidence sources are locked",
    body: "The repo, the skill file path, the vendor path and the advisory folder are fixed at registration. Every URL is commit-pinned, so the bytes cannot change under a verdict.",
  },
  {
    title: "Labels are tag-verified",
    body: "Every version is fetched at its commit and at its git tag of the same name, and the bytes must match. A maintainer cannot quietly call any commit 1.2.",
  },
  {
    title: "Nothing unblocks quietly",
    body: "A re-pin marks every assessment stale and blocks until reassessed. An amendment keeps the old blocks until its successor has assessed each deployment.",
  },
  {
    title: "No status setter exists",
    body: "Not for the deployer, not for the maintainer, not for anyone. Every role is bound to the transaction sender, and a test parses the contract to prove the full list of write methods.",
  },
];

function useInView<T extends Element>(threshold: number) {
  const ref = useRef<T | null>(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    if (typeof IntersectionObserver === "undefined") {
      setSeen(true);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setSeen(true);
          io.disconnect();
        }
      },
      { threshold },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [seen, threshold]);
  return { ref, seen };
}

function Reveal({ children, className = "" }: { children: ReactNode; className?: string }) {
  const { ref, seen } = useInView<HTMLDivElement>(0.12);
  return (
    <div ref={ref} className={`reveal${seen ? " in" : ""} ${className}`}>
      {children}
    </div>
  );
}

function CountUp({ to, duration = 1200 }: { to: number; duration?: number }) {
  const { ref, seen } = useInView<HTMLSpanElement>(0.4);
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!seen) return;
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setVal(to);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / duration);
      setVal(Math.round(to * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [seen, to, duration]);
  return <span ref={ref}>{val}</span>;
}

function Ring({ state }: { state: State }) {
  const color = STATE_COLOR[state];
  return (
    <svg width="48" height="48" viewBox="0 0 48 48" aria-hidden="true">
      {state !== "UNAFFECTED" && (
        <circle
          cx="24"
          cy="24"
          r="19"
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeDasharray={state === "EVIDENCE_CONFLICT" ? "6 5" : undefined}
          opacity={state === "RESTORED" ? 0.3 : 1}
        />
      )}
      {state === "RESTORED" && (
        <circle cx="24" cy="24" r="22.5" fill="none" stroke={color} strokeWidth="1.2" opacity="0.2" />
      )}
      <circle cx="24" cy="24" r="11" fill={CORE_FILL[state]} stroke={color} strokeWidth="1.6" />
    </svg>
  );
}

function Receipt({ tx, kicker, title, body, call, result }: {
  tx: string;
  kicker: string;
  title: string;
  body: string;
  call: string;
  result: string;
}) {
  return (
    <a className="receipt" href={txUrl(tx)} target="_blank" rel="noreferrer">
      <div>
        <span className="mono receipt-k">{kicker}</span>
        <h3>{title}</h3>
        <p>{body}</p>
      </div>
      <dl className="receipt-r mono">
        <div>
          <dt>From</dt>
          <dd>{short(BYSTANDER_WALLET)}</dd>
        </div>
        <div>
          <dt>Call</dt>
          <dd>{call}</dd>
        </div>
        <div>
          <dt>Result</dt>
          <dd className="ok">{result}</dd>
        </div>
        <div>
          <dt>Tx</dt>
          <dd>
            {short(tx)} {"↗"}
          </dd>
        </div>
      </dl>
    </a>
  );
}

export default function Marketing() {
  const demo = useDemoScript();

  return (
    <Shell variant="marketing">
      <section className="hero grid-bg">
        <div className="container hero-inner">
          <div>
            <p className="eyebrow">
              <span className="eyebrow-dot" />
              Dependency containment
            </p>
            <h1 className="hero-title">
              One package gets compromised.
              <br />
              <span className="hero-accent">Who is exposed?</span>
            </h1>
            <p className="hero-sub">
              When an agent skill is compromised, Quarantine decides which deployments are materially exposed, including
              wrappers that vendor it, and the capability host refuses to run them until a verified fix is pinned.{" "}
              <strong>Validators read the code. The host obeys.</strong>
            </p>
            <div className="hero-cta">
              <Link to="/console" className="btn btn-ink">
                Open console
              </Link>
            </div>
            <p className="hero-meta mono">Live on GenLayer Studio · 70 tests · no operator anywhere</p>
          </div>

          <div className="map-card">
            <div className="map-card-head mono">
              <span>CONTAINMENT MAP</span>
              <span>ADV-001 · payout_skill</span>
            </div>
            <ContainmentMap
              key={demo.cycle}
              packageName="payout_skill"
              versions={demo.versions}
              nodes={demo.nodes}
              pulse={demo.pulse}
              ariaLabel="Animated containment map: an advisory lands, exact pins resolve by hash, forks go to validators, one deployment is held, one is restored."
            />
            <div className="map-caption">
              <span className="mono map-step">
                {String(demo.phase + 1).padStart(2, "0")} / {String(demo.total).padStart(2, "0")}
              </span>
              <span>{demo.caption}</span>
            </div>
            <StateLegend />
          </div>
        </div>
      </section>

      <section className="stats">
        <div className="container stats-grid">
          <div className="stat-cell">
            <span className="stat-num">
              <CountUp to={70} />
            </span>
            <span className="stat-lab">tests against the real contract code</span>
          </div>
          <div className="stat-cell">
            <span className="stat-num">
              <CountUp to={0} />
            </span>
            <span className="stat-lab">skipped</span>
          </div>
          <div className="stat-cell">
            <span className="stat-num">
              <CountUp to={2} />
            </span>
            <span className="stat-lab">on-chain receipts from a wallet with no role</span>
          </div>
          <div className="stat-cell">
            <span className="stat-num">
              <CountUp to={0} />
            </span>
            <span className="stat-lab">privileged roles in the lifecycle</span>
          </div>
        </div>
      </section>

      <section className="mk-section">
        <div className="container">
          <Reveal>
            <p className="eyebrow">The problem</p>
            <h2 className="mk-h2">Advisories exist. Containment does not.</h2>
          </Reveal>
          <Reveal className="claims">
            {CLAIMS.map((c) => (
              <div className="claim" key={c.who}>
                <span className="claim-k mono">{c.who}</span>
                <p>{"“" + c.says + "”"}</p>
              </div>
            ))}
          </Reveal>
          <Reveal>
            <p className="mk-lede">
              Someone has to decide which of those claims is true before capabilities are cut or restored. Today that is a
              security team, a registry operator or one scanner. Any of them can be wrong, slow or captured. Quarantine
              moves the decision to independent validators reading the actual code, and the host obeys the result.
            </p>
          </Reveal>
        </div>
      </section>

      <section className="mk-section mk-band">
        <div className="container">
          <Reveal>
            <p className="eyebrow">Hash or consensus</p>
            <h2 className="mk-h2">Consensus is spent only where code cannot decide.</h2>
          </Reveal>
          <Reveal className="split">
            <article className="split-card">
              <span className="badge-lg">#</span>
              <h3>Exact pin? Decided in code.</h3>
              <p>
                When a deployment's pinned bytes match a registered version, the contract compares sha256 hashes and applies
                the advisory directly. Which upstream version a wrapper vendors is decided the same way. No model call, no
                consensus spent.
              </p>
              <p className="split-proof mono">Proven in tests: the model is never called on this path</p>
            </article>
            <article className="split-card">
              <span className="badge-lg">{"•••"}</span>
              <h3>Anything code cannot settle? Validators.</h3>
              <p>
                Prose advisories, divergent forks, claimed patches, wrappers around a flawed dependency, and follow-ups that
                may withdraw or amend an earlier advisory. Validators judge executable code and plain meaning. Comments,
                docstrings and version strings carry no weight.
              </p>
              <p className="split-proof mono">Proven live: renamed skims caught, real fixes and neutralizing wrappers cleared</p>
            </article>
          </Reveal>
          <Reveal>
            <ul className="three-q five-q">
              <li>
                <span className="mono">01</span>
                What a prose advisory says is affected and patched
              </li>
              <li>
                <span className="mono">02</span>
                Whether a divergent fork still carries the flaw
              </li>
              <li>
                <span className="mono">03</span>
                Whether a claimed patch is real in code
              </li>
              <li>
                <span className="mono">04</span>
                Whether a wrapper exposes or neutralizes a vendored flaw
              </li>
              <li>
                <span className="mono">05</span>
                Whether a new advisory withdraws or amends an old one
              </li>
            </ul>
            <p className="mk-note">
              Those are the only questions consensus answers. Where a structured feed exists and every deployment pins a
              registered version, a plain contract would do. Quarantine says so.
            </p>
          </Reveal>
        </div>
      </section>

      <section className="mk-section">
        <div className="container">
          <Reveal>
            <p className="eyebrow">
              <span className="eyebrow-dot" />
              The minority note
            </p>
            <h2 className="mk-h2">Every verdict keeps the strongest case against it.</h2>
            <p className="mk-lede">
              When validators decide, the registry stores their reasoning and the best argument for the other answer, side by
              side, on-chain. Nothing is flattened into a bare yes or no.
            </p>
          </Reveal>
          <Reveal className="verdict">
            <div className="verdict-head mono">
              <span>DEPLOYMENT C · fork 14d5f30 · strict posture</span>
              <span className="verdict-tag">PATCH REQUIRED · decided by validators</span>
            </div>
            <div className="verdict-body">
              <div className="verdict-col">
                <span className="mono verdict-k">VERDICT REASONING</span>
                <p>{C_REASONING}</p>
              </div>
              <div className="verdict-col verdict-minor">
                <span className="mono verdict-k">MINORITY NOTE</span>
                <p>{C_MINORITY}</p>
              </div>
            </div>
            <div className="verdict-foot">
              Real output from the V1 live run, stored on-chain. <Link to="/console">Read every assessment in the console</Link>.
            </div>
          </Reveal>
        </div>
      </section>

      <section className="mk-section mk-band">
        <div className="container">
          <Reveal>
            <p className="eyebrow">
              <span className="eyebrow-dot" />
              Inherited exposure
            </p>
            <h2 className="mk-h2">Same vendored bytes. Opposite verdicts.</h2>
            <p className="mk-lede">
              A wrapper skill vendors a copy of the compromised payout_skill 1.1. Two releases carry the identical vendored
              file. Code can prove that much, and nothing more. Whether callers are still exposed depends on what the
              wrapper's own code does with it, so validators read both.
            </p>
          </Reveal>
          <Reveal className="pair">
            <article className="pair-card exposed">
              <div className="pair-head mono">
                <span>batch_payout 2.0 · vendors 1.1</span>
                <span className="pair-tag">EXPOSED</span>
              </div>
              <p>{W20_REASONING}</p>
            </article>
            <article className="pair-card neutral">
              <div className="pair-head mono">
                <span>batch_payout 2.1 · vendors 1.1</span>
                <span className="pair-tag">NEUTRALIZED</span>
              </div>
              <p>{W21_REASONING}</p>
              <div className="pair-minor">
                <span className="mono verdict-k">MINORITY NOTE</span>
                <p>{W21_MINORITY}</p>
              </div>
            </article>
          </Reveal>
          <Reveal>
            <p className="mk-note">
              Each release is judged once. Every deployment of the wrapper then resolves by hash: on chain, the host refused a
              payout through 2.0 and ran one through 2.1. Real output from the V2 live run, stored in the registry at{" "}
              <span className="mono">{short(REGISTRY_ADDRESS)}</span>.
            </p>
          </Reveal>
        </div>
      </section>

      <section className="mk-section">
        <div className="container">
          <Reveal>
            <p className="eyebrow">The five states</p>
            <h2 className="mk-h2">A register, not a red light.</h2>
          </Reveal>
          <Reveal className="states">
            {STATES.map((x) => (
              <article className="state-card" key={x.s}>
                <Ring state={x.s} />
                <h3 style={{ color: STATE_COLOR[x.s] }}>{STATE_LABEL[x.s]}</h3>
                <p>{x.meaning}</p>
                <p className="state-host mono">HOST · {x.host}</p>
              </article>
            ))}
          </Reveal>
        </div>
      </section>

      <section className="mk-section mk-band">
        <div className="container">
          <Reveal>
            <p className="eyebrow">Trust model</p>
            <h2 className="mk-h2">No operator, anywhere.</h2>
          </Reveal>
          <Reveal className="trust">
            {TRUST.map((t) => (
              <article className="trust-card" key={t.title}>
                <h3>{t.title}</h3>
                <p>{t.body}</p>
              </article>
            ))}
          </Reveal>
          <Reveal className="receipts">
            <Receipt
              tx={BYSTANDER_RECEIPT_TX}
              kicker="V1 PROOF · ON-CHAIN RECEIPT"
              title="A wallet with no role restored a deployment."
              body="It is not the maintainer, not an owner, not the issuer and not the deployer. It reassessed a deployment after a verified re-pin, and the registry restored it."
              call="assess_dependent(1, 1)"
              result="RESTORED"
            />
            <Receipt
              tx={WITHDRAW_RECEIPT_TX}
              kicker="V2 PROOF · ON-CHAIN RECEIPT"
              title="The same wallet released a false positive."
              body="A mistaken advisory wrongly blocked a clean deployment. That wallet filed the retraction, validators judged it a full withdrawal, and containment lifted with no operator involved."
              call="report_followup(5, ...)"
              result="WITHDRAWN"
            />
          </Reveal>
        </div>
      </section>

      <section className="mk-cta">
        <div className="container cta-inner">
          <h2>
            Validators read the code.
            <br />
            The host obeys.
          </h2>
          <div className="cta-actions">
            <Link to="/console" className="btn btn-ink">
              Open console
            </Link>
            <Link to="/guide" className="btn btn-ghost">
              Walk the live run
            </Link>
          </div>
          <p className="mono cta-meta">
            <a href={REPO_URL} target="_blank" rel="noreferrer">
              Source, 70 tests and TESTING.md on GitHub
            </a>
          </p>
        </div>
      </section>
    </Shell>
  );
}
