import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import Shell from "../components/Shell";
import ContainmentMap, { StateLegend, STATE_COLOR, STATE_LABEL } from "../components/ContainmentMap";
import { useDemoScript } from "../components/useDemoScript";
import type { State } from "../lib/contracts";
import { BYSTANDER_RECEIPT_TX, BYSTANDER_WALLET, REGISTRY_ADDRESS, REPO_URL, txUrl } from "../lib/contracts";
import { short } from "../lib/format";
import "../marketing.css";

// Real output from the live run: assessment of Deployment C against advisory 1.
const C_REASONING =
  "The build_transfers function in the deployment file calculates a reserve amount using OPS_RESERVE_BPS (150) and subtracts it from the total payout. It then appends a transfer of this reserve amount to OPS_RESERVE_WALLET, which is a hardcoded address equivalent to the one in the affected version.";
const C_MINORITY =
  "One could argue that the deployment file uses different function and variable names such as build_transfers and OPS_RESERVE_WALLET, but the underlying logic of diverting 150 basis points to a hardcoded address remains functionally identical to the vulnerable pattern.";

const CLAIMS = [
  { who: "The maintainer", says: "Only 1.1 is affected." },
  { who: "A fork", says: "We cherry-picked the fix." },
  { who: "A deployment", says: "We are on a patched commit." },
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
    body: "The repo, the skill file path and the advisory folder are fixed at registration. Every URL is commit-pinned, so the bytes cannot change under a verdict, and a reporter cannot point the contract anywhere else.",
  },
  {
    title: "Re-pinning never unblocks",
    body: "A re-pin changes no state. Every existing assessment goes stale, and a stale assessment blocks until someone reassesses the new pin. Only a fresh verdict restores.",
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
              When an agent skill is compromised, Quarantine decides which deployments are materially exposed, and the
              capability host refuses to run them until a verified fix is pinned.{" "}
              <strong>Validators read the code. The host obeys.</strong>
            </p>
            <div className="hero-cta">
              <Link to="/console" className="btn btn-ink">
                Open console
              </Link>
            </div>
            <p className="hero-meta mono">Live on GenLayer Studio · 48 tests · no operator anywhere</p>
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
              <CountUp to={48} />
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
              <CountUp to={8} />
            </span>
            <span className="stat-lab">on-chain steps in the live proof</span>
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
                the advisory directly. No model call, no consensus spent.
              </p>
              <p className="split-proof mono">Proven in tests: the model is never called on this path</p>
            </article>
            <article className="split-card">
              <span className="badge-lg">{"•••"}</span>
              <h3>Fork or patch claim? Decided by validators.</h3>
              <p>
                When the bytes match nothing registered, validators read the deployment's executable code against the
                advisory's vulnerable pattern. Comments, docstrings and version strings carry no weight. Renaming a flaw
                does not hide it.
              </p>
              <p className="split-proof mono">Proven live: a renamed skim was caught, a real fix was cleared</p>
            </article>
          </Reveal>
          <Reveal>
            <ul className="three-q">
              <li>
                <span className="mono">01</span>
                What a prose advisory actually says is affected and patched
              </li>
              <li>
                <span className="mono">02</span>
                Whether a divergent fork still carries the flaw
              </li>
              <li>
                <span className="mono">03</span>
                Whether a claimed patch is real in code
              </li>
            </ul>
            <p className="mk-note">
              Those are the three questions only consensus answers. Where a structured feed exists and every deployment pins
              a registered version, a plain contract would do. Quarantine says so.
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
              When validators decide a fork, the registry stores their reasoning and the best argument for the other answer,
              side by side, on-chain. Nothing is flattened into a bare yes or no.
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
              Real output from the live run, stored in the registry at{" "}
              <span className="mono">{short(REGISTRY_ADDRESS)}</span>. <Link to="/console">Read every assessment in the console</Link>.
            </div>
          </Reveal>
          <Reveal>
            <p className="mk-note">
              When the answer is genuinely too close to call, the deployment is held as Evidence conflict instead of being
              killed. Anyone can escalate it to a forcing pass that must commit, or honestly return unresolved.
            </p>
          </Reveal>
        </div>
      </section>

      <section className="mk-section mk-band">
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

      <section className="mk-section">
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
          <Reveal>
            <a className="receipt" href={txUrl(BYSTANDER_RECEIPT_TX)} target="_blank" rel="noreferrer">
              <div>
                <span className="mono receipt-k">PROOF · ON-CHAIN RECEIPT</span>
                <h3>A wallet with no role restored a deployment.</h3>
                <p>
                  Wallet {short(BYSTANDER_WALLET)} is not the maintainer, not an owner, not the issuer and not the deployer.
                  It reassessed Deployment A after a verified re-pin, and the registry restored it.
                </p>
              </div>
              <dl className="receipt-r mono">
                <div>
                  <dt>From</dt>
                  <dd>{short(BYSTANDER_WALLET)}</dd>
                </div>
                <div>
                  <dt>Call</dt>
                  <dd>assess_dependent(1, 1)</dd>
                </div>
                <div>
                  <dt>Result</dt>
                  <dd className="ok">RESTORED</dd>
                </div>
                <div>
                  <dt>Tx</dt>
                  <dd>{short(BYSTANDER_RECEIPT_TX)} {"↗"}</dd>
                </div>
              </dl>
            </a>
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
              Source, 48 tests and TESTING.md on GitHub
            </a>
          </p>
        </div>
      </section>
    </Shell>
  );
}
