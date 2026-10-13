import { Link } from "react-router-dom";
import Shell from "../components/Shell";
import ContainmentMap, { StateLegend } from "../components/ContainmentMap";
import { useDemoScript } from "../components/useDemoScript";

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
              When an agent skill is compromised, Quarantine decides which deployments are materially
              exposed, and the capability host refuses to run them until a verified fix is pinned.{" "}
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
    </Shell>
  );
}
