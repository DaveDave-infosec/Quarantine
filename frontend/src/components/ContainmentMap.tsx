import { useEffect, useState } from "react";
import type { CSSProperties } from "react";
import type { State } from "../lib/contracts";

export type MapState = State | "PENDING";
export type MapVia = "hash" | "consensus" | "escalation" | "size" | null;

export interface MapNode {
  id: string;
  name: string;
  pin: string;
  state: MapState;
  via: MapVia;
}

export interface MapVersion {
  label: string;
  status: "clean" | "affected" | "patched";
}

export const STATE_COLOR: Record<State, string> = {
  QUARANTINED: "var(--s-quarantined)",
  PATCH_REQUIRED: "var(--s-patch)",
  UNAFFECTED: "var(--s-unaffected)",
  EVIDENCE_CONFLICT: "var(--s-conflict)",
  RESTORED: "var(--s-restored)",
};

export const STATE_LABEL: Record<MapState, string> = {
  QUARANTINED: "Quarantined",
  PATCH_REQUIRED: "Patch required",
  UNAFFECTED: "Unaffected",
  EVIDENCE_CONFLICT: "Evidence conflict",
  RESTORED: "Restored",
  PENDING: "Not assessed",
};

const CX = 320;
const CY = 214;
const RX = 228;
const RY = 140;
const RING = 36;
const CIRC = 2 * Math.PI * RING;

interface Pt {
  x: number;
  y: number;
}

function nodePos(i: number, n: number): Pt {
  const step = 360 / Math.max(n, 1);
  const a = ((-135 + i * step) * Math.PI) / 180;
  return { x: CX + RX * Math.cos(a), y: CY + RY * Math.sin(a) };
}

function versionPos(i: number, n: number): Pt {
  const a = ((-90 + (i - (n - 1) / 2) * 36) * Math.PI) / 180;
  return { x: CX + 66 * Math.cos(a), y: CY + 66 * Math.sin(a) };
}

function haloStyle(state: MapState): CSSProperties {
  if (state === "PENDING" || state === "UNAFFECTED") {
    return { stroke: "var(--hair)", strokeDasharray: `${CIRC}`, strokeDashoffset: CIRC, opacity: 0 };
  }
  if (state === "EVIDENCE_CONFLICT") {
    return { stroke: STATE_COLOR[state], strokeDasharray: "7 6", strokeDashoffset: 0, opacity: 1 };
  }
  return {
    stroke: STATE_COLOR[state],
    strokeDasharray: `${CIRC}`,
    strokeDashoffset: 0,
    opacity: state === "RESTORED" ? 0 : 1,
  };
}

function Pulses({ from, targets }: { from: Pt; targets: Pt[] }) {
  const [go, setGo] = useState(false);
  useEffect(() => {
    let second = 0;
    const first = requestAnimationFrame(() => {
      second = requestAnimationFrame(() => setGo(true));
    });
    return () => {
      cancelAnimationFrame(first);
      cancelAnimationFrame(second);
    };
  }, []);
  return (
    <g>
      {targets.map((t, i) => (
        <g
          key={i}
          className={"cm-pulse" + (go ? " go" : "")}
          style={{ transform: `translate(${go ? t.x : from.x}px, ${go ? t.y : from.y}px)` }}
        >
          <circle r={5} />
        </g>
      ))}
    </g>
  );
}

interface Props {
  packageName: string;
  versions: MapVersion[];
  nodes: MapNode[];
  pulse?: number | null;
  ariaLabel?: string;
}

export default function ContainmentMap({
  packageName,
  versions,
  nodes,
  pulse = null,
  ariaLabel,
}: Props) {
  const vpos = versions.map((_, i) => versionPos(i, versions.length));
  const npos = nodes.map((_, i) => nodePos(i, nodes.length));
  const affectedIdx = versions.findIndex((v) => v.status === "affected");
  const from = affectedIdx >= 0 ? vpos[affectedIdx] : { x: CX, y: CY };

  return (
    <svg className="cm" viewBox="0 0 640 440" role="img" aria-label={ariaLabel ?? "Containment map"}>
      <g>
        {nodes.map((n, i) => {
          const exposed = n.state === "QUARANTINED" || n.state === "PATCH_REQUIRED";
          return (
            <line
              key={n.id}
              className="cm-edge"
              x1={CX}
              y1={CY}
              x2={npos[i].x}
              y2={npos[i].y}
              style={{
                stroke: exposed ? STATE_COLOR[n.state as State] : "var(--hair)",
                strokeDasharray: n.state === "EVIDENCE_CONFLICT" ? "4 5" : "none",
                opacity: exposed ? 0.75 : 1,
              }}
            />
          );
        })}
      </g>

      <circle className="cm-orbit" cx={CX} cy={CY} r={66} />
      <circle className="cm-pkg" cx={CX} cy={CY} r={44} />
      <text className="cm-pkg-kicker" x={CX} y={CY - 6}>
        PACKAGE
      </text>
      <text className="cm-pkg-name" x={CX} y={CY + 12}>
        {packageName}
      </text>

      {versions.map((v, i) => (
        <g key={v.label} className={`cm-ver v-${v.status}`} transform={`translate(${vpos[i].x} ${vpos[i].y})`}>
          {v.status === "affected" && <circle className="cm-ver-halo" r={12} />}
          <circle className="cm-ver-dot" r={6.5} />
          <text className="cm-ver-label" y={-14}>
            {v.label}
          </text>
        </g>
      ))}

      {pulse !== null && <Pulses key={pulse} from={from} targets={npos} />}

      {nodes.map((n, i) => (
        <g
          key={n.id}
          className={`cm-node s-${n.state.toLowerCase()}`}
          transform={`translate(${npos[i].x} ${npos[i].y})`}
        >
          <circle className="cm-halo" r={RING} style={haloStyle(n.state)} />
          <circle className="cm-core" r={24} />
          <text className="cm-name" y={6}>
            {n.name}
          </text>
          {n.via && (
            <g transform="translate(21 -21)">
              <g className="cm-badge-in" key={n.via}>
                <circle className="bg" r={10} />
                {n.via === "hash" ? (
                  <text y={4}>#</text>
                ) : n.via === "size" ? (
                  <text y={4}>!</text>
                ) : (
                  <g>
                    <circle className="dot" cx={-4} cy={0} r={1.7} />
                    <circle className="dot" cx={0} cy={0} r={1.7} />
                    <circle className="dot" cx={4} cy={0} r={1.7} />
                  </g>
                )}
              </g>
            </g>
          )}
          <text className="cm-pin" y={56}>
            {n.pin}
          </text>
          <text
            className="cm-state"
            y={73}
            style={{ fill: n.state === "PENDING" ? "var(--faint)" : STATE_COLOR[n.state as State] }}
          >
            {STATE_LABEL[n.state].toUpperCase()}
          </text>
        </g>
      ))}
    </svg>
  );
}

export function StateLegend() {
  const states: State[] = ["QUARANTINED", "PATCH_REQUIRED", "UNAFFECTED", "EVIDENCE_CONFLICT", "RESTORED"];
  return (
    <ul className="legend">
      {states.map((s) => (
        <li key={s}>
          <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
            <circle
              cx="9"
              cy="9"
              r="6.5"
              fill="none"
              stroke={STATE_COLOR[s]}
              strokeWidth="2.2"
              strokeDasharray={s === "EVIDENCE_CONFLICT" ? "3 2.4" : undefined}
            />
          </svg>
          {STATE_LABEL[s]}
        </li>
      ))}
      <li>
        <span className="legend-badge">#</span> decided by hash
      </li>
      <li>
        <span className="legend-badge">{"•••"}</span> decided by validators
      </li>
    </ul>
  );
}
