import { useEffect, useState } from "react";
import type { MapNode, MapVersion } from "./ContainmentMap";

const DURATIONS = [1700, 1800, 1500, 2300, 2700, 3600];

export const DEMO_STEPS = [
  "A package with three versions. Four deployments depend on it.",
  "ADV-001 lands. Validators read the prose: 1.1 is affected, 1.2 is patched.",
  "Exposure propagates outward from the compromised version.",
  "Exact pins resolve in code by hash. No consensus spent.",
  "Forks go to validators. One still skims and is contained. One is too close to call, so it is held, not killed.",
  "A re-pins to 1.2. A bystander reassesses. Restored, and the host runs it again.",
];

export function useDemoScript() {
  const [phase, setPhase] = useState(0);
  const [cycle, setCycle] = useState(0);

  useEffect(() => {
    if (
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      setPhase(DURATIONS.length - 1);
      return;
    }
    let timer = 0;
    let p = 0;
    const step = () => {
      timer = window.setTimeout(() => {
        if (p >= DURATIONS.length - 1) {
          p = 0;
          setCycle((c) => c + 1);
        } else {
          p += 1;
        }
        setPhase(p);
        step();
      }, DURATIONS[p]);
    };
    step();
    return () => window.clearTimeout(timer);
  }, []);

  const versions: MapVersion[] = [
    { label: "1.0", status: "clean" },
    { label: "1.1", status: phase >= 1 ? "affected" : "clean" },
    { label: "1.2", status: phase >= 1 ? "patched" : "clean" },
  ];

  const nodes: MapNode[] = [
    {
      id: "a",
      name: "A",
      pin: phase >= 5 ? "pin 1.1 to 1.2" : "pin 1.1",
      state: phase >= 5 ? "RESTORED" : phase >= 3 ? "PATCH_REQUIRED" : "PENDING",
      via: phase >= 3 ? "hash" : null,
    },
    {
      id: "b",
      name: "B",
      pin: "pin 1.0",
      state: phase >= 3 ? "UNAFFECTED" : "PENDING",
      via: phase >= 3 ? "hash" : null,
    },
    {
      id: "d",
      name: "D",
      pin: "fork, fix claimed",
      state: phase >= 4 ? "EVIDENCE_CONFLICT" : "PENDING",
      via: phase >= 4 ? "consensus" : null,
    },
    {
      id: "c",
      name: "C",
      pin: "fork, renamed",
      state: phase >= 4 ? "PATCH_REQUIRED" : "PENDING",
      via: phase >= 4 ? "consensus" : null,
    },
  ];

  return {
    phase,
    cycle,
    total: DURATIONS.length,
    caption: DEMO_STEPS[phase],
    versions,
    nodes,
    pulse: phase === 2 ? cycle : null,
  };
}
