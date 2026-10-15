import { useCallback, useEffect, useRef, useState } from "react";
import {
  getCounts,
  getPackage,
  getAdvisory,
  getDependent,
  getAssessment,
  getOperator,
  getRunnerConfig,
  getDerived,
  getPropagation,
} from "./contracts";
import type {
  Package,
  Advisory,
  Dependent,
  Assessment,
  RunnerConfig,
  Propagation,
} from "./contracts";

export interface DepView {
  dep: Dependent;
  assessments: Record<string, Assessment>;
  operator: string;
}

export interface PropView {
  upstreamAdvisory: Advisory;
  derivedId: string;
  propagation: Propagation | null;
  failed: boolean;
}

export interface PackageView {
  pkg: Package;
  advisories: Advisory[];
  deps: DepView[];
  upstreamName: string;
  upstreamFailed: boolean;
  props: PropView[];
}

export interface PackageSummary {
  id: string;
  name: string;
  versions: number;
  dependents: number;
  open: number;
  upstream: string;
}

async function inBatches<T, R>(items: T[], size: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += size) {
    const chunk = await Promise.all(items.slice(i, i + size).map(fn));
    out.push(...chunk);
  }
  return out;
}

async function loadProp(ua: Advisory, packageId: string): Promise<PropView> {
  try {
    const derivedId = await getDerived(ua.id, packageId);
    const propagation = derivedId ? await getPropagation(derivedId) : null;
    return { upstreamAdvisory: ua, derivedId, propagation, failed: false };
  } catch {
    return { upstreamAdvisory: ua, derivedId: "", propagation: null, failed: true };
  }
}

async function loadPackage(pkg: Package, address: string | null): Promise<PackageView> {
  const advisories = await inBatches(pkg.advisory_ids, 2, (aid) => getAdvisory(aid));
  const deps = await inBatches(pkg.dependent_ids, 2, (did) => getDependent(did));
  const views = await inBatches(deps, 2, async (dep): Promise<DepView> => {
    const pairs: [string, Assessment][] = [];
    for (const aid of pkg.open_advisory_ids) {
      pairs.push([aid, await getAssessment(aid, dep.id)]);
    }
    // The operator only decides whether the owner sees Bind or Execute, so it
    // is read only for deployments the connected wallet owns.
    const operator =
      address && address === dep.owner ? await getOperator(dep.id).catch(() => "") : "";
    return { dep, assessments: Object.fromEntries(pairs), operator };
  });

  // Upstream and propagation reads are isolated: if they fail, the rest of the
  // package still renders and only the Inherited exposure panel says so.
  let upstreamName = "";
  let upstreamFailed = false;
  let props: PropView[] = [];
  if (pkg.upstream) {
    try {
      const up = await getPackage(pkg.upstream);
      upstreamName = up.name;
      const upstreamAdvisories = await inBatches(up.open_advisory_ids, 2, (aid) => getAdvisory(aid));
      props = await inBatches(upstreamAdvisories, 1, (ua) => loadProp(ua, pkg.id));
    } catch {
      upstreamFailed = true;
    }
  }
  return { pkg, advisories, deps: views, upstreamName, upstreamFailed, props };
}

export function useRegistry(selectedId: string, address: string | null) {
  const [summaries, setSummaries] = useState<PackageSummary[]>([]);
  const [view, setView] = useState<PackageView | null>(null);
  const [runner, setRunner] = useState<RunnerConfig | null>(null);
  const [runnerError, setRunnerError] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const selectedRef = useRef(selectedId);
  const addressRef = useRef(address);

  const readRunner = useCallback(async (): Promise<boolean> => {
    try {
      setRunner(await getRunnerConfig());
      setRunnerError("");
      return true;
    } catch (e) {
      setRunnerError(String((e as any)?.message ?? e));
      return false;
    }
  }, []);

  // The runner is the last read in a burst, so it is the one Studio throttles.
  // Retry that single read quietly in the background instead of making a
  // visitor press a button.
  const reloadRunner = useCallback(async () => {
    if (await readRunner()) return;
    void (async () => {
      for (let i = 0; i < 3; i++) {
        await new Promise((r) => setTimeout(r, 15000));
        if (await readRunner()) return;
      }
    })();
  }, [readRunner]);

  const reload = useCallback(async () => {
    const counts = await getCounts();
    const ids = Array.from({ length: Number(counts.packages) }, (_, i) => String(i + 1));
    const pkgs = await inBatches(ids, 2, (id) => getPackage(id));
    setSummaries(
      pkgs.map((p) => ({
        id: p.id,
        name: p.name,
        versions: p.versions.length,
        dependents: p.dependent_ids.length,
        open: p.open_advisory_ids.length,
        upstream: p.upstream,
      })),
    );
    const chosen = pkgs.find((p) => p.id === selectedRef.current) ?? pkgs[0] ?? null;
    setView(chosen ? await loadPackage(chosen, addressRef.current) : null);
    setError("");
    await reloadRunner();
  }, [reloadRunner]);

  useEffect(() => {
    selectedRef.current = selectedId;
    addressRef.current = address;
    let alive = true;
    setLoading(true);
    reload()
      .catch((e) => {
        if (alive) setError(String(e?.message ?? e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [selectedId, address, reload]);

  return { summaries, view, runner, runnerError, loading, error, reload, reloadRunner };
}
