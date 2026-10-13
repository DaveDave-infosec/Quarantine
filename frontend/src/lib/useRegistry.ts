import { useCallback, useEffect, useRef, useState } from "react";
import {
  getCounts,
  getPackage,
  getAdvisory,
  getDependent,
  getAssessment,
  getOperator,
  getRunnerConfig,
} from "./contracts";
import type { Package, Advisory, Dependent, Assessment, RunnerConfig } from "./contracts";

export interface DepView {
  dep: Dependent;
  assessments: Record<string, Assessment>;
  operator: string;
}

export interface PackageView {
  pkg: Package;
  advisories: Advisory[];
  deps: DepView[];
}

export interface PackageSummary {
  id: string;
  name: string;
  versions: number;
  dependents: number;
  open: number;
}

async function inBatches<T, R>(items: T[], size: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += size) {
    const chunk = await Promise.all(items.slice(i, i + size).map(fn));
    out.push(...chunk);
  }
  return out;
}

async function loadPackage(pkg: Package, address: string | null): Promise<PackageView> {
  const advisories = await inBatches(pkg.advisory_ids, 3, (aid) => getAdvisory(aid));
  const deps = await inBatches(pkg.dependent_ids, 3, (did) => getDependent(did));
  const views = await inBatches(deps, 3, async (dep): Promise<DepView> => {
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
  return { pkg, advisories, deps: views };
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

  const reloadRunner = useCallback(async () => {
    try {
      setRunner(await getRunnerConfig());
      setRunnerError("");
    } catch (e) {
      setRunnerError(String((e as any)?.message ?? e));
    }
  }, []);

  const reload = useCallback(async () => {
    const counts = await getCounts();
    const ids = Array.from({ length: Number(counts.packages) }, (_, i) => String(i + 1));
    const pkgs = await inBatches(ids, 3, (id) => getPackage(id));
    setSummaries(
      pkgs.map((p) => ({
        id: p.id,
        name: p.name,
        versions: p.versions.length,
        dependents: p.dependent_ids.length,
        open: p.open_advisory_ids.length,
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
