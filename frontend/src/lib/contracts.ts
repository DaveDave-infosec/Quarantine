import { readContract, writeContract, toPlain } from "./genlayer";
import type { WriteResult } from "./genlayer";

// Single source of truth for every address shown anywhere in the app.
export const REGISTRY_ADDRESS = "0xbE5BeB80AE04F5F363F2bf371607EAd61cbC894a";
export const RUNNER_ADDRESS = "0xE7d2f39B6CC7F3Bdeb71f53D26CB206153644A5a";
export const CHAIN_LABEL = "GenLayer Studio, chainId 61999";
export const EXPLORER = "https://explorer-studio.genlayer.com";
export const BYSTANDER_RECEIPT_TX =
  "0x92972310f8d2b37d0038216bb6d58fc2361c95dbdc245c6d1c1336c23344fd74";
export const BYSTANDER_WALLET = "0xD7cd43cBc01f767A74909943Cec29e20dB4e7cc3";
export const REPO_URL = "https://github.com/DaveDave-infosec/Quarantine";
export const DEMO_REPO_URL = "https://github.com/DaveDave-infosec/quarantine-demo-skills";
export const DEMO_FORK_URL = "https://github.com/DaveDave-infosec/quarantine-demo-fork";

export function txUrl(hash: string): string {
  return `${EXPLORER}/tx/${hash}`;
}

export function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export type State =
  | "QUARANTINED"
  | "PATCH_REQUIRED"
  | "UNAFFECTED"
  | "EVIDENCE_CONFLICT"
  | "RESTORED";

export type Capability = "allowed" | "warn" | "blocked";

export interface Version {
  label: string;
  sha: string;
  file_hash: string;
}

export interface Package {
  id: string;
  name: string;
  maintainer: string;
  repo_prefix: string;
  source_path: string;
  advisory_dir: string;
  versions: Version[];
  dependent_ids: string[];
  advisory_ids: string[];
  open_advisory_ids: string[];
}

export interface Dependent {
  id: string;
  package_id: string;
  owner: string;
  repo_prefix: string;
  pinned_sha: string;
  posture: "standard" | "strict";
  pin_nonce: string;
  capability: Capability;
}

export interface Advisory {
  id: string;
  package_id: string;
  url: string;
  status: string;
  reporter: string;
  reported_at: string;
  affected_labels: string[];
  patched_labels: string[];
  vulnerable_pattern: string;
  summary: string;
}

export interface Assessment {
  exists: boolean;
  state?: State;
  path?: "hash" | "consensus" | "escalation" | "size";
  matched_label?: string;
  file_hash?: string;
  reasoning?: string;
  minority_note?: string;
  conflict_reason?: string;
  assessor?: string;
  assessed_at?: string;
  count?: string;
  stale?: boolean;
}

export interface Counts {
  packages: string;
  dependents: string;
  advisories: string;
}

export interface RunnerConfig {
  registry: string;
  issuer: string;
  max_supply: string;
  minted: string;
  vault: string;
  executions: string;
}

export interface Execution {
  id: string;
  dependent_id: string;
  operator: string;
  recipient: string;
  amount: string;
  capability: Capability;
  executed_at: string;
}

async function reg(functionName: string, args: any[] = []): Promise<any> {
  return toPlain(await readContract({ address: REGISTRY_ADDRESS, functionName, args }));
}

async function run(functionName: string, args: any[] = []): Promise<any> {
  return toPlain(await readContract({ address: RUNNER_ADDRESS, functionName, args }));
}

// ---------- registry reads ----------

export const getCounts = (): Promise<Counts> => reg("get_counts");
export const getPackage = (id: string): Promise<Package> => reg("get_package", [id]);
export const getDependent = (id: string): Promise<Dependent> => reg("get_dependent", [id]);
export const getAdvisory = (id: string): Promise<Advisory> => reg("get_advisory", [id]);
export const getAssessment = (advisoryId: string, dependentId: string): Promise<Assessment> =>
  reg("get_assessment", [advisoryId, dependentId]);
export const getCapability = (dependentId: string): Promise<Capability> =>
  reg("get_capability", [dependentId]);

// ---------- runner reads ----------

export const getRunnerConfig = (): Promise<RunnerConfig> => run("get_config");
export const getRunnerBalance = (account: string): Promise<string> => run("balance_of", [account]);
export const getOperator = (dependentId: string): Promise<string> => run("get_operator", [dependentId]);
export const getExecution = (id: string): Promise<Execution> => run("get_execution", [id]);

// ---------- registry writes ----------

const regWrite = (functionName: string, args: any[]): Promise<WriteResult> =>
  writeContract({ address: REGISTRY_ADDRESS, functionName, args });

const runWrite = (functionName: string, args: any[]): Promise<WriteResult> =>
  writeContract({ address: RUNNER_ADDRESS, functionName, args });

export const registerPackage = (
  name: string,
  repoPrefix: string,
  sourcePath: string,
  advisoryDir: string,
  versions: string,
) => regWrite("register_package", [name, repoPrefix, sourcePath, advisoryDir, versions]);

export const addVersion = (packageId: string, label: string, sha: string) =>
  regWrite("add_version", [packageId, label, sha]);

export const registerDependent = (
  packageId: string,
  repoPrefix: string,
  sha: string,
  posture: "standard" | "strict",
) => regWrite("register_dependent", [packageId, repoPrefix, sha, posture]);

export const repinDependent = (dependentId: string, repoPrefix: string, sha: string) =>
  regWrite("repin_dependent", [dependentId, repoPrefix, sha]);

export const reportAdvisory = (packageId: string, url: string) =>
  regWrite("report_advisory", [packageId, url, nowIso()]);

export const assessDependent = (advisoryId: string, dependentId: string) =>
  regWrite("assess_dependent", [advisoryId, dependentId, nowIso()]);

export const escalate = (advisoryId: string, dependentId: string) =>
  regWrite("escalate", [advisoryId, dependentId, nowIso()]);

// ---------- runner writes ----------

export const bindSkill = (dependentId: string) => runWrite("bind_skill", [dependentId]);

export const executeSkill = (dependentId: string, recipient: string, amount: number) =>
  runWrite("execute", [dependentId, recipient, amount, nowIso()]);

export const mint = (amount: number) => runWrite("mint", [amount]);
