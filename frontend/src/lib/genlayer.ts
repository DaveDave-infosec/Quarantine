import { createClient, createAccount, generatePrivateKey } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

export const CHAIN_ID = 61999 as const;
const BURNER_KEY = "quarantine_burner_pk";

export function normAddr(a: string): string {
  return a.toLowerCase();
}

type Mode = "metamask" | "demo";
let mode: Mode = "demo";
let mmAddress: string | null = null;
let mmProvider: any = null;
let burnerAccount: any = null;
let submitListener: ((hash: string) => void) | null = null;

// The console registers a listener so it can show "submitted" the moment a
// transaction hash exists, before finalization.
export function onTxSubmitted(fn: ((hash: string) => void) | null): void {
  submitListener = fn;
}

export function setWalletProvider(p: any): void {
  mmProvider = p;
}

function applyProvider(): void {
  if (mmProvider && typeof window !== "undefined") {
    (window as any).ethereum = mmProvider;
  }
}

function getBurner(): any {
  if (!burnerAccount) {
    let pk: string | null = null;
    try {
      pk = localStorage.getItem(BURNER_KEY);
    } catch {
      pk = null;
    }
    if (!pk) {
      pk = generatePrivateKey();
      try {
        localStorage.setItem(BURNER_KEY, pk);
      } catch {
        // storage unavailable, the burner lives for this page load only
      }
    }
    burnerAccount = createAccount(pk as `0x${string}`);
  }
  return burnerAccount;
}

export function resetBurner(): void {
  try {
    localStorage.removeItem(BURNER_KEY);
  } catch {
    // storage unavailable
  }
  burnerAccount = null;
}

export function activateDemo(): string {
  mode = "demo";
  const acct = getBurner();
  return acct.address as string;
}

export function activateMetaMask(address: string): void {
  mode = "metamask";
  mmAddress = address;
}

export function currentMode(): Mode {
  return mode;
}

export function currentAddress(): string | null {
  if (mode === "demo") {
    return burnerAccount ? (burnerAccount.address as string) : null;
  }
  return mmAddress;
}

function getReadClient(): any {
  return createClient({ chain: studionet }) as any;
}

async function getWriteClient(): Promise<any> {
  if (mode === "demo") {
    return createClient({ chain: studionet, account: getBurner() }) as any;
  }
  applyProvider();
  const client = createClient({
    chain: studionet,
    account: mmAddress as `0x${string}`,
  }) as any;
  await client.connect("studionet");
  return client;
}

// viem wraps transport failures: its shortMessage is a generic "unknown RPC
// error" and the real cause ("Failed to fetch") sits in details, message or
// cause. Read every part so network blips are recognised and retried.
function errText(e: any): string {
  const parts = [
    e?.shortMessage,
    e?.details,
    e?.message,
    e?.cause?.shortMessage,
    e?.cause?.message,
    typeof e === "string" ? e : "",
  ];
  return parts
    .filter((p) => typeof p === "string" && p.length > 0)
    .join(" ")
    .toLowerCase();
}

// Only genuine capacity signals count as busy. A loose match on "rate" also
// caught words like "generate" and hid real errors behind retries.
function isBusy(e: any): boolean {
  return /\bbusy\b|\b429\b|rate.?limit|too many requests|no available slot/.test(errText(e));
}

function isNetwork(e: any): boolean {
  return /failed to fetch|networkerror|network error|timed? ?out|timeout|econnreset|socket hang up|\b502\b|\b503\b|\b504\b|bad gateway|service unavailable/.test(
    errText(e),
  );
}

// Studio shares a small pool of execution slots. Keep at most three reads in
// flight; a finished read hands its slot straight to the next one waiting.
const MAX_READS = 2;
let activeReads = 0;
const readQueue: (() => void)[] = [];

// Studio throttles bursts from one browser, and its throttle response reaches
// the browser as a bare "Failed to fetch". Space read starts out as well.
const READ_SPACING_MS = 400;
let lastReadStart = 0;

async function acquireRead(): Promise<void> {
  if (activeReads < MAX_READS) {
    activeReads++;
  } else {
    await new Promise<void>((resolve) => readQueue.push(resolve));
  }
  const now = Date.now();
  const startAt = Math.max(now, lastReadStart + READ_SPACING_MS);
  lastReadStart = startAt;
  if (startAt > now) await sleep(startAt - now);
}

function releaseRead(): void {
  const next = readQueue.shift();
  if (next) next();
  else activeReads--;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// genlayer-js can return contract dicts as Map objects. Normalise to plain JSON.
export function toPlain(v: any): any {
  if (v instanceof Map) {
    const o: Record<string, any> = {};
    v.forEach((val: any, key: any) => {
      o[String(key)] = toPlain(val);
    });
    return o;
  }
  if (Array.isArray(v)) return v.map(toPlain);
  if (typeof v === "bigint") return v.toString();
  return v;
}

export class ContractRevert extends Error {
  txHash: string;
  constructor(message: string, txHash: string) {
    super(message);
    this.name = "ContractRevert";
    this.txHash = txHash;
  }
}

// Pull the contract's own message out of a GenVM traceback.
export function extractContractMessage(stderr: string): string {
  const lines = stderr
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = lines[i].match(/^[A-Za-z_.]*(?:Error|Exception):\s*(.+)$/);
    if (m) return m[1];
  }
  const flat = stderr.match(/(?:AssertionError|UserError|Exception|Error):\s*([^\n]+?)\s*$/);
  return flat ? flat[1] : "";
}

// ACCEPTED and FINALIZED only mean validators agreed. They agree on reverts too.
// Only the leader receipt is authoritative: Studio can cancel the remaining
// validators after quorum and those entries report ERROR on a successful tx.
export function findExecutionError(receipt: any): string | null {
  const leaders = receipt?.consensus_data?.leader_receipt;
  const leader = Array.isArray(leaders) ? leaders[0] : leaders;
  if (!leader) return null;
  const result = String(leader.execution_result ?? "").toUpperCase();
  if (result !== "ERROR") return null;
  const stderr = String(leader?.genvm_result?.stderr ?? "");
  return extractContractMessage(stderr) || "The contract refused this transaction.";
}

export async function readContract(params: {
  address: string;
  functionName: string;
  args?: any[];
}): Promise<any> {
  const client = getReadClient();
  let lastErr: any = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    await acquireRead();
    try {
      return await client.readContract({
        address: params.address as `0x${string}`,
        functionName: params.functionName,
        args: params.args || [],
      });
    } catch (e) {
      lastErr = e;
      if (!(isBusy(e) || isNetwork(e))) throw e;
    } finally {
      releaseRead();
    }
    await sleep(Math.min(12000, 1500 * 2 ** attempt) + Math.floor(Math.random() * 500));
  }
  const detail = String(
    [lastErr?.shortMessage, lastErr?.details].filter(Boolean).join(" ") || lastErr?.message || lastErr || "",
  ).slice(0, 240);
  throw new Error(`The network is busy right now. Please try that again in a moment. (${params.functionName}: ${detail})`);
}

export interface WriteResult {
  txHash: string;
  receipt: any;
}

export async function writeContract(params: {
  address: string;
  functionName: string;
  args?: any[];
}): Promise<WriteResult> {
  const client = await getWriteClient();

  let txHash: any = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      txHash = await client.writeContract({
        address: params.address as `0x${string}`,
        functionName: params.functionName,
        args: params.args || [],
        value: 0n,
      });
      break;
    } catch (e) {
      if (isBusy(e) || isNetwork(e)) {
        await sleep(2000 * (attempt + 1));
        continue;
      }
      throw e;
    }
  }
  if (!txHash) {
    throw new Error("Could not submit the transaction. The network may be busy; please try again.");
  }
  if (submitListener) submitListener(String(txHash));

  for (let attempt = 0; attempt < 75; attempt++) {
    try {
      const receipt = await client.waitForTransactionReceipt({
        hash: txHash,
        status: "FINALIZED",
        interval: 4000,
        retries: 3,
      });
      const err = findExecutionError(receipt);
      if (err) throw new ContractRevert(err, String(txHash));
      return { txHash: String(txHash), receipt };
    } catch (e) {
      if (e instanceof ContractRevert) throw e;
      if (isBusy(e) || isNetwork(e)) {
        await sleep(4000);
        continue;
      }
      const msg = String((e as any)?.message || e).toLowerCase();
      if (msg.includes("finalized") || msg.includes("timed out") || msg.includes("timeout")) {
        const pending: any = new Error("PENDING_FINALIZATION");
        pending.pending = true;
        pending.txHash = String(txHash);
        throw pending;
      }
      throw e;
    }
  }
  const pending2: any = new Error("PENDING_FINALIZATION");
  pending2.pending = true;
  pending2.txHash = String(txHash);
  throw pending2;
}
