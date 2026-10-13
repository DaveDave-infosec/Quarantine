import { useCallback, useRef, useState } from "react";
import { ContractRevert, onTxSubmitted, currentMode } from "./genlayer";
import type { WriteResult } from "./genlayer";

export type TxPhase = "idle" | "signing" | "finalizing" | "reading" | "done" | "error";

export interface TxState {
  phase: TxPhase;
  label: string;
  message: string;
  txHash: string;
}

export type Run = (
  label: string,
  fn: () => Promise<WriteResult>,
  after?: () => Promise<void>,
) => Promise<boolean>;

const IDLE: TxState = { phase: "idle", label: "", message: "", txHash: "" };

export function useTx(reload: () => Promise<void>) {
  const [tx, setTx] = useState<TxState>(IDLE);
  const busyRef = useRef(false);

  const run: Run = useCallback(
    async (label, fn, after) => {
      if (busyRef.current) return false;
      busyRef.current = true;
      setTx({
        phase: "signing",
        label,
        message:
          currentMode() === "metamask"
            ? "Confirm the transaction in MetaMask."
            : "Submitting with the demo wallet.",
        txHash: "",
      });
      onTxSubmitted((hash) =>
        setTx((s) => ({
          ...s,
          phase: "finalizing",
          txHash: hash,
          message:
            "Submitted. Validators are executing it and the transaction is finalizing. This can take a minute or two.",
        })),
      );
      try {
        const res = await fn();
        setTx((s) => ({
          ...s,
          phase: "reading",
          txHash: res.txHash,
          message: "Finalized. Reading the new state back from chain.",
        }));
        await reload();
        if (after) await after();
        setTx((s) => ({
          ...s,
          phase: "done",
          message: "Done. Everything below was read back from chain after finalization.",
        }));
        return true;
      } catch (e) {
        const err: any = e;
        if (err instanceof ContractRevert) {
          setTx((s) => ({
            ...s,
            phase: "error",
            txHash: err.txHash,
            message: "Refused by the contract: " + err.message,
          }));
          return false;
        }
        if (err?.pending) {
          setTx((s) => ({
            ...s,
            phase: "reading",
            txHash: String(err.txHash ?? s.txHash),
            message: "Still finalizing on chain. Re-reading state.",
          }));
          try {
            await reload();
          } catch {
            // keep the message below
          }
          setTx((s) => ({
            ...s,
            phase: "done",
            message: "Submitted and still finalizing. Press Refresh in a minute to see the final state.",
          }));
          return true;
        }
        setTx((s) => ({ ...s, phase: "error", message: String(err?.message ?? err) }));
        return false;
      } finally {
        onTxSubmitted(null);
        busyRef.current = false;
      }
    },
    [reload],
  );

  const dismiss = useCallback(() => setTx(IDLE), []);
  const busy = tx.phase === "signing" || tx.phase === "finalizing" || tx.phase === "reading";
  return { tx, busy, run, dismiss };
}
