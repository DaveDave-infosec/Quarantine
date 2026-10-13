import type { TxState } from "../../lib/useTx";
import { txUrl } from "../../lib/contracts";
import { short } from "../../lib/format";

export default function TxBar({ tx, onDismiss }: { tx: TxState; onDismiss: () => void }) {
  if (tx.phase === "idle") return null;
  return (
    <div className={`txbar tx-${tx.phase}`} role="status" aria-live="polite">
      <div className="container txbar-inner">
        <span className="tx-dot" />
        <div className="tx-text">
          <strong>{tx.label}</strong>
          <span>{tx.message}</span>
        </div>
        {tx.txHash && (
          <a className="mono tx-link" href={txUrl(tx.txHash)} target="_blank" rel="noreferrer">
            {short(tx.txHash)}
          </a>
        )}
        {(tx.phase === "done" || tx.phase === "error") && (
          <button className="link-btn" onClick={onDismiss}>
            Dismiss
          </button>
        )}
      </div>
    </div>
  );
}
