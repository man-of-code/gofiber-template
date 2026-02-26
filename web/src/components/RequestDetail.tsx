import { Copy, X } from "lucide-react";

import type { NetworkEntry } from "../lib/types";
import { JsonView } from "./ui/JsonView";
import { Button } from "./ui/Button";

export function RequestDialog({
  entry,
  onClose,
}: {
  entry: NetworkEntry;
  onClose: () => void;
}) {
  const requestBody =
    entry.displayRequestBody || entry.rawRequestBody || "(empty request body)";
  const responseBody =
    entry.displayResponseBody ||
    entry.rawResponseBody ||
    "(empty response body)";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div className="max-h-[80vh] w-full max-w-xl space-y-4 rounded-xl border border-slate-700 bg-slate-900/95 p-4 shadow-xl">
        <header className="flex items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase text-slate-400">
              Request
            </p>
            <p className="truncate text-sm text-slate-100">
              {entry.method} {entry.path}
            </p>
          </div>
          <Button
            variant="primary"
            className="min-h-1 px-1.5 py-0.5 text-xs"
            onClick={onClose}
          >
            <X size={14} className="mr-1" />
            Close
          </Button>
        </header>

        <section className="space-y-1">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-semibold uppercase text-slate-400">
              Request Body (prettified JSON)
            </p>
            <Button
              variant="secondary"
              className="min-h-1 px-3 py-1 text-xs"
              onClick={async () => {
                await navigator.clipboard.writeText(requestBody);
              }}
            >
              <Copy size={14} className="mr-1" />
              Copy
            </Button>
          </div>
          <JsonView content={requestBody} />
        </section>

        <section className="space-y-1">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-semibold uppercase text-slate-400">
              Response Body (prettified JSON)
            </p>
            <Button
              variant="secondary"
              className="min-h-1 px-3 py-1 text-xs"
              onClick={async () => {
                await navigator.clipboard.writeText(responseBody);
              }}
            >
              <Copy size={14} className="mr-1" />
              Copy
            </Button>
          </div>
          <JsonView content={responseBody} />
        </section>
      </div>
    </div>
  );
}
