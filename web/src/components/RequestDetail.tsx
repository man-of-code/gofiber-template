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
  const requestHeaders =
    Object.keys(entry.requestHeaders).length > 0
      ? JSON.stringify(entry.requestHeaders, null, 2)
      : "(empty request headers)";
  const responseHeaders =
    Object.keys(entry.responseHeaders).length > 0
      ? JSON.stringify(entry.responseHeaders, null, 2)
      : "(empty response headers)";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div className="flex max-h-[80vh] w-full max-w-xl flex-col rounded-xl border border-slate-700 bg-slate-900/95 p-4 shadow-xl">
        <header className="flex items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase text-slate-400">
              Request
            </p>
            <p className="truncate text-sm text-slate-100">
              {entry.method} {entry.path}
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-300">
              <span className="rounded-full border border-slate-700 bg-slate-950 px-2 py-0.5">
                Method: {entry.method}
              </span>
              <span className="rounded-full border border-slate-700 bg-slate-950 px-2 py-0.5">
                Status: {entry.status}
              </span>
            </div>
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

        <div className="mt-4 flex-1 space-y-4 overflow-auto pr-1">
          <section className="space-y-1">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-semibold uppercase text-slate-400">
                Request Headers
              </p>
              <Button
                variant="secondary"
                className="min-h-1 px-3 py-1 text-xs"
                onClick={async () => {
                  await navigator.clipboard.writeText(requestHeaders);
                }}
              >
                <Copy size={14} className="mr-1" />
                Copy
              </Button>
            </div>
            <JsonView content={requestHeaders} />
          </section>

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
                Response Headers
              </p>
              <Button
                variant="secondary"
                className="min-h-1 px-3 py-1 text-xs"
                onClick={async () => {
                  await navigator.clipboard.writeText(responseHeaders);
                }}
              >
                <Copy size={14} className="mr-1" />
                Copy
              </Button>
            </div>
            <JsonView content={responseHeaders} />
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
    </div>
  );
}
