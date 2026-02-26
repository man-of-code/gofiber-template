export function JsonView({ content }: { content: string }) {
  return (
    <pre className="max-h-72 overflow-auto rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-200">
      <code>{content || '(empty)'}</code>
    </pre>
  )
}
