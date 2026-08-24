import { AlertTriangle } from 'lucide-react'

export default function ErrorState({ message, onRetry }) {
  return (
    <div className="rounded-xl border border-critical/30 bg-critical/5 p-6 text-center">
      <AlertTriangle className="mx-auto mb-2 text-critical" size={22} />
      <p className="text-sm font-medium text-ink">Something went wrong while connecting to BharatGuard services.</p>
      {message && <p className="text-xs text-ink-dim mt-1">{message}</p>}
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-4 rounded-lg border border-border px-4 py-1.5 text-sm font-medium text-ink hover:bg-surface-hover"
        >
          Retry
        </button>
      )}
    </div>
  )
}
