import { Activity as ActivityIcon, Radio } from 'lucide-react'
import Card from '../components/common/Card'
import EmptyState from '../components/common/EmptyState'
import { useActivity } from '../context/ActivityContext'

function timeAgo(ts) {
  const seconds = Math.floor((Date.now() - ts) / 1000)
  if (seconds < 5) return 'just now'
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  return `${Math.floor(minutes / 60)}h ago`
}

export default function Activity() {
  const { entries } = useActivity()

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <ActivityIcon size={20} className="text-accent" /> Activity
        </h1>
        <p className="text-sm text-ink-dim mt-1">
          A real, session-local record of Protect actions taken in this tab — entity type counts only, never
          raw text or values. Cleared on refresh; nothing is sent anywhere or persisted.
        </p>
      </div>

      <Card>
        {entries.length === 0 ? (
          <EmptyState
            icon={Radio}
            title="No activity yet"
            description="Run Protect on some text to see it appear here."
          />
        ) : (
          <ul className="space-y-4">
            {entries.map((entry) => (
              <li key={entry.id} className="flex items-start gap-3">
                <span className="mt-1.5 h-2 w-2 rounded-full bg-accent shrink-0" aria-hidden="true" />
                <div className="text-sm">
                  <p>
                    Protected text —{' '}
                    {Object.keys(entry.entityCounts).length === 0
                      ? 'no PII detected'
                      : Object.entries(entry.entityCounts)
                          .map(([type, count]) => `${count}× ${type}`)
                          .join(', ')}
                    {entry.mocked && <span className="text-ink-dim"> (mocked Sarvam response)</span>}
                  </p>
                  <p className="text-xs text-ink-dim">{timeAgo(entry.timestamp)}</p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
