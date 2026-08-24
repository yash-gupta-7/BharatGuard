import EmptyState from '../common/EmptyState'
import { ShieldCheck } from 'lucide-react'

const CRITICAL_TYPES = new Set(['AADHAAR', 'PAN', 'IFSC', 'ADDRESS', 'API_KEY', 'CARD_NUMBER'])

export default function EntityBadges({ entities }) {
  if (entities.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No PII detected"
        description="This text contains no recognizable Indian identifiers, names, or addresses."
      />
    )
  }

  return (
    <div className="flex flex-wrap gap-2">
      {entities.map((e, i) => (
        <span
          key={i}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold text-white ${
            CRITICAL_TYPES.has(e.entity_type) ? 'bg-critical' : 'bg-accent'
          }`}
        >
          {e.entity_type}
          <span className="font-normal opacity-85">{Math.round(e.confidence * 100)}%</span>
        </span>
      ))}
    </div>
  )
}
