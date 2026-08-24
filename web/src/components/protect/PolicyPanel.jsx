import { useState } from 'react'
import Card from '../common/Card'
import { SkeletonTable } from '../common/Skeleton'
import { useFetch } from '../../hooks/useFetch'
import { getDetectors } from '../../services/api'

const ACTIONS = ['mask', 'tokenize', 'ignore']

// Lets a user override the default mask/tokenize/ignore policy per entity
// type before running Protect -- exercises PIIGuard's real PolicyConfig
// override capability via /api/protect's policy_overrides field.
export default function PolicyPanel({ overrides, onChange }) {
  const { status, data } = useFetch(getDetectors)
  const [open, setOpen] = useState(false)

  if (status === 'loading') return <SkeletonTable rows={3} />
  if (status !== 'success') return null

  return (
    <Card
      title="Policy"
      subtitle={open ? 'Override the default action per entity type' : undefined}
      action={
        <button
          className="text-xs font-medium text-accent"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
        >
          {open ? 'Hide' : 'Customize'}
        </button>
      }
    >
      {open && (
        <div className="space-y-2">
          {data.map((d) => (
            <div key={d.entity_type} className="flex items-center justify-between text-sm">
              <span className="text-ink-dim">{d.entity_type}</span>
              <select
                className="rounded-md border border-border bg-bg px-2 py-1 text-xs"
                value={overrides[d.entity_type] || d.default_action}
                onChange={(e) =>
                  onChange({ ...overrides, [d.entity_type]: e.target.value })
                }
              >
                {ACTIONS.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
