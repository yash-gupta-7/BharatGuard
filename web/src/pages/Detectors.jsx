import { ListChecks } from 'lucide-react'
import Card from '../components/common/Card'
import Badge from '../components/common/Badge'
import { SkeletonTable } from '../components/common/Skeleton'
import ErrorState from '../components/common/ErrorState'
import { useFetch } from '../hooks/useFetch'
import { getDetectors } from '../services/api'

const ACTION_VARIANT = { mask: 'critical', tokenize: 'accent', ignore: 'neutral' }
const CATEGORY_VARIANT = { deterministic: 'ok', contextual: 'warn' }

export default function Detectors() {
  const { status, data, error, retry } = useFetch(getDetectors)

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <ListChecks size={20} className="text-accent" /> Detectors
        </h1>
        <p className="text-sm text-ink-dim mt-1">
          Supported PII types and their default protection policy, read directly from BharatGuard's
          configuration — deterministic detectors use regex + structural validation (Verhoeff checksum for
          Aadhaar, holder-code validation for PAN); contextual detectors use a local spaCy model and
          rule-based address heuristics, which are inherently less precise.
        </p>
      </div>

      {status === 'loading' && <SkeletonTable rows={9} />}
      {status === 'error' && <ErrorState message={error} onRetry={retry} />}
      {status === 'success' && (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-ink-dim border-b border-border">
                  <th className="pb-2 pr-4">Entity type</th>
                  <th className="pb-2 pr-4">Category</th>
                  <th className="pb-2">Default action</th>
                </tr>
              </thead>
              <tbody>
                {data.map((d) => (
                  <tr key={d.entity_type} className="border-b border-border last:border-0">
                    <td className="py-2.5 pr-4 font-medium">{d.entity_type}</td>
                    <td className="py-2.5 pr-4">
                      <Badge variant={CATEGORY_VARIANT[d.category]}>{d.category}</Badge>
                    </td>
                    <td className="py-2.5">
                      <Badge variant={ACTION_VARIANT[d.default_action]}>{d.default_action}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
