import { LineChart } from 'lucide-react'
import Card from '../components/common/Card'
import { SkeletonCard, SkeletonMetric } from '../components/common/Skeleton'
import ErrorState from '../components/common/ErrorState'
import MetricCard from '../components/evaluation/MetricCard'
import ConfigComparisonChart from '../components/evaluation/ConfigComparisonChart'
import { useFetch } from '../hooks/useFetch'
import { getEvaluation } from '../services/api'

function pct(x) {
  return `${(x * 100).toFixed(1)}%`
}

export default function Evaluation() {
  const { status, data, error, retry } = useFetch(getEvaluation)

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <LineChart size={20} className="text-accent" /> Evaluation
        </h1>
        <p className="text-sm text-ink-dim mt-1">
          Live results from BharatGuard's evaluation harness, run against a synthetic dataset. These numbers
          are computed by the server on request, not hardcoded — this is an evaluation-set measurement, not a
          guarantee about arbitrary real-world input.
        </p>
      </div>

      {status === 'loading' && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonMetric key={i} />
          ))}
        </div>
      )}
      {status === 'loading' && <SkeletonCard />}

      {status === 'error' && <ErrorState message={error} onRetry={retry} />}

      {status === 'success' && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <MetricCard label="Dataset size" value={data.dataset_size} />
            <MetricCard label="F1 (deterministic)" value={data.configs.deterministic.overall.f1.toFixed(3)} />
            <MetricCard
              label="F1 (det. + contextual)"
              value={data.configs.deterministic_contextual.overall.f1.toFixed(3)}
            />
            <MetricCard label="Leakage rate" value={pct(data.leakage.leakage_rate)} />
          </div>

          <Card title="Precision / Recall / F1 by configuration">
            <ConfigComparisonChart
              configA={data.configs.deterministic.overall}
              configB={data.configs.deterministic_contextual.overall}
            />
          </Card>

          <Card title="Per-entity-type F1 (deterministic + contextual)">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wider text-ink-dim border-b border-border">
                    <th className="pb-2 pr-4">Type</th>
                    <th className="pb-2 pr-4">Precision</th>
                    <th className="pb-2 pr-4">Recall</th>
                    <th className="pb-2">F1</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.configs.deterministic_contextual.per_type).map(([type, m]) => (
                    <tr key={type} className="border-b border-border last:border-0">
                      <td className="py-2 pr-4 font-medium">{type}</td>
                      <td className="py-2 pr-4 text-ink-dim">{m.precision.toFixed(2)}</td>
                      <td className="py-2 pr-4 text-ink-dim">{m.recall.toFixed(2)}</td>
                      <td className="py-2 text-ink-dim">{m.f1.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card title="Privacy leakage">
            <p className="text-sm text-ink-dim">
              {data.leakage.total_leaked} of {data.leakage.total_pii_values_checked} checked values leaked
              into protected output ({data.leakage.exact_substring_leaks} exact-substring,{' '}
              {data.leakage.canonical_leaks} canonical-form). Known cause: weak Devanagari-script PERSON
              detection.
            </p>
          </Card>
        </>
      )}
    </div>
  )
}
