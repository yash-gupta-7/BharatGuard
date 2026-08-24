import { Link } from 'react-router-dom'
import { Shield, Lock, Cpu, ShieldCheck } from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import MetricCard from '../components/evaluation/MetricCard'
import { SkeletonMetric } from '../components/common/Skeleton'
import { useFetch } from '../hooks/useFetch'
import { getEvaluation } from '../services/api'

const CAPABILITIES = [
  {
    icon: Cpu,
    title: 'Local detection',
    body: 'Aadhaar, PAN, phone, email, UPI, IFSC, card numbers, API keys, names, and addresses — detected entirely on-device, before any network call.',
  },
  {
    icon: Lock,
    title: 'Mask or tokenize',
    body: 'Irreversibly redact, or reversibly tokenize with a request-local mapping that never touches disk.',
  },
  {
    icon: ShieldCheck,
    title: 'Sanitized by default',
    body: 'Only the protected text ever reaches Sarvam. Raw PII is never sent for detection purposes.',
  },
]

export default function Overview() {
  const { status, data } = useFetch(getEvaluation)

  return (
    <div className="space-y-8">
      <section className="rounded-2xl border border-border bg-gradient-to-br from-accent-soft to-surface p-8 md:p-10">
        <div className="flex items-center gap-2 text-accent mb-3">
          <Shield size={22} />
          <span className="text-sm font-semibold tracking-wide uppercase">BharatGuard</span>
        </div>
        <h1 className="text-3xl md:text-4xl font-semibold tracking-tight max-w-xl">
          Intelligent security infrastructure for a safer digital Bharat.
        </h1>
        <p className="text-ink-dim mt-3 max-w-lg">
          A technical privacy control that reduces unnecessary exposure of personal data before it reaches an
          external LLM provider — built for Indian identifiers, Hindi/Hinglish text, and Indic numerals.
        </p>
        <div className="mt-6 flex gap-3">
          <Link to="/protect">
            <Button>Try it live</Button>
          </Link>
          <Link to="/evaluation">
            <Button variant="secondary">View evaluation results</Button>
          </Link>
        </div>
      </section>

      <section className="grid md:grid-cols-3 gap-4">
        {CAPABILITIES.map(({ icon: Icon, title, body }) => (
          <Card key={title}>
            <Icon className="text-accent mb-2" size={20} />
            <h3 className="font-medium text-sm">{title}</h3>
            <p className="text-xs text-ink-dim mt-1">{body}</p>
          </Card>
        ))}
      </section>

      <section>
        <h2 className="text-xs font-semibold uppercase tracking-wider text-ink-dim mb-3">
          Measured, not claimed
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {status === 'loading' &&
            Array.from({ length: 4 }).map((_, i) => <SkeletonMetric key={i} />)}
          {status === 'success' && (
            <>
              <MetricCard label="Dataset size" value={data.dataset_size} />
              <MetricCard
                label="F1 (det. + contextual)"
                value={data.configs.deterministic_contextual.overall.f1.toFixed(3)}
              />
              <MetricCard
                label="Precision (deterministic)"
                value={data.configs.deterministic.overall.precision.toFixed(3)}
              />
              <MetricCard label="Leakage rate" value={`${(data.leakage.leakage_rate * 100).toFixed(1)}%`} />
            </>
          )}
        </div>
        <p className="text-xs text-ink-dim mt-2">
          Live from the real evaluation harness (evals/run_eval.py) — an evaluation-set measurement, not a
          guarantee for arbitrary real-world input. See{' '}
          <Link to="/evaluation" className="text-accent">
            Evaluation
          </Link>{' '}
          for methodology.
        </p>
      </section>
    </div>
  )
}
