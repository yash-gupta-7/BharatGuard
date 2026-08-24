import { useState } from 'react'
import { Lock } from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import ErrorState from '../components/common/ErrorState'
import EntityBadges from '../components/protect/EntityBadges'
import PolicyPanel from '../components/protect/PolicyPanel'
import { protectText } from '../services/api'
import { useActivity } from '../context/ActivityContext'

const EXAMPLES = {
  English: 'My Aadhaar number is 234123412346 and my phone is 9876543210.',
  Hindi: 'मेरा आधार नंबर 234123412346 है और फोन नंबर 9876543210 है।',
  Hinglish: 'mera aadhaar number hai 234123412346, aur PAN ABCPE1234F bhi hai',
  'Indic numerals': 'मेरा आधार नंबर २३४१२३४१२३४६ है।',
}

function ResultCard({ title, children }) {
  return (
    <Card title={title}>
      <pre className="whitespace-pre-wrap break-words rounded-lg bg-bg border border-border p-3 text-sm text-ink-dim">
        {children}
      </pre>
    </Card>
  )
}

export default function Protect() {
  const [exampleName, setExampleName] = useState('English')
  const [text, setText] = useState(EXAMPLES.English)
  const [overrides, setOverrides] = useState({})
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const { record } = useActivity()

  function pickExample(name) {
    setExampleName(name)
    setText(EXAMPLES[name])
    setResult(null)
  }

  async function runProtect() {
    setLoading(true)
    setError(null)
    try {
      const data = await protectText(text, overrides)
      setResult(data)
      record({
        entityCounts: data.entities.reduce((acc, e) => {
          acc[e.entity_type] = (acc[e.entity_type] || 0) + 1
          return acc
        }, {}),
        mocked: data.mocked,
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold flex items-center gap-2">
          <Lock size={20} className="text-accent" /> Protect
        </h1>
        <p className="text-sm text-ink-dim mt-1">
          Detect and mask PII locally, then send only the sanitized text to Sarvam.
        </p>
      </div>

      <Card>
        <div className="flex flex-col gap-3">
          <select
            className="w-fit rounded-md border border-border bg-bg px-3 py-1.5 text-sm"
            value={exampleName}
            onChange={(e) => pickExample(e.target.value)}
          >
            {Object.keys(EXAMPLES).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <textarea
            className="w-full rounded-lg border border-border bg-bg p-3 text-sm resize-y"
            rows={3}
            value={text}
            onChange={(e) => setText(e.target.value)}
            aria-label="Text to protect"
          />
          <Button onClick={runProtect} disabled={loading || !text.trim()} className="self-start">
            {loading ? 'Protecting…' : 'Protect'}
          </Button>
        </div>
      </Card>

      <PolicyPanel overrides={overrides} onChange={setOverrides} />

      {error && <ErrorState message={error} onRetry={runProtect} />}

      {result && (
        <div className="space-y-4">
          <Card title="Detected PII">
            <EntityBadges entities={result.entities} />
          </Card>
          <ResultCard title="Protected text">{result.protected_text}</ResultCard>
          <ResultCard title="Sarvam request">{result.sarvam_request}</ResultCard>
          <ResultCard title={result.mocked ? 'Sarvam response (mocked — no SARVAM_API_KEY set)' : 'Sarvam response'}>
            {result.sarvam_response}
          </ResultCard>
          <ResultCard title="Restored response (optional)">{result.restored_response}</ResultCard>
        </div>
      )}
    </div>
  )
}
