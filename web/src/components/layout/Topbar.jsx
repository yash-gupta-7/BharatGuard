import { useLocation } from 'react-router-dom'
import { Menu } from 'lucide-react'
import { useHealth } from '../../hooks/useHealth'

const TITLES = {
  '/': 'Overview',
  '/protect': 'Protect',
  '/detectors': 'Detectors',
  '/evaluation': 'Evaluation',
  '/activity': 'Activity',
}

export default function Topbar({ onMenuClick }) {
  const location = useLocation()
  const { status } = useHealth()
  const title = TITLES[location.pathname] || 'BharatGuard'

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between border-b border-border bg-bg/90 backdrop-blur px-4 md:px-6 py-3">
      <div className="flex items-center gap-3">
        <button
          className="md:hidden text-ink-dim"
          onClick={onMenuClick}
          aria-label="Open navigation"
        >
          <Menu size={20} />
        </button>
        <div className="text-sm">
          <span className="text-ink-dim">BharatGuard / </span>
          <span className="font-medium">{title}</span>
        </div>
      </div>

      <div className="flex items-center gap-2 text-xs text-ink-dim">
        <span
          className={`h-2 w-2 rounded-full ${
            status === 'ok' ? 'bg-ok' : status === 'checking' ? 'bg-warn animate-pulse' : 'bg-critical'
          }`}
          aria-hidden="true"
        />
        {status === 'ok' && 'Backend connected'}
        {status === 'checking' && 'Checking backend…'}
        {status === 'down' && 'Backend unreachable'}
      </div>
    </header>
  )
}
