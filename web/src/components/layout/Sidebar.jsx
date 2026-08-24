import { NavLink } from 'react-router-dom'
import { Shield, Lock, ListChecks, LineChart, Activity, X } from 'lucide-react'

const NAV = [
  { to: '/', label: 'Overview', icon: Shield, end: true },
  { to: '/protect', label: 'Protect', icon: Lock },
  { to: '/detectors', label: 'Detectors', icon: ListChecks },
  { to: '/evaluation', label: 'Evaluation', icon: LineChart },
  { to: '/activity', label: 'Activity', icon: Activity },
]

export default function Sidebar({ open, onClose }) {
  return (
    <>
      {open && (
        <div
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}
      <aside
        className={`fixed md:static inset-y-0 left-0 z-50 w-60 shrink-0 border-r border-border bg-surface flex flex-col transition-transform md:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center justify-between px-5 py-5">
          <div className="flex items-center gap-2">
            <Shield className="text-accent" size={20} />
            <span className="font-semibold tracking-tight">BharatGuard</span>
          </div>
          <button className="md:hidden text-ink-dim" onClick={onClose} aria-label="Close navigation">
            <X size={18} />
          </button>
        </div>

        <nav className="flex-1 px-3 space-y-1" aria-label="Primary">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={onClose}
              className={({ isActive }) =>
                `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-accent-soft text-accent'
                    : 'text-ink-dim hover:bg-surface-hover hover:text-ink'
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-5 py-4 border-t border-border text-xs text-ink-dim">
          Detection runs entirely locally.
          <br />
          No PII leaves this app for detection.
        </div>
      </aside>
    </>
  )
}
