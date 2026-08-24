const VARIANTS = {
  critical: 'bg-critical/15 text-critical border-critical/30',
  warn: 'bg-warn/15 text-warn border-warn/30',
  ok: 'bg-ok/15 text-ok border-ok/30',
  accent: 'bg-accent/15 text-accent border-accent/30',
  neutral: 'bg-ink-dim/15 text-ink-dim border-ink-dim/30',
}

export default function Badge({ children, variant = 'neutral', icon: Icon }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${VARIANTS[variant]}`}
    >
      {Icon && <Icon size={12} strokeWidth={2.5} />}
      {children}
    </span>
  )
}
