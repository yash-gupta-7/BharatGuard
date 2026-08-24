export default function Card({ title, subtitle, action, children, className = '' }) {
  return (
    <div className={`rounded-xl border border-border bg-surface p-5 ${className}`}>
      {(title || action) && (
        <div className="flex items-start justify-between mb-4">
          <div>
            {title && (
              <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-dim">
                {title}
              </h3>
            )}
            {subtitle && <p className="text-sm text-ink-dim mt-1">{subtitle}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </div>
  )
}
