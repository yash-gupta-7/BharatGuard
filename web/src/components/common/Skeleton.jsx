export function SkeletonLine({ width = 'w-full' }) {
  return <div className={`h-3.5 rounded bg-border animate-pulse ${width}`} />
}

export function SkeletonCard() {
  return (
    <div className="rounded-xl border border-border bg-surface p-5 space-y-3">
      <SkeletonLine width="w-1/3" />
      <SkeletonLine width="w-2/3" />
      <SkeletonLine width="w-1/2" />
    </div>
  )
}

export function SkeletonMetric() {
  return (
    <div className="rounded-xl border border-border bg-surface p-4 space-y-3">
      <SkeletonLine width="w-1/2" />
      <div className="h-7 rounded bg-border animate-pulse w-2/3" />
    </div>
  )
}

export function SkeletonTable({ rows = 4 }) {
  return (
    <div className="rounded-xl border border-border bg-surface p-5 space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <SkeletonLine key={i} />
      ))}
    </div>
  )
}
