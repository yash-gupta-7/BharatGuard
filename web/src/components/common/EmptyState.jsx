export default function EmptyState({ icon: Icon, title, description }) {
  return (
    <div className="text-center py-10">
      {Icon && <Icon className="mx-auto mb-3 text-ink-dim" size={26} strokeWidth={1.5} />}
      <p className="text-sm font-medium text-ink">{title}</p>
      {description && <p className="text-xs text-ink-dim mt-1 max-w-xs mx-auto">{description}</p>}
    </div>
  )
}
