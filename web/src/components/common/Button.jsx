const VARIANTS = {
  primary: 'bg-accent text-white hover:bg-accent/90',
  secondary: 'border border-border text-ink hover:bg-surface-hover',
}

export default function Button({ children, variant = 'primary', className = '', ...rest }) {
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${VARIANTS[variant]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  )
}
