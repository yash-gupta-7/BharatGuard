import { useEffect, useState } from 'react'
import { getHealth } from '../services/api'

// Polls the real /api/health endpoint. Status only ever reflects an
// actual response from the backend -- never a hardcoded "Operational".
export function useHealth(intervalMs = 15000) {
  const [status, setStatus] = useState('checking')

  useEffect(() => {
    let cancelled = false

    async function check() {
      try {
        await getHealth()
        if (!cancelled) setStatus('ok')
      } catch {
        if (!cancelled) setStatus('down')
      }
    }

    check()
    const id = setInterval(check, intervalMs)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [intervalMs])

  return { status }
}
