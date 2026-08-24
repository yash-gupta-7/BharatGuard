// Service layer: every backend call goes through here, nowhere else.
// In dev, Vite proxies /api to the backend (see vite.config.js), so
// VITE_API_BASE_URL is only needed for a production deploy where the
// frontend and backend are served from different origins.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

async function request(path, options) {
  let response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, options)
  } catch {
    throw new Error('Could not reach BharatGuard services. Is the backend running?')
  }
  if (!response.ok) {
    throw new Error(`Request to ${path} failed (${response.status})`)
  }
  return response.json()
}

export function getHealth() {
  return request('/api/health')
}

export function getDetectors() {
  return request('/api/detectors')
}

export function getEvaluation() {
  return request('/api/evaluation')
}

export function protectText(text, policyOverrides) {
  return request('/api/protect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, policy_overrides: policyOverrides || null }),
  })
}
