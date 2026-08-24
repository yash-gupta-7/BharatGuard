import { createContext, useContext, useState, useCallback } from 'react'

// Real, session-local record of Protect actions taken in this browser tab.
// Stores only entity TYPE counts and outcome metadata -- never raw text or
// detected values. In-memory only (lost on refresh); deliberately not
// persisted to localStorage since there's no reason to keep even this
// metadata around longer than the session needs it.
const ActivityContext = createContext(null)

export function ActivityProvider({ children }) {
  const [entries, setEntries] = useState([])

  const record = useCallback((entry) => {
    setEntries((prev) => [{ id: crypto.randomUUID(), timestamp: Date.now(), ...entry }, ...prev])
  }, [])

  return (
    <ActivityContext.Provider value={{ entries, record }}>{children}</ActivityContext.Provider>
  )
}

export function useActivity() {
  const ctx = useContext(ActivityContext)
  if (!ctx) throw new Error('useActivity must be used within ActivityProvider')
  return ctx
}
