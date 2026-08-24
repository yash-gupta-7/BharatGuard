import { useCallback, useEffect, useState } from 'react'

// Generic loading/data/error hook for a read-only API call, with retry.
// `fetcher` is stable-by-reference-expected (pass a useCallback'd fn or a
// plain module-level function) since it re-runs whenever it changes.
export function useFetch(fetcher) {
  const [state, setState] = useState({ status: 'loading', data: null, error: null })

  const run = useCallback(() => {
    setState({ status: 'loading', data: null, error: null })
    fetcher()
      .then((data) => setState({ status: 'success', data, error: null }))
      .catch((error) => setState({ status: 'error', data: null, error: error.message }))
  }, [fetcher])

  useEffect(() => {
    run()
  }, [run])

  return { ...state, retry: run }
}
