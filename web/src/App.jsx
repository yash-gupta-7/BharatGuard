import { Suspense, lazy } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import AppShell from './components/layout/AppShell'
import { ActivityProvider } from './context/ActivityContext'
import { SkeletonCard } from './components/common/Skeleton'
import Overview from './pages/Overview'
import Protect from './pages/Protect'
import Detectors from './pages/Detectors'
import Activity from './pages/Activity'

// Evaluation pulls in recharts, the heaviest dependency -- load it only
// when that route is actually visited.
const Evaluation = lazy(() => import('./pages/Evaluation'))

export default function App() {
  return (
    <ActivityProvider>
      <BrowserRouter>
        <AppShell>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/protect" element={<Protect />} />
            <Route path="/detectors" element={<Detectors />} />
            <Route
              path="/evaluation"
              element={
                <Suspense fallback={<SkeletonCard />}>
                  <Evaluation />
                </Suspense>
              }
            />
            <Route path="/activity" element={<Activity />} />
          </Routes>
        </AppShell>
      </BrowserRouter>
    </ActivityProvider>
  )
}
