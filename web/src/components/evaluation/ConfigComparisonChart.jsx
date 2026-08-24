import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

export default function ConfigComparisonChart({ configA, configB }) {
  const data = [
    { metric: 'Precision', Deterministic: configA.precision, 'Det. + Contextual': configB.precision },
    { metric: 'Recall', Deterministic: configA.recall, 'Det. + Contextual': configB.recall },
    { metric: 'F1', Deterministic: configA.f1, 'Det. + Contextual': configB.f1 },
  ]

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#232b3a" vertical={false} />
        <XAxis dataKey="metric" stroke="#8b95a7" fontSize={12} tickLine={false} axisLine={false} />
        <YAxis domain={[0, 1]} stroke="#8b95a7" fontSize={12} tickLine={false} axisLine={false} />
        <Tooltip
          contentStyle={{ background: '#10151f', border: '1px solid #232b3a', borderRadius: 8, fontSize: 12 }}
          formatter={(v) => v.toFixed(3)}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Bar dataKey="Deterministic" fill="#8b95a7" radius={[4, 4, 0, 0]} />
        <Bar dataKey="Det. + Contextual" fill="#3b9dd8" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}
