import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { detectionResults } from '../../data/mockData';
import { SectionCard } from '../SectionCard';

export function DetectionResultsChart() {
  return (
    <SectionCard title="Detection Results per Engine" className="detection-card">
      <div className="chart-wrapper chart-medium">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={detectionResults}>
            <CartesianGrid stroke="rgba(106, 140, 179, 0.1)" vertical={false} />
            <XAxis dataKey="name" tickLine={false} axisLine={false} tick={{ fill: '#6f8eb6', fontSize: 12 }} />
            <YAxis hide />
            <Tooltip
              contentStyle={{
                background: '#10233e',
                border: '1px solid rgba(90,130,180,0.25)',
                borderRadius: 12,
                color: '#d8e9ff',
              }}
            />
            <Bar dataKey="total" radius={[12, 12, 0, 0]} fill="#41adff" maxBarSize={44} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </SectionCard>
  );
}
