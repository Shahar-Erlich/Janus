import { Cell, Pie, PieChart, ResponsiveContainer } from 'recharts';
import type { ProtocolShare } from '../../types';
import { SectionCard } from '../SectionCard';

const COLORS = ['#46b7ff', '#7b7cff', '#ff4d7c', '#6b7ea4'];

type ProtocolDistributionChartProps = {
  data: ProtocolShare[];
};

function formatCompact(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return `${value}`;
}

export function ProtocolDistributionChart({ data }: ProtocolDistributionChartProps) {
  const total = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <SectionCard title="Protocol Distribution" className="protocol-card">
      <div className="protocol-layout">
        <div className="donut-chart-wrapper">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                innerRadius={62}
                outerRadius={78}
                paddingAngle={2}
                dataKey="value"
                stroke="transparent"
              >
                {data.map((entry, index) => (
                  <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-center">
            <strong>{formatCompact(total)}</strong>
            <span>Packets</span>
          </div>
        </div>

        <div className="protocol-legend-list">
          {data.map((item, index) => {
            const percent = total > 0 ? Math.round((item.value / total) * 100) : 0;
            return (
              <div key={item.name} className="protocol-legend-row">
                <div className="protocol-label-wrap">
                  <span className="protocol-color" style={{ background: COLORS[index % COLORS.length] }} />
                  <span>{item.name}</span>
                </div>
                <strong>{percent}%</strong>
              </div>
            );
          })}
        </div>
      </div>
    </SectionCard>
  );
}