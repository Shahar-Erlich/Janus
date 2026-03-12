import { Cell, Pie, PieChart, ResponsiveContainer } from 'recharts';
import { protocolDistribution } from '../../data/mockData';
import { SectionCard } from '../SectionCard';

const COLORS = ['#46b7ff', '#7b7cff', '#ff4d7c', '#6b7ea4'];

export function ProtocolDistributionChart() {
  return (
    <SectionCard title="Protocol Distribution" className="protocol-card">
      <div className="protocol-layout">
        <div className="donut-chart-wrapper">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={protocolDistribution}
                innerRadius={62}
                outerRadius={78}
                paddingAngle={2}
                dataKey="value"
                stroke="transparent"
              >
                {protocolDistribution.map((entry, index) => (
                  <Cell key={entry.name} fill={COLORS[index]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-center">
            <strong>1.2B</strong>
            <span>Packets</span>
          </div>
        </div>

        <div className="protocol-legend-list">
          {protocolDistribution.map((item, index) => (
            <div key={item.name} className="protocol-legend-row">
              <div className="protocol-label-wrap">
                <span className="protocol-color" style={{ background: COLORS[index] }} />
                <span>{item.name}</span>
              </div>
              <strong>{item.value}%</strong>
            </div>
          ))}
        </div>
      </div>
    </SectionCard>
  );
}
