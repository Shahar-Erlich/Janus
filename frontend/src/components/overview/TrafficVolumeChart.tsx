import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { trafficSeries } from '../../data/mockData';
import { SectionCard } from '../SectionCard';

export function TrafficVolumeChart() {
  return (
    <SectionCard
      title="Real-time Traffic Volume (kbps)"
      subtitle="Visualizing data stream across primary gateways"
      className="traffic-chart-card"
      rightSlot={
        <div className="legend-inline">
          <span><i className="legend-dot legend-dot-primary" />Inbound</span>
          <span><i className="legend-dot legend-dot-secondary" />Outbound</span>
        </div>
      }
    >
      <div className="chart-wrapper chart-tall">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={trafficSeries}>
            <defs>
              <linearGradient id="inboundFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="rgba(69, 181, 255, 0.65)" />
                <stop offset="100%" stopColor="rgba(69, 181, 255, 0.04)" />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(106, 140, 179, 0.12)" vertical={false} />
            <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: '#6f8eb6', fontSize: 12 }} />
            <YAxis hide domain={[0, 800]} />
            <Tooltip
              contentStyle={{
                background: '#10233e',
                border: '1px solid rgba(90,130,180,0.25)',
                borderRadius: 12,
                color: '#d8e9ff',
              }}
            />
            <Area
              type="monotone"
              dataKey="inbound"
              stroke="#4db7ff"
              strokeWidth={6}
              fill="url(#inboundFill)"
              dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </SectionCard>
  );
}
