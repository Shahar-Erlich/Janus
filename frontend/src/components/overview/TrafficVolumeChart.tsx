import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { TrafficPoint } from '../../types';
import { SectionCard } from '../SectionCard';

type TrafficVolumeChartProps = {
  data: TrafficPoint[];
};

export function TrafficVolumeChart({ data }: TrafficVolumeChartProps) {
  return (
    <SectionCard
      title="Traffic Volume (Packets / Minute)"
      subtitle="Total traffic vs allowed traffic over time"
      className="traffic-chart-card"
      rightSlot={
        <div className="legend-inline">
          <span><i className="legend-dot legend-dot-primary" />Total</span>
          <span><i className="legend-dot legend-dot-secondary" />Allowed</span>
        </div>
      }
    >
      <div className="chart-wrapper chart-tall">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="inboundFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="rgba(168, 85, 247, 0.42)" />
                <stop offset="100%" stopColor="rgba(168, 85, 247, 0.03)" />
              </linearGradient>

              <linearGradient id="outboundFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="rgba(192, 132, 252, 0.28)" />
                <stop offset="100%" stopColor="rgba(192, 132, 252, 0.02)" />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(106, 140, 179, 0.12)" vertical={false} />
            <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: '#6f8eb6', fontSize: 12 }} />
            <YAxis hide domain={[0, 'dataMax + 5']} />
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
              stroke="#a855f7"
              strokeWidth={3}
              fill="url(#inboundFill)"
              dot={false}
            />

            <Area
              type="monotone"
              dataKey="outbound"
              stroke="#c084fc"
              strokeWidth={3}
              fill="url(#outboundFill)"
              dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </SectionCard>
  );
}