import { MetricCard } from '../types';
import { cn, formatDeltaToneClass } from '../utils/format';

export function StatCard({ label, value, delta, deltaTone, highlight }: MetricCard) {
  return (
    <div className={cn('stat-card', highlight && 'stat-card-highlight')}>
      <div className="stat-label">{label}</div>
      <div className="stat-value-row">
        <div className="stat-value">{value}</div>
        {delta ? <div className={cn('stat-delta', formatDeltaToneClass(deltaTone))}>{delta}</div> : null}
      </div>
    </div>
  );
}
