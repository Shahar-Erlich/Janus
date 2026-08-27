import type { SummaryItem } from '../../types';
import { SectionCard } from '../SectionCard';

type SystemSummaryCardProps = {
  items: SummaryItem[];
};

export function SystemSummaryCard({ items }: SystemSummaryCardProps) {
  return (
    <SectionCard title="System Summary" className="mini-card">
      <div className="summary-grid">
        {items.map((item) => (
          <div key={item.label} className="summary-item">
            <span className="summary-label">{item.label}</span>
            <strong className={`summary-value summary-${item.tone ?? 'neutral'}`}>{item.value}</strong>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}