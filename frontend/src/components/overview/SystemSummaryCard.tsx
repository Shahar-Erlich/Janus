import { systemSummary } from '../../data/mockData';
import { SectionCard } from '../SectionCard';

export function SystemSummaryCard() {
  return (
    <SectionCard title="System Summary" className="mini-card">
      <div className="summary-grid">
        {systemSummary.map((item) => (
          <div key={item.label} className="summary-item">
            <span className="summary-label">{item.label}</span>
            <strong className={`summary-value summary-${item.tone ?? 'neutral'}`}>{item.value}</strong>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}
