import type { TriggeredRule } from '../../types';
import { severityToClass } from '../../utils/format';
import { SectionCard } from '../SectionCard';

type TriggeredRulesCardProps = {
  items: TriggeredRule[];
};

export function TriggeredRulesCard({ items }: TriggeredRulesCardProps) {
  return (
    <SectionCard title="Triggered Rules" className="mini-card">
      <div className="stack-list compact-list">
        {items.map((item) => (
          <div key={`${item.rule}-${item.hits}`} className="rule-row">
            <div>
              <div className="rule-title">{item.rule}</div>
              <div className="progress-track">
                <div className="progress-bar" style={{ width: `${Math.min(item.hits / 5, 100)}%` }} />
              </div>
            </div>
            <span className={`pill ${severityToClass(item.severity)}`}>{item.severity}</span>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}