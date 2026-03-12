import { triggeredRules } from '../../data/mockData';
import { severityToClass } from '../../utils/format';
import { SectionCard } from '../SectionCard';

export function TriggeredRulesCard() {
  return (
    <SectionCard title="Triggered Rules" className="mini-card">
      <div className="stack-list compact-list">
        {triggeredRules.map((item) => (
          <div key={item.rule} className="rule-row">
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
