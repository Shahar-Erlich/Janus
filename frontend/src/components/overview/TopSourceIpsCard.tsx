import { topSourceIps } from '../../data/mockData';
import { SectionCard } from '../SectionCard';

export function TopSourceIpsCard() {
  return (
    <SectionCard title="Top Source IPs" className="mini-card">
      <div className="stack-list compact-list">
        {topSourceIps.map((item) => (
          <div key={item.ip} className="list-row between">
            <span>{item.ip}</span>
            <strong>{item.requests}</strong>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}
