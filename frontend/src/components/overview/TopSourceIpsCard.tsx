import type { TopSourceIp } from '../../types';
import { SectionCard } from '../SectionCard';

type TopSourceIpsCardProps = {
  items: TopSourceIp[];
};

export function TopSourceIpsCard({ items }: TopSourceIpsCardProps) {
  return (
    <SectionCard title="Top Source IPs" className="mini-card">
      <div className="stack-list compact-list">
        {items.map((item) => (
          <div key={item.ip} className="list-row between">
            <span>{item.ip}</span>
            <strong>{item.requests}</strong>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}