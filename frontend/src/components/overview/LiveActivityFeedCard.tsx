import type { ActivityFeedItem } from '../../types';
import { SectionCard } from '../SectionCard';

type LiveActivityFeedCardProps = {
  items: ActivityFeedItem[];
};

export function LiveActivityFeedCard({ items }: LiveActivityFeedCardProps) {
  return (
    <SectionCard title="Live Activity Feed" className="mini-card">
      <div className="activity-list">
        {items.map((item) => (
          <div key={`${item.time}-${item.source}-${item.message}`} className="activity-item">
            <span className="activity-line" />
            <div>
              <div className="activity-time">{item.time}</div>
              <div className="activity-text">
                <strong>{item.source}</strong> · {item.message}
              </div>
            </div>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}