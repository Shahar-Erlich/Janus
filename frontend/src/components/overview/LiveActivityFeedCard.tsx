import { activityFeed } from '../../data/mockData';
import { SectionCard } from '../SectionCard';

export function LiveActivityFeedCard() {
  return (
    <SectionCard title="Live Activity Feed" className="mini-card">
      <div className="activity-list">
        {activityFeed.map((item) => (
          <div key={`${item.time}-${item.source}`} className="activity-item">
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
