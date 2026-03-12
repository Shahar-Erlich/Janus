import { StatCard } from '../components/StatCard';
import { DetectionResultsChart } from '../components/overview/DetectionResultsChart';
import { LiveActivityFeedCard } from '../components/overview/LiveActivityFeedCard';
import { ProtocolDistributionChart } from '../components/overview/ProtocolDistributionChart';
import { SystemSummaryCard } from '../components/overview/SystemSummaryCard';
import { TopSourceIpsCard } from '../components/overview/TopSourceIpsCard';
import { TrafficVolumeChart } from '../components/overview/TrafficVolumeChart';
import { TriggeredRulesCard } from '../components/overview/TriggeredRulesCard';
import { overviewMetrics } from '../data/mockData';

export function OverviewPage() {
  return (
    <div className="page-stack">
      <section className="stats-grid">
        {overviewMetrics.map((metric) => (
          <StatCard key={metric.label} {...metric} />
        ))}
      </section>

      <TrafficVolumeChart />

      <section className="overview-two-col-grid">
        <ProtocolDistributionChart />
        <DetectionResultsChart />
      </section>

      <section className="overview-four-col-grid">
        <TopSourceIpsCard />
        <TriggeredRulesCard />
        <LiveActivityFeedCard />
        <SystemSummaryCard />
      </section>
    </div>
  );
}
