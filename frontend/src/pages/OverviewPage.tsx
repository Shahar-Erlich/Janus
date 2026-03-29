import { useEffect, useState } from 'react';
import { StatCard } from '../components/StatCard';
import { DetectionResultsChart } from '../components/overview/DetectionResultsChart';
import { LiveActivityFeedCard } from '../components/overview/LiveActivityFeedCard';
import { ProtocolDistributionChart } from '../components/overview/ProtocolDistributionChart';
import { SystemSummaryCard } from '../components/overview/SystemSummaryCard';
import { TopSourceIpsCard } from '../components/overview/TopSourceIpsCard';
import { TrafficVolumeChart } from '../components/overview/TrafficVolumeChart';
import { TriggeredRulesCard } from '../components/overview/TriggeredRulesCard';
import { emptyDashboardViewModel, mapDashboardOverview, type DashboardViewModel } from '../mappers/dashboardMapper';
import { janusClient } from '../services/janusClient';

export function OverviewPage() {
  const [data, setData] = useState<DashboardViewModel>(emptyDashboardViewModel);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const response = await janusClient.getDashboardOverview();

        if (cancelled) return;

        if (!response.dashboardOverview) {
          throw new Error('Dashboard response is missing');
        }

        setData(mapDashboardOverview(response.dashboardOverview));
        setError(null);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load overview');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void load();
    const intervalId = window.setInterval(() => {
      void load();
    }, 10_000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, []);

  return (
    <div className="page-stack">
      {error ? (
        <div className="section-card">
          <div className="section-title">Overview load error</div>
          <p className="section-subtitle">{error}</p>
        </div>
      ) : null}

      {loading && data.metrics.length === 0 ? (
        <div className="section-card">
          <div className="section-title">Loading overview…</div>
          <p className="section-subtitle">Waiting for dashboard data from Janus handler.</p>
        </div>
      ) : null}

      <section className="stats-grid">
        {data.metrics.map((metric) => (
          <StatCard key={metric.label} {...metric} />
        ))}
      </section>

      <TrafficVolumeChart data={data.trafficSeries} />

      <section className="overview-two-col-grid">
        <ProtocolDistributionChart data={data.protocolDistribution} />
        <DetectionResultsChart data={data.detectionResults} />
      </section>

      <section className="overview-four-col-grid">
        <TopSourceIpsCard items={data.topSourceIps} />
        <TriggeredRulesCard items={data.triggeredRules} />
        <LiveActivityFeedCard items={data.activityFeed} />
        <SystemSummaryCard items={data.systemSummary} />
      </section>
    </div>
  );
}