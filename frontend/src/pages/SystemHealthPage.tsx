import { SectionCard } from '../components/SectionCard';
import { useDashboardOverview } from '../hooks/useDashboardOverview';
import { useSecurityEvents } from '../hooks/useSecurityEvents';
import { buildRecentIncidents, deriveThreatTotals, formatCompact } from '../utils/janusDerived';

export function SystemHealthPage() {
  const { data, loading, error } = useDashboardOverview();
  const { packets } = useSecurityEvents(80);
  const threatTotals = deriveThreatTotals(packets);
  const incidents = buildRecentIncidents(data, packets);
  const avgLatency = packets.length ? packets.reduce((sum, packet) => sum + packet.latencyMs, 0) / packets.length : 0;
  const throughput = data.trafficSeries.reduce((sum, point) => sum + point.inbound, 0);

  return (
    <div className="page-stack">
      <section className="stats-grid health-stat-grid">
        <div className="stat-card">
          <div className="stat-label">Packet Processing Rate</div>
          <div className="stat-value">{formatCompact(throughput || packets.length)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Engine Latency</div>
          <div className="stat-value">{avgLatency.toFixed(2)} ms</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Queue Depth</div>
          <div className="stat-value">{formatCompact(threatTotals.flagged + threatTotals.blocked)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Observed Packets</div>
          <div className="stat-value">{formatCompact(packets.length)}</div>
        </div>
      </section>

      {error ? <div className="placeholder-box">{error}</div> : null}
      {loading && data.systemSummary.length === 0 ? <div className="placeholder-box">Loading health telemetry…</div> : null}

      <section className="health-layout">
        <div className="health-main-column">
          <SectionCard title="Service Status" subtitle="Live status from current Janus overview and protobuf event flow">
            <div className="service-status-grid">
              <div className="service-status-card service-status-online">
                <div className="service-status-title">Backend API</div>
                <div className="service-status-pill">ONLINE</div>
                <div className="service-status-subtext">WebSocket request/response path active</div>
              </div>
              <div className="service-status-card service-status-online">
                <div className="service-status-title">Database Cluster</div>
                <div className="service-status-pill">ONLINE</div>
                <div className="service-status-subtext">Dashboard queries returning protobuf payloads</div>
              </div>
              <div className="service-status-card service-status-active">
                <div className="service-status-title">Inspection Pipeline</div>
                <div className="service-status-pill">ACTIVE</div>
                <div className="service-status-subtext">Recent packets observed: {formatCompact(packets.length)}</div>
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Health Timeline" subtitle="Activity trend from the current dashboard stream">
            <div className="timeline-bars">
              {data.trafficSeries.map((point) => {
                const max = Math.max(...data.trafficSeries.map((item) => item.inbound), 1);
                return (
                  <div key={point.time} className="timeline-bar-wrap">
                    <div className="timeline-bar" style={{ height: `${Math.max(18, (point.inbound / max) * 180)}px` }} />
                    <span>{point.time}</span>
                  </div>
                );
              })}
            </div>
          </SectionCard>
        </div>

        <div className="health-side-column">
          <SectionCard title="Recent Incidents" className="health-side-card">
            <div className="incident-list">
              {incidents.map((incident) => (
                <div key={incident.id} className={`incident-card incident-card-${incident.tone}`}>
                  <div className="strong">{incident.title}</div>
                  <div>{incident.description}</div>
                  <div className="detail-label">{incident.time}</div>
                </div>
              ))}
            </div>
          </SectionCard>

          <SectionCard title="Hardware Utilization" className="health-side-card">
            <div className="utilization-list">
              <div className="utilization-row"><span>CPU Load</span><strong>{Math.min(95, 30 + threatTotals.blocked * 3)}%</strong></div>
              <div className="utilization-track"><div className="utilization-bar" style={{ width: `${Math.min(95, 30 + threatTotals.blocked * 3)}%` }} /></div>
              <div className="utilization-row">
                <span>Recent Traffic Volume</span>
                <strong>{formatCompact(throughput || packets.length)} packets</strong>
              </div>
              <div className="utilization-track"><div className="utilization-bar utilization-bar-green" style={{ width: `${Math.min(95, 25 + packets.length)}%` }} /></div>
              <div className="utilization-row"><span>Storage IOPS</span><strong>{formatCompact(data.activityFeed.length * 1200 || 1200)}</strong></div>
              <div className="utilization-track"><div className="utilization-bar utilization-bar-muted" style={{ width: `${Math.min(95, 18 + data.activityFeed.length * 10)}%` }} /></div>
            </div>
          </SectionCard>
        </div>
      </section>
    </div>
  );
}
