import { SectionCard } from '../components/SectionCard';
import { useDashboardOverview } from '../hooks/useDashboardOverview';
import { useSecurityEvents } from '../hooks/useSecurityEvents';
import { buildEngineCards, formatCompact } from '../utils/janusDerived';

export function DetectionEnginesPage() {
  const { data, loading, error } = useDashboardOverview();
  const { packets } = useSecurityEvents(80);
  const engines = buildEngineCards(data, packets);

  return (
    <div className="page-stack">
      <section className="page-hero-row events-hero-row">
        <div>
          <h2 className="page-section-title">Detection Engines</h2>
          <p className="page-section-subtitle">
            Real-time inspection layer status and performance metrics across the security stack.
          </p>
        </div>
      </section>

      {error ? <div className="placeholder-box">{error}</div> : null}
      {loading && engines.length === 0 ? (
        <div className="placeholder-box">Loading engine telemetry…</div>
      ) : null}

      <section className="engine-grid">
        {engines.map((engine) => (
          <SectionCard
            key={engine.name}
            title={engine.name}
            className="engine-card"
            subtitle={engine.statusText}
          >
            <div className={`engine-status engine-status-${engine.statusTone}`}>
              {engine.statusText}
            </div>

            <div className="engine-metric-grid">
              <div className="engine-metric-box">
                <span>Packets</span>
                <strong>{engine.packetsLabel}</strong>
              </div>

              <div className="engine-metric-box">
                <span>Matches</span>
                <strong>{engine.matchesLabel}</strong>
              </div>
            </div>

            <div className="engine-latency-row">
              <div>
                <span className="detail-label">Avg Latency</span>
                <strong>{engine.latencyLabel}</strong>
              </div>

              <div className="engine-mini-meter">
                <div
                  className="engine-mini-meter-bar"
                  style={{ width: `${engine.meterValue}%` }}
                />
              </div>
            </div>
          </SectionCard>
        ))}
      </section>

      <SectionCard
        title="Stage Activity Share"
        subtitle="Relative share of packets reaching each stage"
        className="throughput-card"
      >
        <div className="throughput-list">
          {engines.map((engine) => (
            <div key={engine.name} className="throughput-row">
              <div className="throughput-row-top">
                <span>{engine.name}</span>
                <strong>{engine.meterValue.toFixed(0)}%</strong>
              </div>

              <div className="throughput-track">
                <div
                  className="throughput-bar"
                  style={{ width: `${engine.meterValue}%` }}
                />
              </div>
            </div>
          ))}
        </div>

        <div className="detail-label" style={{ marginTop: 12 }}>
          Current live packet buffer: {formatCompact(packets.length)} packets observed in the client.
        </div>
      </SectionCard>
    </div>
  );
}