import { ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { SectionCard } from '../components/SectionCard';
import { useDashboardOverview } from '../hooks/useDashboardOverview';
import { useSecurityEvents } from '../hooks/useSecurityEvents';
import { buildHourlyHeatmap, formatCompact } from '../utils/janusDerived';

const COLORS = ['#48b7ff', '#ff4f7d', '#f1b326', '#4dd4b6', '#8899bb'];

export function ReportsAnalyticsPage() {
  const { data, loading, error } = useDashboardOverview();
  const { packets } = useSecurityEvents(120);
  const heatmap = buildHourlyHeatmap(data.trafficSeries);

  return (
    <div className="page-stack">
      <section className="page-hero-row events-hero-row">
        <div>
          <h2 className="page-section-title">Reports & Analytics</h2>
          <p className="page-section-subtitle">Operational trends, protocol breakdown, and offender intelligence derived from the Janus protobuf stream.</p>
        </div>
        {/* <div className="hero-button-row">
          <button className="secondary-button">Export PDF</button>
          <button className="primary-button">Export CSV</button>
        </div> */}
      </section>

      {error ? <div className="placeholder-box">{error}</div> : null}
      {loading && data.metrics.length === 0 ? <div className="placeholder-box">Loading analytics…</div> : null}

      <section className="stats-grid reports-stat-grid">
        {data.metrics.slice(0, 4).map((metric) => (
          <div key={metric.label} className="stat-card">
            <div className="stat-label">{metric.label}</div>
            <div className="stat-value-row">
              <div className="stat-value">{metric.value}</div>
              {metric.delta ? <div className="stat-delta">{metric.delta}</div> : null}
            </div>
          </div>
        ))}
      </section>

      <section className="reports-grid-top">
        <SectionCard title="Traffic Intelligence Trends" subtitle="Inbound vs allowed packet trend" className="reports-chart-card">
          <div className="chart-wrapper chart-tall">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.trafficSeries}>
                <Bar dataKey="inbound" radius={[10, 10, 0, 0]} fill="#48b7ff" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </SectionCard>

        <SectionCard title="Threat Distribution" subtitle="Protocol activity share" className="reports-donut-card">
          <div className="protocol-layout">
            <div className="donut-chart-wrapper">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={data.protocolDistribution} innerRadius={62} outerRadius={78} dataKey="value" stroke="transparent">
                    {data.protocolDistribution.map((entry, index) => (
                      <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-center">
                <strong>{formatCompact(data.protocolDistribution.reduce((sum, item) => sum + item.value, 0))}</strong>
                <span>Total</span>
              </div>
            </div>
            <div className="protocol-legend-list">
              {data.protocolDistribution.map((item, index) => (
                <div key={item.name} className="protocol-legend-row">
                  <div className="protocol-label-wrap">
                    <span className="protocol-color" style={{ background: COLORS[index % COLORS.length] }} />
                    <span>{item.name}</span>
                  </div>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>
      </section>

      <section className="reports-grid-bottom">
        <SectionCard title="Suspicious Activity Heatmap" subtitle="Two-hour buckets from current traffic series" className="reports-heatmap-card">
          <div className="heatmap-grid">
            {heatmap.map((cell) => (
              <div key={cell.label} className="heatmap-cell-wrap">
                <div className="heatmap-cell" style={{ opacity: Math.max(0.15, cell.value / 100) }} />
                <span>{cell.label}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="Top Offending IPs" subtitle="Live event and overview correlation" className="reports-ip-card">
          <div className="top-ip-list-dense">
            {data.topSourceIps.map((item, index) => (
              <div key={item.ip} className="top-ip-row">
                <div>
                  <div className="strong">{item.ip}</div>
                  <div className="detail-label">#{index + 1} ranked source</div>
                </div>
                <div className="top-ip-hits">{item.requests}</div>
              </div>
            ))}
            {data.topSourceIps.length === 0 && !loading ? <div className="placeholder-box">No top offenders available yet.</div> : null}
          </div>
          <div className="detail-label" style={{ marginTop: 12 }}>Recent packets observed in client: {formatCompact(packets.length)}</div>
        </SectionCard>
      </section>
    </div>
  );
}
