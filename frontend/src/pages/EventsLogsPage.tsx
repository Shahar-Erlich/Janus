import { AlertTriangle, RotateCcw, Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { PacketDetailsPanel } from '../components/live-traffic/PacketDetailsPanel';
import { SectionCard } from '../components/SectionCard';
import { useSecurityEvents } from '../hooks/useSecurityEvents';
import { statusSeverityColor } from '../utils/janusDerived';
import type { PacketRecord } from '../types';

const timeFilters = ['All Time', 'Last 24 Hours', 'Last Hour'];
const actionFilters = ['Any Action', 'Passed', 'Flagged', 'Blocked'];

function matchesSearch(packet: PacketRecord, query: string) {
  const haystack = [
    packet.id,
    packet.sourceIp,
    packet.destinationIp,
    packet.sourcePort,
    packet.destinationPort,
    packet.protocol,
    packet.actionReason,
    packet.status,
  ]
    .join(' ')
    .toLowerCase();

  return haystack.includes(query.toLowerCase());
}

export function EventsLogsPage() {
  const { packets, selectedId, setSelectedId, selectedPacket, loading, error } = useSecurityEvents(120);
  const [search, setSearch] = useState('');
  const [activeTab, setActiveTab] = useState<'All Events' | 'Allowed' | 'Blocked' | 'Flagged'>('All Events');
  const [timeFilter, setTimeFilter] = useState('Last 24 Hours');
  const [actionFilter, setActionFilter] = useState('Any Action');

  const filteredPackets = useMemo(() => {
    let next = packets;

    if (activeTab === 'Allowed') next = next.filter((packet) => packet.status === 'Passed');
    if (activeTab === 'Blocked') next = next.filter((packet) => packet.status === 'Blocked');
    if (activeTab === 'Flagged') next = next.filter((packet) => packet.status === 'Flagged');

    if (actionFilter !== 'Any Action') {
      const expected = actionFilter === 'Passed' ? 'Passed' : actionFilter === 'Blocked' ? 'Blocked' : 'Flagged';
      next = next.filter((packet) => packet.status === expected);
    }

    if (search.trim()) {
      next = next.filter((packet) => matchesSearch(packet, search.trim()));
    }

    return next;
  }, [packets, activeTab, actionFilter, search]);

  const counters = useMemo(() => ({
    all: packets.length,
    allowed: packets.filter((packet) => packet.status === 'Passed').length,
    blocked: packets.filter((packet) => packet.status === 'Blocked').length,
    flagged: packets.filter((packet) => packet.status === 'Flagged').length,
  }), [packets]);

  return (
    <div className="page-stack">
      <section className="page-hero-row events-hero-row">
        <div>
          <h2 className="page-section-title">Security Events</h2>
          <p className="page-section-subtitle">Real-time threat monitoring and searchable event analysis.</p>
        </div>
        {/* <div className="hero-button-row">
          <button className="secondary-button">Export CSV</button>
          <button className="primary-button">Live Stream</button>
        </div> */}
      </section>

      <section className="events-tab-row">
        {[
          ['All Events', counters.all],
          ['Allowed', counters.allowed],
          ['Blocked', counters.blocked],
          ['Flagged', counters.flagged],
        ].map(([label, count]) => (
          <button
            key={label}
            className={`events-tab ${activeTab === label ? 'events-tab-active' : ''}`}
            onClick={() => setActiveTab(label as typeof activeTab)}
          >
            <span>{label}</span>
            {label === 'Flagged' && count > 0 ? <span className="events-tab-badge">{count}</span> : null}
          </button>
        ))}
      </section>

      <div className="events-layout">
        <SectionCard
          title="Event Stream"
          subtitle={timeFilter}
          className="events-stream-card"
          rightSlot={
            <div className="events-filter-row-inline">
              <label className="page-search events-search-inline">
                <Search size={16} />
                <input
                  placeholder="Search by Event ID, IP, or Rule name..."
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
              </label>
            </div>
          }
        >
          <div className="events-toolbar">
            <select className="toolbar-select" value={timeFilter} onChange={(event) => setTimeFilter(event.target.value)}>
              {timeFilters.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
            <select className="toolbar-select" value={actionFilter} onChange={(event) => setActionFilter(event.target.value)}>
              {actionFilters.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
            <button className="reset-link-button" onClick={() => { setSearch(''); setActionFilter('Any Action'); setTimeFilter('Last 24 Hours'); setActiveTab('All Events'); }}>
              <RotateCcw size={14} /> Reset
            </button>
          </div>

          {error ? <div className="placeholder-box">{error}</div> : null}
          {loading && packets.length === 0 ? <div className="placeholder-box">Loading security events…</div> : null}

          <div className="events-grid-header">
            <span>Severity</span>
            <span>Timestamp</span>
            <span>Source IP</span>
            <span>Dest IP</span>
            <span>Protocol</span>
            <span>Action</span>
          </div>

          <div className="events-grid-body">
            {filteredPackets.map((packet) => {
              const severity = statusSeverityColor(packet.status);
              return (
                <button
                  key={packet.id}
                  className={`event-row ${selectedId === packet.id ? 'event-row-active' : ''}`}
                  onClick={() => setSelectedId(packet.id)}
                >
                  <div className={`event-severity event-severity-${severity}`}>{severity.toUpperCase()}</div>
                  <div>{packet.timestamp}</div>
                  <div className="strong">{packet.sourceIp}</div>
                  <div className="strong">{packet.destinationIp}</div>
                  <div><span className={`protocol-pill protocol-${packet.protocol.toLowerCase()}`}>{packet.protocol}</span></div>
                  <div className="event-action-text">{packet.status}</div>
                </button>
              );
            })}

            {!loading && filteredPackets.length === 0 ? (
              <div className="placeholder-box">No events matched the selected filters.</div>
            ) : null}
          </div>
        </SectionCard>

        <aside className="packet-panel event-details-shell">
          <div className="event-side-header">
            <div className="event-side-title">
              <span className="event-side-icon"><AlertTriangle size={18} /></span>
              <div>
                <h3>Event Details</h3>
                <div className="detail-label">ID: {selectedPacket?.id ?? '—'}</div>
              </div>
            </div>
          </div>

          {selectedPacket ? <PacketDetailsPanel packet={selectedPacket} /> : <div className="placeholder-box">Select an event to inspect its details.</div>}
        </aside>
      </div>
    </div>
  );
}
