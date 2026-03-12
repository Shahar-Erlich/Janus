import { RotateCcw, Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { FilterChip } from '../components/FilterChip';
import { PacketDetailsPanel } from '../components/live-traffic/PacketDetailsPanel';
import { TrafficTable } from '../components/live-traffic/TrafficTable';
import { protocolFilters, packets } from '../data/mockData';

export function LiveTrafficPage() {
  const [selectedId, setSelectedId] = useState(packets[0].id);
  const selectedPacket = useMemo(
    () => packets.find((packet) => packet.id === selectedId) ?? packets[0],
    [selectedId],
  );

  return (
    <div className="page-stack">
      <section className="page-hero-row">
        <div>
          <h2 className="page-section-title">Live Traffic Monitoring</h2>
          <p className="page-section-subtitle">Real-time packet inspection and flow analysis</p>
        </div>

        <label className="page-search">
          <Search size={16} />
          <input placeholder="Search by IP address, Port, or Rule ID" />
        </label>
      </section>

      <section className="filter-bar">
        <div className="filter-chip-row">
          {protocolFilters.map((filter) => (
            <FilterChip key={filter.label} label={filter.label} />
          ))}
        </div>
        <button className="reset-link-button">
          <RotateCcw size={14} /> Reset Filters
        </button>
      </section>

      <section className="live-traffic-layout">
        <div className="table-card">
          <TrafficTable
            packets={packets}
            selectedId={selectedPacket.id}
            onSelect={(packet) => setSelectedId(packet.id)}
          />
        </div>
        <PacketDetailsPanel packet={selectedPacket} />
      </section>

      <footer className="live-footer-bar">
        <div className="live-footer-item">
          <span className="status-dot" />
          <span>Live Feed: <strong>Active</strong></span>
        </div>
        <div className="live-footer-item">Packets/sec: <strong>1.2k</strong></div>
        <div className="live-footer-item">Buffer Health: <strong>98%</strong></div>
        <div className="live-footer-item">Threat Level: <strong>Low</strong></div>
        <div className="live-footer-item">SOC-NODE-04 | 2.4.1-stable</div>
      </footer>
    </div>
  );
}
