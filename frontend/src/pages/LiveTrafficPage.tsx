import { RotateCcw, Search } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { PacketDetailsPanel } from '../components/live-traffic/PacketDetailsPanel';
import { TrafficTable } from '../components/live-traffic/TrafficTable';
import { mapLivePacketEvent, mapPacketDetails, mapPacketSummary } from '../mappers/packetMappers';
import { janusClient } from '../services/janusClient';
import type { PacketRecord } from '../types';

type ProtocolFilterValue = 'ALL' | 'TCP' | 'UDP' | 'HTTP' | 'OTHER';
type ActionFilterValue = 'ALL' | 'Passed' | 'Blocked' | 'Flagged';
type EngineFilterValue = 'ALL' | 'SPI_DPI' | 'SPI' | 'DPI' | 'POLICY';
type TimeFilterValue = '5M' | '15M' | '1H' | '24H' | 'ALL';

const protocolOptions: Array<{ label: string; value: ProtocolFilterValue }> = [
  { label: 'Protocol: TCP/UDP', value: 'ALL' },
  { label: 'Protocol: TCP', value: 'TCP' },
  { label: 'Protocol: UDP', value: 'UDP' },
  { label: 'Protocol: HTTP', value: 'HTTP' },
  { label: 'Protocol: Other', value: 'OTHER' },
];

const actionOptions: Array<{ label: string; value: ActionFilterValue }> = [
  { label: 'Action: All', value: 'ALL' },
  { label: 'Action: Passed', value: 'Passed' },
  { label: 'Action: Blocked', value: 'Blocked' },
  { label: 'Action: Flagged', value: 'Flagged' },
];

const engineOptions: Array<{ label: string; value: EngineFilterValue }> = [
  { label: 'Engine: SPI/DPI', value: 'SPI_DPI' },
  { label: 'Engine: Policy', value: 'POLICY' },
  { label: 'Engine: SPI', value: 'SPI' },
  { label: 'Engine: DPI', value: 'DPI' },
  { label: 'Engine: All', value: 'ALL' },
];

const timeOptions: Array<{ label: string; value: TimeFilterValue }> = [
  { label: 'Time: Last 5m', value: '5M' },
  { label: 'Time: Last 15m', value: '15M' },
  { label: 'Time: Last 1h', value: '1H' },
  { label: 'Time: Last 24h', value: '24H' },
  { label: 'Time: All Loaded', value: 'ALL' },
];

function parsePacketTimestamp(value: string): number | null {
  if (!value) return null;

  // supports "29/03/2026, 01:45:44"
  const match = value.match(
    /^(\d{1,2})\/(\d{1,2})\/(\d{4}),\s*(\d{1,2}):(\d{2})(?::(\d{2}))?$/,
  );

  if (match) {
    const [, dd, mm, yyyy, hh, min, ss] = match;
    const dt = new Date(
      Number(yyyy),
      Number(mm) - 1,
      Number(dd),
      Number(hh),
      Number(min),
      Number(ss ?? '0'),
    );
    return Number.isNaN(dt.getTime()) ? null : dt.getTime();
  }

  const fallback = Date.parse(value);
  return Number.isNaN(fallback) ? null : fallback;
}

function isWithinSelectedWindow(packet: PacketRecord, filter: TimeFilterValue, newestTs: number | null): boolean {
  if (filter === 'ALL') return true;

  const packetTs = parsePacketTimestamp(packet.timestamp);
  if (!packetTs || !newestTs) return true;

  const diffMs = newestTs - packetTs;

  switch (filter) {
    case '5M':
      return diffMs <= 5 * 60 * 1000;
    case '15M':
      return diffMs <= 15 * 60 * 1000;
    case '1H':
      return diffMs <= 60 * 60 * 1000;
    case '24H':
      return diffMs <= 24 * 60 * 60 * 1000;
    default:
      return true;
  }
}

export function LiveTrafficPage() {
  const [packets, setPackets] = useState<PacketRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string>('');
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<ProtocolFilterValue>('ALL');
  const [actionFilter, setActionFilter] = useState<ActionFilterValue>('ALL');
  const [engineFilter, setEngineFilter] = useState<EngineFilterValue>('SPI_DPI');
  const [timeFilter, setTimeFilter] = useState<TimeFilterValue>('5M');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const newestTimestamp = useMemo(() => {
    const values = packets
      .map((packet) => parsePacketTimestamp(packet.timestamp))
      .filter((value): value is number => value !== null);

    return values.length ? Math.max(...values) : null;
  }, [packets]);

  const filteredPackets = useMemo(() => {
    const q = search.trim().toLowerCase();

    return packets.filter((packet) => {
      if (protocolFilter !== 'ALL' && packet.protocol !== protocolFilter) {
        return false;
      }

      if (actionFilter !== 'ALL' && packet.status !== actionFilter) {
        return false;
      }

      if (engineFilter === 'POLICY' && !packet.enginePath.includes('POLICY')) {
        return false;
      }

      if (engineFilter === 'SPI' && !packet.enginePath.includes('SPI')) {
        return false;
      }

      if (engineFilter === 'DPI' && !packet.enginePath.includes('DPI')) {
        return false;
      }

      if (engineFilter === 'SPI_DPI') {
        const hasEither = packet.enginePath.includes('SPI') || packet.enginePath.includes('DPI');
        if (!hasEither) return false;
      }

      if (!isWithinSelectedWindow(packet, timeFilter, newestTimestamp)) {
        return false;
      }

      if (!q) return true;

      const haystack = [
        packet.id,
        packet.sourceIp,
        packet.destinationIp,
        packet.sourcePort,
        packet.destinationPort,
        packet.protocol,
        packet.actionReason,
        packet.status,
        packet.enginePath.join(' '),
      ]
        .join(' ')
        .toLowerCase();

      return haystack.includes(q);
    });
  }, [packets, search, protocolFilter, actionFilter, engineFilter, timeFilter, newestTimestamp]);

  const selectedPacket = useMemo(
    () => filteredPackets.find((packet) => packet.id === selectedId) ?? filteredPackets[0],
    [filteredPackets, selectedId],
  );

  useEffect(() => {
    if (!filteredPackets.length) return;
    if (!selectedPacket) {
      setSelectedId(filteredPackets[0].id);
    }
  }, [filteredPackets, selectedPacket]);

  useEffect(() => {
    let cancelled = false;
    let unsubscribe = () => { };

    const loadRecentPackets = async () => {
      try {
        const response = await janusClient.getRecentPackets(100);
        if (cancelled) return;

        const nextPackets = (response.recentPackets?.packets ?? []).map(mapPacketSummary);
        setPackets(nextPackets);
        setSelectedId((current) => current || nextPackets[0]?.id || '');
        setError(null);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load recent packets');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void loadRecentPackets();

    void janusClient.subscribeLive(true).catch((err) => {
      console.error('Failed to subscribe to live packets', err);
    });

    unsubscribe = janusClient.onLivePacket((response) => {
      if (!response.livePacketEvent || cancelled) return;

      const livePacket = mapLivePacketEvent(response.livePacketEvent);

      setPackets((prev) => {
        const next = [livePacket, ...prev.filter((packet) => packet.id !== livePacket.id)];
        return next.slice(0, 100);
      });

      setSelectedId((current) => current || livePacket.id);
    });

    return () => {
      cancelled = true;
      unsubscribe();
      void janusClient.subscribeLive(false).catch(() => { });
    };
  }, []);

  useEffect(() => {
    if (!selectedPacket) return;
    if (!/^\d+$/.test(selectedPacket.id)) return;
    if (selectedPacket.payloadPreview.length > 0 || selectedPacket.protocolHeaderHex.length > 0) return;

    let cancelled = false;

    const loadDetails = async () => {
      try {
        const response = await janusClient.getPacketDetails(Number(selectedPacket.id));
        if (cancelled || !response.packetDetails) return;

        const enriched = mapPacketDetails(response.packetDetails);
        if (!enriched) return;

        setPackets((prev) =>
          prev.map((packet) => (packet.id === selectedPacket.id ? enriched : packet)),
        );
      } catch (err) {
        if (!cancelled) {
          console.error('Failed to load packet details', err);
        }
      }
    };

    void loadDetails();

    return () => {
      cancelled = true;
    };
  }, [selectedPacket]);

  const resetFilters = () => {
    setSearch('');
    setProtocolFilter('ALL');
    setActionFilter('ALL');
    setEngineFilter('SPI_DPI');
    setTimeFilter('5M');
  };

  const blockedCount = packets.filter((packet) => packet.status === 'Blocked').length;
  const flaggedCount = packets.filter((packet) => packet.status === 'Flagged').length;
  const threatLevel = blockedCount > 0 ? 'High' : flaggedCount > 0 ? 'Medium' : 'Low';

  return (
    <div className="page-stack">
      {error ? (
        <div className="section-card">
          <div className="section-title">Live traffic load error</div>
          <p className="section-subtitle">{error}</p>
        </div>
      ) : null}

      <section className="page-hero-row">
        <div>
          <h2 className="page-section-title">Live Traffic Monitoring</h2>
          <p className="page-section-subtitle">Real-time packet inspection and flow analysis</p>
        </div>

        <label className="page-search">
          <Search size={16} />
          <input
            placeholder="Search by IP address, Port, or Rule ID"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
      </section>

      <section className="filter-bar">
        <div className="filter-chip-row">
          <select
            className="filter-chip"
            value={protocolFilter}
            onChange={(event) => setProtocolFilter(event.target.value as ProtocolFilterValue)}
          >
            {protocolOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          <select
            className="filter-chip"
            value={actionFilter}
            onChange={(event) => setActionFilter(event.target.value as ActionFilterValue)}
          >
            {actionOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          <select
            className="filter-chip"
            value={engineFilter}
            onChange={(event) => setEngineFilter(event.target.value as EngineFilterValue)}
          >
            {engineOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          <select
            className="filter-chip"
            value={timeFilter}
            onChange={(event) => setTimeFilter(event.target.value as TimeFilterValue)}
          >
            {timeOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        <button className="reset-link-button" onClick={resetFilters}>
          <RotateCcw size={14} /> Reset Filters
        </button>
      </section>

      {loading && packets.length === 0 ? (
        <div className="section-card">
          <div className="section-title">Loading live traffic…</div>
          <p className="section-subtitle">Waiting for recent packets from Janus handler.</p>
        </div>
      ) : null}

      <section className="live-traffic-layout">
        <div className="table-card">
          <TrafficTable
            packets={filteredPackets}
            selectedId={selectedPacket?.id ?? ''}
            onSelect={(packet) => setSelectedId(packet.id)}
          />
        </div>

        {selectedPacket ? (
          <PacketDetailsPanel packet={selectedPacket} />
        ) : (
          <aside className="packet-panel">
            <div className="packet-panel-header">
              <h3>Packet Details</h3>
            </div>
            <div className="detail-box">
              <div className="detail-label">No packet selected</div>
            </div>
          </aside>
        )}
      </section>

      <footer className="live-footer-bar">
        <div className="live-footer-item">
          <span className="status-dot" />
          <span>Live Feed: <strong>Active</strong></span>
        </div>
        <div className="live-footer-item">Packets Loaded: <strong>{packets.length}</strong></div>
        <div className="live-footer-item">Filtered View: <strong>{filteredPackets.length}</strong></div>
        <div className="live-footer-item">Blocked: <strong>{blockedCount}</strong></div>
        <div className="live-footer-item">Threat Level: <strong>{threatLevel}</strong></div>
        <div className="live-footer-item">Selected: <strong>{selectedPacket?.sourceIp ?? '—'}</strong></div>
      </footer>
    </div>
  );
}