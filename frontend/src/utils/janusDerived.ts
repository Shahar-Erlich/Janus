import type { DashboardViewModel } from '../mappers/dashboardMappers';
import type { PacketRecord } from '../types';

export type EngineCardModel = {
  name: string;
  statusText: string;
  statusTone: 'healthy' | 'warning' | 'danger';
  packetsLabel: string;
  matchesLabel: string;
  latencyLabel: string;
  meterValue: number;
};

export type HeatmapCell = {
  label: string;
  value: number;
};

export function formatCompact(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return `${value}`;
}

export function formatPct(value: number): string {
  return `${Math.round(value)}%`;
}

export function statusSeverityColor(status: PacketRecord['status']): 'critical' | 'high' | 'medium' | 'low' {
  switch (status) {
    case 'Blocked':
      return 'critical';
    case 'Flagged':
      return 'high';
    default:
      return 'low';
  }
}

export function buildEngineCards(dashboard: DashboardViewModel, packets: PacketRecord[]): EngineCardModel[] {
  const packetCount = Math.max(packets.length, 1);
  const avgLatency = packets.reduce((sum, packet) => sum + packet.latencyMs, 0) / packetCount;

  return dashboard.detectionResults.map((item, index) => {
    const normalized = item.name.toLowerCase();
    const heavy = normalized.includes('dpi');
    const warning = heavy || avgLatency > 3;
    const statusTone: EngineCardModel['statusTone'] = warning ? 'warning' : 'healthy';
    const matchRate = item.total / packetCount;

    return {
      name: item.name,
      statusText: warning ? 'Observed / Active' : 'Healthy / Active',
      statusTone,
      packetsLabel: formatCompact(Math.max(item.total * 30, item.total)),
      matchesLabel: formatCompact(item.total),
      latencyLabel: `${(Math.max(avgLatency, 0.08) * (heavy ? 1.8 : 1 + index * 0.08)).toFixed(2)}ms`,
      meterValue: Math.min(100, Math.max(8, Math.round(matchRate * 100))),
    };
  });
}

export function buildHourlyHeatmap(trafficSeries: DashboardViewModel['trafficSeries']): HeatmapCell[] {
  const base = Array.from({ length: 12 }, (_, index) => ({
    label: `${String(index * 2).padStart(2, '0')}:00`,
    value: 0,
  }));

  trafficSeries.forEach((point, index) => {
    base[index % base.length].value += point.inbound;
  });

  const max = Math.max(...base.map((item) => item.value), 1);
  return base.map((item) => ({
    ...item,
    value: Math.round((item.value / max) * 100),
  }));
}

export function deriveThreatTotals(packets: PacketRecord[]) {
  return packets.reduce(
    (acc, packet) => {
      if (packet.status === 'Blocked') acc.blocked += 1;
      else if (packet.status === 'Flagged') acc.flagged += 1;
      else acc.passed += 1;
      return acc;
    },
    { blocked: 0, flagged: 0, passed: 0 },
  );
}

export function buildRecentIncidents(dashboard: DashboardViewModel, packets: PacketRecord[]) {
  const fromActivity = dashboard.activityFeed.map((item, index) => ({
    id: `activity-${index}`,
    title: item.source,
    description: item.message,
    time: item.time,
    tone: index === 0 ? 'warning' : 'neutral',
  }));

  const fromPackets = packets.slice(0, 3).map((packet) => ({
    id: `packet-${packet.id}`,
    title: `${packet.status} ${packet.protocol}`,
    description: `${packet.sourceIp} → ${packet.destinationIp}`,
    time: packet.timestamp,
    tone: packet.status === 'Blocked' ? 'danger' : packet.status === 'Flagged' ? 'warning' : 'neutral',
  }));

  return [...fromPackets, ...fromActivity].slice(0, 4);
}
