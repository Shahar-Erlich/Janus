import type { DashboardOverviewResponse } from '../generated/janus_frontend';
import type {
  ActivityFeedItem,
  DetectionEngineBar,
  MetricCard,
  ProtocolShare,
  SummaryItem,
  TopSourceIp,
  TrafficPoint,
  TriggeredRule,
} from '../types';

export type DashboardViewModel = {
  metrics: MetricCard[];
  trafficSeries: TrafficPoint[];
  protocolDistribution: ProtocolShare[];
  detectionResults: DetectionEngineBar[];
  topSourceIps: TopSourceIp[];
  triggeredRules: TriggeredRule[];
  activityFeed: ActivityFeedItem[];
  systemSummary: SummaryItem[];
};

export const emptyDashboardViewModel: DashboardViewModel = {
  metrics: [],
  trafficSeries: [],
  protocolDistribution: [],
  detectionResults: [],
  topSourceIps: [],
  triggeredRules: [],
  activityFeed: [],
  systemSummary: [],
};

function toDeltaTone(tone: string | undefined): MetricCard['deltaTone'] {
  switch ((tone ?? '').toLowerCase()) {
    case 'positive':
      return 'positive';
    case 'negative':
      return 'negative';
    case 'warning':
      return 'warning';
    default:
      return 'neutral';
  }
}

function toSummaryTone(tone: string | undefined): SummaryItem['tone'] {
  switch ((tone ?? '').toLowerCase()) {
    case 'healthy':
      return 'healthy';
    case 'warning':
      return 'warning';
    case 'danger':
      return 'danger';
    default:
      return 'neutral';
  }
}

function toSeverity(value: string | undefined): TriggeredRule['severity'] {
  switch ((value ?? '').toLowerCase()) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    default:
      return 'Low';
  }
}

function formatTime(tsUnixMs: number): string {
  if (!tsUnixMs) return '--:--:--';
  return new Date(tsUnixMs).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function mapDashboardOverview(response: DashboardOverviewResponse): DashboardViewModel {
  return {
    metrics: response.metrics.map((metric) => ({
      label: metric.label,
      value: metric.value,
      delta: metric.delta || undefined,
      deltaTone: toDeltaTone(metric.tone),
      highlight: metric.highlight,
    })),
    trafficSeries: response.trafficSeries.map((point) => ({
      time: point.timeLabel,
      inbound: point.totalPackets,
      outbound: point.allowedPackets,
    })),
    protocolDistribution: response.protocolDistribution.map((item) => ({
      name: item.name,
      value: item.totalPackets,
    })),
    detectionResults: response.detectionResults.map((item) => ({
      name: item.name,
      total: item.total,
    })),
    topSourceIps: response.topSourceIps.map((item) => ({
      ip: item.ip,
      requests: item.requestsLabel,
    })),
    triggeredRules: response.triggeredRules.map((item) => ({
      rule: item.ruleName || `Rule #${item.ruleId}`,
      severity: toSeverity(item.severity),
      hits: item.hitCount,
    })),
    activityFeed: response.activityFeed.map((item) => ({
      time: formatTime(item.tsUnixMs),
      source: item.source,
      message: item.message,
    })),
    systemSummary: response.systemSummary.map((item) => ({
      label: item.label,
      value: item.value,
      tone: toSummaryTone(item.tone),
    })),
  };
}
