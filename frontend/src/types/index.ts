import type { LucideIcon } from 'lucide-react';

export type NavItem = {
  label: string;
  to: string;
  icon: LucideIcon;
  section?: string;
};

export type MetricCard = {
  label: string;
  value: string;
  delta?: string;
  deltaTone?: 'positive' | 'negative' | 'warning' | 'neutral';
  highlight?: boolean;
};

export type TrafficPoint = {
  time: string;
  inbound: number;
  outbound: number;
};

export type ProtocolShare = {
  name: string;
  value: number;
};

export type DetectionEngineBar = {
  name: string;
  total: number;
};

export type TopSourceIp = {
  ip: string;
  requests: string;
};

export type TriggeredRule = {
  rule: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  hits: number;
};

export type ActivityFeedItem = {
  time: string;
  source: string;
  message: string;
};

export type SummaryItem = {
  label: string;
  value: string;
  tone?: 'healthy' | 'warning' | 'danger' | 'neutral';
};

export type FilterOption = {
  label: string;
  value: string;
};

export type PacketRecord = {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: 'TCP' | 'UDP' | 'HTTP';
  enginePath: Array<'INGRESS' | 'POLICY' | 'SPI' | 'DPI' | 'EGRESS'>;
  latencyMs: number;
  actionReason: string;
  status: 'Passed' | 'Blocked' | 'Flagged';
  payloadPreview: string[];
  protocolHeaderHex: string[];
};
