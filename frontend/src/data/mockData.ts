import {
  ActivityFeedItem,
  DetectionEngineBar,
  FilterOption,
  MetricCard,
  PacketRecord,
  ProtocolShare,
  SummaryItem,
  TopSourceIp,
  TrafficPoint,
  TriggeredRule,
} from '../types';

export const overviewMetrics: MetricCard[] = [
  { label: 'Total Packets', value: '1.2B', delta: '+5.2%', deltaTone: 'positive' },
  { label: 'Allowed', value: '850M', delta: 'Stable', deltaTone: 'positive' },
  { label: 'Blocked', value: '350M', delta: 'High', deltaTone: 'negative', highlight: true },
  { label: 'Flagged', value: '2M', delta: '+0.8%', deltaTone: 'warning' },
  { label: 'Active Engines', value: '6/6', delta: '100%', deltaTone: 'positive' },
  { label: 'Avg Latency', value: '1.2ms', delta: '-0.1ms', deltaTone: 'positive' },
];

export const trafficSeries: TrafficPoint[] = [
  { time: '09:00', inbound: 160, outbound: 120 },
  { time: '09:03', inbound: 180, outbound: 140 },
  { time: '09:06', inbound: 290, outbound: 190 },
  { time: '09:09', inbound: 210, outbound: 150 },
  { time: '09:12', inbound: 430, outbound: 260 },
  { time: '09:15', inbound: 220, outbound: 180 },
  { time: '09:18', inbound: 690, outbound: 410 },
  { time: '09:21', inbound: 210, outbound: 175 },
  { time: '09:24', inbound: 710, outbound: 420 },
  { time: '09:27', inbound: 740, outbound: 460 },
  { time: '09:30', inbound: 480, outbound: 260 },
];

export const protocolDistribution: ProtocolShare[] = [
  { name: 'TCP', value: 65 },
  { name: 'UDP', value: 25 },
  { name: 'HTTP', value: 8 },
  { name: 'Other', value: 2 },
];

export const detectionResults: DetectionEngineBar[] = [
  { name: 'Policy', total: 420 },
  { name: 'SPI', total: 355 },
  { name: 'DPI', total: 510 },
  { name: 'Regex', total: 190 },
  { name: 'Aho', total: 275 },
  { name: 'SIMD', total: 640 },
];

export const topSourceIps: TopSourceIp[] = [
  { ip: '192.168.1.104', requests: '45.2k req' },
  { ip: '10.0.4.55', requests: '32.1k req' },
  { ip: '45.33.22.11', requests: '18.4k req' },
  { ip: '185.199.108.153', requests: '12.8k req' },
];

export const triggeredRules: TriggeredRule[] = [
  { rule: 'SQL Injection Attempt', severity: 'Critical', hits: 418 },
  { rule: 'Unauthorized API Key Pattern', severity: 'High', hits: 266 },
  { rule: 'Blocked Tor Exit Node', severity: 'Medium', hits: 189 },
  { rule: 'Suspicious Payload Signature', severity: 'High', hits: 123 },
];

export const activityFeed: ActivityFeedItem[] = [
  { time: '14:02:11', source: 'Node A', message: 'Conn established' },
  { time: '14:02:13', source: 'SPI', message: 'Header path validated' },
  { time: '14:02:15', source: 'DPI', message: 'Payload sampled for inspection' },
  { time: '14:02:18', source: 'Policy', message: 'Whitelist match applied' },
  { time: '14:02:21', source: 'Core', message: 'Forwarded to trusted network' },
];

export const systemSummary: SummaryItem[] = [
  { label: 'Zone', value: 'Trusted Zone', tone: 'healthy' },
  { label: 'Core Status', value: 'Healthy', tone: 'healthy' },
  { label: 'Queue Depth', value: '31 / 512', tone: 'neutral' },
  { label: 'Threat Level', value: 'Low', tone: 'healthy' },
];

export const protocolFilters: FilterOption[] = [
  { label: 'Protocol: TCP/UDP', value: 'all' },
  { label: 'Action: All', value: 'all' },
  { label: 'Engine: SPI/DPI', value: 'all' },
  { label: 'Time: Last 5m', value: '5m' },
];

export const packets: PacketRecord[] = [
  {
    id: 'pkt-1',
    timestamp: '2026-03-24 14:22:10',
    sourceIp: '192.168.1.104',
    destinationIp: '8.8.8.8',
    sourcePort: 53210,
    destinationPort: 443,
    protocol: 'TCP',
    enginePath: ['INGRESS', 'POLICY', 'SPI', 'DPI', 'EGRESS'],
    latencyMs: 0.45,
    actionReason: 'Policy #2104 Match',
    status: 'Passed',
    protocolHeaderHex: [
      '0000 45 00 05 a9 d7 0a 40 00 40 06 c4 20 c0 a8 01 68',
      '0010 08 08 08 08 cf da 01 bb 1d ac ab a1 d5 f7 1d cc',
      '0020 80 18 01 f5 b4 b0 00 00 01 01 08 0a c7 47 f0 fa',
    ],
    payloadPreview: [
      'GET /api/v2/telemetry HTTP/1.1',
      'Host: janus-cloud.io',
      'User-Agent: JanusProbe/4.1.2',
      'Authorization: Bearer eyJhbGciOiJIUzI1Ni...',
      'Accept: application/json',
      'Connection: keep-alive',
    ],
  },
  {
    id: 'pkt-2',
    timestamp: '2026-03-24 14:22:09',
    sourceIp: '10.0.4.55',
    destinationIp: '104.18.12.31',
    sourcePort: 44922,
    destinationPort: 443,
    protocol: 'TCP',
    enginePath: ['INGRESS', 'POLICY', 'SPI', 'DPI', 'EGRESS'],
    latencyMs: 0.62,
    actionReason: 'Regex payload review',
    status: 'Passed',
    protocolHeaderHex: ['0000 45 00 04 c2 af 0f 40 00 40 06 d2 19 0a 00 04 37'],
    payloadPreview: ['POST /v1/auth/session HTTP/1.1', 'Host: cdn-secure.net'],
  },
  {
    id: 'pkt-3',
    timestamp: '2026-03-24 14:22:08',
    sourceIp: '192.168.1.12',
    destinationIp: '185.199.108.153',
    sourcePort: 53112,
    destinationPort: 443,
    protocol: 'TCP',
    enginePath: ['INGRESS', 'POLICY', 'SPI', 'DPI', 'EGRESS'],
    latencyMs: 0.51,
    actionReason: 'SIMD anchor passed',
    status: 'Passed',
    protocolHeaderHex: ['0000 45 00 05 14 81 3d 40 00 40 06 aa 73 c0 a8 01 0c'],
    payloadPreview: ['TLS application data detected', 'Payload omitted in preview'],
  },
  {
    id: 'pkt-4',
    timestamp: '2026-03-24 14:22:07',
    sourceIp: '45.33.22.11',
    destinationIp: '192.168.1.1',
    sourcePort: 1025,
    destinationPort: 22,
    protocol: 'TCP',
    enginePath: ['INGRESS', 'POLICY', 'SPI', 'DPI'],
    latencyMs: 0.91,
    actionReason: 'Blocked source / SSH attempt',
    status: 'Blocked',
    protocolHeaderHex: ['0000 45 00 00 34 7a 10 40 00 35 06 8b 2a 2d 21 16 0b'],
    payloadPreview: ['SSH-2.0-OpenSSH_9.6', 'KEXINIT withheld after block'],
  },
  {
    id: 'pkt-5',
    timestamp: '2026-03-24 14:22:06',
    sourceIp: '192.168.1.104',
    destinationIp: '1.1.1.1',
    sourcePort: 54001,
    destinationPort: 53,
    protocol: 'UDP',
    enginePath: ['INGRESS', 'POLICY', 'SPI', 'EGRESS'],
    latencyMs: 0.28,
    actionReason: 'DNS allowed by policy',
    status: 'Passed',
    protocolHeaderHex: ['0000 45 00 00 4c 12 7e 00 00 40 11 9d 41 c0 a8 01 68'],
    payloadPreview: ['DNS query: janus-cloud.io A IN'],
  },
];
