import {
  EngineStage,
  Protocol,
  Verdict,
} from '../generated/janus_common';
import type {
  PacketDetailsResponse,
  PacketSummary,
} from '../generated/janus_frontend';
import type { PacketDecisionEvent } from '../generated/janus_packet';
import type { PacketRecord } from '../types';

function formatTimestamp(tsUnixMs: number): string {
  if (!tsUnixMs) return '—';
  return new Date(tsUnixMs).toLocaleString([], {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function mapProtocol(protocol: Protocol): PacketRecord['protocol'] {
  switch (protocol) {
    case Protocol.PROTOCOL_TCP:
      return 'TCP';
    case Protocol.PROTOCOL_UDP:
      return 'UDP';
    case Protocol.PROTOCOL_HTTP:
      return 'HTTP';
    default:
      return 'OTHER';
  }
}

function mapStatus(verdict: Verdict, flagged: boolean): PacketRecord['status'] {
  if (verdict === Verdict.VERDICT_DROP) return 'Blocked';
  if (flagged) return 'Flagged';
  return 'Passed';
}

function normalizeEnginePath(rawStages: string[]): PacketRecord['enginePath'] {
  const ordered: PacketRecord['enginePath'] = [];
  const push = (step: PacketRecord['enginePath'][number]) => {
    if (!ordered.includes(step)) ordered.push(step);
  };

  for (const stage of rawStages) {
    const normalized = stage.replace(/^ENGINE_STAGE_/, '').toUpperCase();

    if (normalized === 'PREPROCESS') push('INGRESS');
    else if (normalized === 'POLICY') push('POLICY');
    else if (normalized === 'VECTOR_FILTER') push('SPI');
    else if (normalized === 'REGEX' || normalized === 'AHO' || normalized === 'DPI') push('DPI');
    else if (normalized === 'ENCAPSULATION' || normalized === 'TRANSMISSION' || normalized === 'LOGGING') push('EGRESS');
  }

  if (!ordered.includes('INGRESS')) ordered.unshift('INGRESS');
  return ordered.length ? ordered : ['INGRESS'];
}

function normalizeEnginePathFromTraceStages(stages: EngineStage[]): PacketRecord['enginePath'] {
  const names = stages.map((stage) => {
    switch (stage) {
      case EngineStage.ENGINE_STAGE_PREPROCESS:
        return 'ENGINE_STAGE_PREPROCESS';
      case EngineStage.ENGINE_STAGE_POLICY:
        return 'ENGINE_STAGE_POLICY';
      case EngineStage.ENGINE_STAGE_VECTOR_FILTER:
        return 'ENGINE_STAGE_VECTOR_FILTER';
      case EngineStage.ENGINE_STAGE_REGEX:
        return 'ENGINE_STAGE_REGEX';
      case EngineStage.ENGINE_STAGE_AHO:
        return 'ENGINE_STAGE_AHO';
      case EngineStage.ENGINE_STAGE_DPI:
        return 'ENGINE_STAGE_DPI';
      case EngineStage.ENGINE_STAGE_ENCAPSULATION:
        return 'ENGINE_STAGE_ENCAPSULATION';
      case EngineStage.ENGINE_STAGE_TRANSMISSION:
        return 'ENGINE_STAGE_TRANSMISSION';
      case EngineStage.ENGINE_STAGE_LOGGING:
        return 'ENGINE_STAGE_LOGGING';
      default:
        return 'ENGINE_STAGE_UNSPECIFIED';
    }
  });

  return normalizeEnginePath(names);
}

export function mapPacketSummary(packet: PacketSummary): PacketRecord {
  return {
    id: String(packet.dbEventId || `${packet.packetId}-${packet.tsUnixMs}`),
    timestamp: formatTimestamp(packet.tsUnixMs),
    sourceIp: packet.sourceIp,
    destinationIp: packet.destinationIp,
    sourcePort: packet.sourcePort,
    destinationPort: packet.destinationPort,
    protocol: mapProtocol(packet.protocol),
    enginePath: normalizeEnginePath(packet.enginePath),
    latencyMs: Number((packet.endToEndProcessingUs / 1000).toFixed(2)),
    actionReason: packet.actionReason || 'No action reason',
    status: mapStatus(packet.verdict, packet.flagged),
    payloadPreview: [],
    protocolHeaderHex: [],
  };
}

export function mapPacketDetails(details: PacketDetailsResponse): PacketRecord | null {
  if (!details.packet) return null;

  const base = mapPacketSummary(details.packet);

  return {
    ...base,
    enginePath: details.processingTrace.length
      ? normalizeEnginePathFromTraceStages(details.processingTrace.map((trace) => trace.stage))
      : base.enginePath,
    payloadPreview: details.payloadPreview ?? [],
    protocolHeaderHex: details.protocolHeaderHex ?? [],
  };
}

export function mapLivePacketEvent(event: PacketDecisionEvent): PacketRecord {
  const metadata = event.metadata;

  return {
    id: metadata?.eventId || `live-${metadata?.packetId ?? 0}-${metadata?.tsUnixMs ?? Date.now()}`,
    timestamp: formatTimestamp(metadata?.tsUnixMs ?? Date.now()),
    sourceIp: metadata?.source?.ip ?? '—',
    destinationIp: metadata?.destination?.ip ?? '—',
    sourcePort: metadata?.source?.port ?? 0,
    destinationPort: metadata?.destination?.port ?? 0,
    protocol: mapProtocol(metadata?.protocol ?? Protocol.PROTOCOL_OTHER),
    enginePath: normalizeEnginePathFromTraceStages(
      (event.processingTrace ?? []).map((trace) => trace.stage),
    ),
    latencyMs: Number(((event.endToEndProcessingUs ?? 0) / 1000).toFixed(2)),
    actionReason: event.matchInfo || event.detectionSource || 'Live event',
    status: mapStatus(event.verdict, event.flagged),
    payloadPreview: [],
    protocolHeaderHex: [],
  };
}
