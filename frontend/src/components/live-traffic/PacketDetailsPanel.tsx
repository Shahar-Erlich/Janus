import { CheckCircle2, X } from 'lucide-react';
import { PacketRecord } from '../../types';

type PacketDetailsPanelProps = {
  packet: PacketRecord;
};

const pathOrder: Array<'INGRESS' | 'POLICY' | 'SPI' | 'DPI' | 'EGRESS'> = [
  'INGRESS',
  'POLICY',
  'SPI',
  'DPI',
  'EGRESS',
];

export function PacketDetailsPanel({ packet }: PacketDetailsPanelProps) {
  return (
    <aside className="packet-panel">
      <div className="packet-panel-header">
        <h3>Packet Details</h3>
        <button className="ghost-icon-button" aria-label="Close panel">
          <X size={16} />
        </button>
      </div>

      <div className="detail-box">
        <div className="detail-box-header">
          <span>Detection Path</span>
          <span className={`status-pill-small status-${packet.status.toLowerCase()}`}>
            {packet.status === 'Passed' ? (
              <>
                <CheckCircle2 size={12} /> Passed
              </>
            ) : (
              packet.status
            )}
          </span>
        </div>

        <div className="path-row">
          {pathOrder.map((step, index) => {
            const active = packet.enginePath.includes(step);
            return (
              <div key={step} className="path-node-wrap">
                <div className={`path-node ${active ? 'path-node-active' : ''}`} />
                <span>{step}</span>
                {index < pathOrder.length - 1 ? <div className="path-link" /> : null}
              </div>
            );
          })}
        </div>
      </div>

      <div className="packet-metrics-grid">
        <div className="packet-mini-card">
          <span>Action Reason</span>
          <strong>{packet.actionReason}</strong>
        </div>
        <div className="packet-mini-card">
          <span>Total Latency</span>
          <strong>{packet.latencyMs}ms</strong>
        </div>
      </div>

      <div className="detail-box">
        <div className="detail-label">Protocol Header</div>
        <div className="code-block">
          {packet.protocolHeaderHex.map((line) => (
            <div key={line}>{line}</div>
          ))}
        </div>
      </div>

      <div className="detail-box">
        <div className="detail-label">Payload (UTF-8 preview)</div>
        <div className="code-block code-block-payload">
          {packet.payloadPreview.map((line) => (
            <div key={line}>{line}</div>
          ))}
        </div>
      </div>

      <div className="packet-panel-actions">
        <button className="primary-outline-button">View Full PCAP</button>
        <button className="secondary-button">Report False Pos.</button>
      </div>
    </aside>
  );
}
