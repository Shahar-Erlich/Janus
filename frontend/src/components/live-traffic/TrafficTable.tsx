import { ArrowRight, Ban } from 'lucide-react';
import { PacketRecord } from '../../types';
import { cn } from '../../utils/format';

type TrafficTableProps = {
  packets: PacketRecord[];
  selectedId: string;
  onSelect: (packet: PacketRecord) => void;
};

export function TrafficTable({ packets, selectedId, onSelect }: TrafficTableProps) {
  return (
    <div className="traffic-table-wrap">
      <table className="traffic-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th />
            <th>Dest IP</th>
            <th>Ports</th>
            <th>Protocol</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((packet) => {
            const blocked = packet.status === 'Blocked';
            return (
              <tr
                key={packet.id}
                className={cn(packet.id === selectedId && 'traffic-row-selected')}
                onClick={() => onSelect(packet)}
              >
                <td>{packet.timestamp}</td>
                <td className="table-ip strong">{packet.sourceIp}</td>
                <td className="table-arrow-cell">
                  {blocked ? <Ban size={14} className="blocked-icon" /> : <ArrowRight size={14} className="table-arrow" />}
                </td>
                <td className="table-ip strong">{packet.destinationIp}</td>
                <td>
                  {packet.sourcePort} <span className="ports-arrow">→</span> {packet.destinationPort}
                </td>
                <td>
                  <span className={`protocol-pill protocol-${packet.protocol.toLowerCase()}`}>{packet.protocol}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
