import { useEffect, useMemo, useState } from 'react';
import { mapLivePacketEvent, mapPacketDetails, mapPacketSummary } from '../mappers/packetMappers';
import { janusClient } from '../services/janusClient';
import type { PacketRecord } from '../types';

export function useSecurityEvents(limit = 100) {
  const [packets, setPackets] = useState<PacketRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const selectedPacket = useMemo(
    () => packets.find((packet) => packet.id === selectedId) ?? packets[0] ?? null,
    [packets, selectedId],
  );

  useEffect(() => {
    let cancelled = false;
    let unsubscribe = () => {};

    const loadRecentPackets = async () => {
      try {
        const response = await janusClient.getRecentPackets(limit);
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
        return next.slice(0, limit);
      });
      setSelectedId((current) => current || livePacket.id);
    });

    return () => {
      cancelled = true;
      unsubscribe();
      void janusClient.subscribeLive(false).catch(() => {});
    };
  }, [limit]);

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

        setPackets((prev) => prev.map((packet) => (packet.id === selectedPacket.id ? enriched : packet)));
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

  return {
    packets,
    selectedId,
    setSelectedId,
    selectedPacket,
    loading,
    error,
  };
}
