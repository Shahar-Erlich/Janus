import { useEffect, useState } from 'react';
import { emptyDashboardViewModel, mapDashboardOverview, type DashboardViewModel } from '../mappers/dashboardMappers';
import { janusClient } from '../services/janusClient';

export function useDashboardOverview(refreshMs = 10000) {
  const [data, setData] = useState<DashboardViewModel>(emptyDashboardViewModel);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const response = await janusClient.getDashboardOverview();
        if (cancelled) return;

        if (!response.dashboardOverview) {
          throw new Error('Dashboard response is missing');
        }

        setData(mapDashboardOverview(response.dashboardOverview));
        setError(null);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load dashboard overview');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void load();
    const intervalId = window.setInterval(() => void load(), refreshMs);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [refreshMs]);

  return { data, loading, error };
}
