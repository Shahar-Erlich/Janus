import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppShell } from './layout/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { LiveTrafficPage } from './pages/LiveTrafficPage';
import { EventsLogsPage } from './pages/EventsLogsPage';
import { DetectionEnginesPage } from './pages/DetectionEnginesPage';
import { RulesPoliciesPage } from './pages/RulesPoliciesPage';
import { ReportsAnalyticsPage } from './pages/ReportsAnalyticsPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { PlaceholderPage } from './pages/PlaceholderPage';
import { useEffect } from 'react';
import { janusClient } from './services/janusClient';

const pageTitleMap: Record<string, string> = {
  '/overview': 'Overview Dashboard',
  '/live-traffic': 'Live Traffic Monitoring',
  '/events-logs': 'Events & Logs',
  '/detection-engines': 'Detection Engines',
  '/rules-policies': 'Rules & Policies',
  '/reports-analytics': 'Reports & Analytics',
  '/system-health': 'System Health',
  // '/remote-control': 'Remote Control',
  // '/settings': 'Settings',
};

export default function App() {
  useEffect(() => {
    janusClient.connect('ws://localhost:8000/ws').catch((err) => {
      console.error('Failed to connect to Janus handler', err);
    });

    return () => {
      janusClient.disconnect();
    };
  }, []);

  const location = useLocation();
  const title = pageTitleMap[location.pathname] ?? 'Janus Platform';

  return (
    <AppShell title={title}>
      <Routes>
        <Route path="/" element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/live-traffic" element={<LiveTrafficPage />} />
        <Route path="/events-logs" element={<EventsLogsPage />} />
        {/* <Route path="/detection-engines" element={<DetectionEnginesPage />} /> */}
        <Route path="/rules-policies" element={<RulesPoliciesPage />} />
        <Route path="/reports-analytics" element={<ReportsAnalyticsPage />} />
        <Route path="/system-health" element={<SystemHealthPage />} />
        {/* <Route
          path="/remote-control"
          element={
            <PlaceholderPage
              title="Remote Control"
              description="This backend currently exposes monitoring protobufs, not control actions. Keep this page as the place for future safe engine toggles, emergency blocks, and runtime policy swaps."
            />
          }
        />
        <Route
          path="/settings"
          element={
            <PlaceholderPage
              title="Settings"
              description="This backend currently exposes monitoring protobufs, not persisted UI or platform settings. Keep this page for thresholds, retention, and endpoint preferences later."
            />
          }
        /> */}
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </AppShell>
  );
}
