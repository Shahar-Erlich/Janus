import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppShell } from './layout/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { LiveTrafficPage } from './pages/LiveTrafficPage';
import { EventsLogsPage } from './pages/EventsLogsPage';
import { RulesPoliciesPage } from './pages/RulesPoliciesPage';
import { ReportsAnalyticsPage } from './pages/ReportsAnalyticsPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { useEffect } from 'react';
import { janusClient } from './services/janusClient';
import { BlacklistPage } from './pages/BlacklistPage';
const pageTitleMap: Record<string, string> = {
  '/overview': 'Overview Dashboard',
  '/live-traffic': 'Live Traffic Monitoring',
  '/events-logs': 'Events & Logs',
  '/detection-engines': 'Detection Engines',
  '/rules-policies': 'Rules & Policies',
  '/reports-analytics': 'Reports & Analytics',
  '/system-health': 'System Health',
  '/blacklist': 'Blacklist Management',

};

export default function App() {
  useEffect(() => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';

    janusClient.connect(`${wsProtocol}://${window.location.hostname || 'localhost'}:8000/ws`).catch((err) => {
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
        <Route path="/rules-policies" element={<RulesPoliciesPage />} />
        <Route path="/blacklist" element={<BlacklistPage />} />
        <Route path="/reports-analytics" element={<ReportsAnalyticsPage />} />
        <Route path="/system-health" element={<SystemHealthPage />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </AppShell>
  );
}
