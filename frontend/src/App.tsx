import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppShell } from './layout/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { LiveTrafficPage } from './pages/LiveTrafficPage';
import { PlaceholderPage } from './pages/PlaceholderPage';

const pageTitleMap: Record<string, string> = {
  '/overview': 'Overview Dashboard',
  '/live-traffic': 'Live Traffic Monitoring',
  '/events-logs': 'Events & Logs',
  '/detection-engines': 'Detection Engines',
  '/rules-policies': 'Rules & Policies',
  '/reports-analytics': 'Reports & Analytics',
  '/system-health': 'System Health',
  '/remote-control': 'Remote Control',
  '/user-management': 'User Management',
  '/network-assets': 'Network Assets',
  '/settings': 'Settings',
};

export default function App() {
  const location = useLocation();
  const title = pageTitleMap[location.pathname] ?? 'Janus Platform';

  return (
    <AppShell title={title}>
      <Routes>
        <Route path="/" element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/live-traffic" element={<LiveTrafficPage />} />
        <Route
          path="/events-logs"
          element={
            <PlaceholderPage
              title="Events & Logs"
              description="Hook this page to your PostgreSQL / protobuf-decoded event pipeline for searchable incident logs, correlation views, and exportable audit trails."
            />
          }
        />
        <Route
          path="/detection-engines"
          element={
            <PlaceholderPage
              title="Detection Engines"
              description="Use this section for SPI, Regex, Aho-Corasick, and SIMD vector filtering engine health, rule counts, latency, and enable/disable controls."
            />
          }
        />
        <Route
          path="/rules-policies"
          element={
            <PlaceholderPage
              title="Rules & Policies"
              description="Add policy management, whitelist/blacklist editors, regex rules, ICD-driven signature profiles, and rollout history here."
            />
          }
        />
        <Route
          path="/reports-analytics"
          element={
            <PlaceholderPage
              title="Reports & Analytics"
              description="This page is ready for KPI reports, protocol heatmaps, packet anomaly trends, incident summaries, and compliance-oriented exports."
            />
          }
        />
        <Route
          path="/system-health"
          element={
            <PlaceholderPage
              title="System Health"
              description="Use this area for host health, container states, queue depth, throughput, capture rate, database status, and backpressure indicators."
            />
          }
        />
        <Route
          path="/remote-control"
          element={
            <PlaceholderPage
              title="Remote Control"
              description="Attach safe operator actions here such as engine toggles, emergency blocks, runtime policy swaps, and incident playbooks."
            />
          }
        />
        <Route
          path="/user-management"
          element={
            <PlaceholderPage
              title="User Management"
              description="This page can contain role-based access control, operator accounts, audit history, and SOC team permissions."
            />
          }
        />
        <Route
          path="/network-assets"
          element={
            <PlaceholderPage
              title="Network Assets"
              description="Use this page for trusted/untrusted nodes, IP inventory, network groups, VLANs, capture points, and topology views."
            />
          }
        />
        <Route
          path="/settings"
          element={
            <PlaceholderPage
              title="Settings"
              description="Put global thresholds, retention settings, ingestion adapters, protobuf endpoints, and UI preferences here."
            />
          }
        />
      </Routes>
    </AppShell>
  );
}
