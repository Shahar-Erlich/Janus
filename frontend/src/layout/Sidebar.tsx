import {
  BarChart3,
  Cpu,
  FileText,
  Gauge,
  LayoutDashboard,
  Radio,
  Shield,
  ShieldCheck,
  ShieldBan,
  Waypoints,
} from 'lucide-react';
import { NavLink, useLocation } from 'react-router-dom';
import { NavItem } from '../types';

const navItems: NavItem[] = [
  { label: 'Overview', to: '/overview', icon: LayoutDashboard },
  { label: 'Live Traffic', to: '/live-traffic', icon: Radio },
  { label: 'Events & Logs', to: '/events-logs', icon: FileText },
  { label: 'Rules & Policies', to: '/rules-policies', icon: ShieldCheck },
  { label: 'Blacklist', to: '/blacklist', icon: ShieldBan, },
  { label: 'Reports & Analytics', to: '/reports-analytics', icon: BarChart3, section: 'Analysis' },
  { label: 'System Health', to: '/system-health', icon: Gauge },

];

export function Sidebar() {
  const location = useLocation();
  let currentSection = '';

  return (
    <aside className="sidebar">
      <div className="brand-block">
        <div className="brand-icon">
          <Shield />
        </div>
        <div>
          <div className="brand-title">Janus SOC</div>
          <div className="brand-subtitle">MONITORING FABRIC</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const showSection = item.section && item.section !== currentSection;
          if (item.section) currentSection = item.section;
          const Icon = item.icon;

          return (
            <div key={item.to}>
              {showSection ? <div className="sidebar-section-label">{item.section}</div> : null}
              <NavLink
                to={item.to}
                className={({ isActive }) =>
                  isActive || location.pathname === item.to
                    ? 'sidebar-link sidebar-link-active'
                    : 'sidebar-link'
                }
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </NavLink>
            </div>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="status-dot" />
        <div>
          <div className="footer-label">Node Cluster: Secure</div>
          <div className="footer-subtext">Telemetry linked to Janus handler</div>
        </div>
        <Waypoints size={16} className="footer-icon" />
      </div>
    </aside>
  );
}
