import { Bell, Clock3, Search, UserCircle2 } from 'lucide-react';

export function Topbar({ title }: { title: string }) {
  return (
    <header className="topbar">
      <div>
        <div className="breadcrumb">Janus Platform · {title}</div>
        <h1 className="page-title">{title}</h1>
      </div>

      <div className="topbar-controls">
        {/* <div className="status-pill">Production (Monitoring)</div>
        <label className="global-search">
          <Search size={16} />
          <input placeholder="Global search..." />
        </label>
        <div className="range-switcher">
          <button className="range-button range-button-active">Last 30m</button>
          <button className="range-button">Last 24h</button>
          <button className="range-button">Custom</button>
        </div>
        <button className="icon-button" aria-label="Notifications">
          <Bell size={18} />
        </button>
        <button className="icon-button" aria-label="Recent activity">
          <Clock3 size={18} />
        </button>
        <div className="user-chip">
          <div>
            <div className="user-name">Alex Chen</div>
            <div className="user-role">Senior Architect</div>
          </div>
          <UserCircle2 size={28} />
        </div> */}
      </div>
    </header>
  );
}
