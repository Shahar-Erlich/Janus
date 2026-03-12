import { PropsWithChildren } from 'react';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

type AppShellProps = PropsWithChildren<{
  title: string;
}>;

export function AppShell({ children, title }: AppShellProps) {
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-shell">
        <Topbar title={title} />
        <main className="page-content">{children}</main>
      </div>
    </div>
  );
}
