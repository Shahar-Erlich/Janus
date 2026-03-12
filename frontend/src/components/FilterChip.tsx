import { ChevronDown } from 'lucide-react';

export function FilterChip({ label }: { label: string }) {
  return (
    <button className="filter-chip">
      <span>{label}</span>
      <ChevronDown size={14} />
    </button>
  );
}
