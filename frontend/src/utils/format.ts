export function cn(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(' ');
}

export function formatDeltaToneClass(
  tone: 'positive' | 'negative' | 'warning' | 'neutral' = 'neutral',
) {
  switch (tone) {
    case 'positive':
      return 'tone-positive';
    case 'negative':
      return 'tone-negative';
    case 'warning':
      return 'tone-warning';
    default:
      return 'tone-neutral';
  }
}

export function severityToClass(severity: 'Low' | 'Medium' | 'High' | 'Critical') {
  switch (severity) {
    case 'Low':
      return 'badge-success';
    case 'Medium':
      return 'badge-warning';
    case 'High':
      return 'badge-danger';
    case 'Critical':
      return 'badge-critical';
  }
}
