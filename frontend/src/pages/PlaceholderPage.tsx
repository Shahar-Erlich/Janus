import { SectionCard } from '../components/SectionCard';

export function PlaceholderPage({ title, description }: { title: string; description: string }) {
  return (
    <SectionCard title={title} subtitle="Page scaffold ready for backend integration">
      <div className="placeholder-box">
        <p>{description}</p>
      </div>
    </SectionCard>
  );
}
