import { Plus } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { SectionCard } from '../components/SectionCard';
import { formatCompact } from '../utils/janusDerived';

const RULES_API_BASE = `http://${window.location.hostname || 'localhost'}:8000`;

type ManagedRule = {
  id: string;
  desc: string;
  proto?: 'ANY' | 'TCP' | 'UDP';
  action: 'ALLOW' | 'FLAG' | 'BLOCK';
  offset_mode?: 'PAYLOAD' | 'EXACT';
  offset: number;
  length: number;
  value_hex: string;
  regex: string;
  aho_patterns?: string[];
};

type RulesResponse = {
  version: number;
  defaults: {
    max_scan_shift_bytes: number;
  };
  vf_rules: ManagedRule[];
};

type RuleFormState = {
  id: string;
  desc: string;
  offset: string;
  anchor: string;
  aho_patterns: string;
  regex: string;
};

const initialForm: RuleFormState = {
  id: '',
  desc: '',
  offset: '0',
  anchor: '',
  aho_patterns: '',
  regex: '',
};

function hexToAscii(hex: string): string {
  if (!hex || hex.length % 2 !== 0) return '';

  try {
    const chars = hex.match(/.{1,2}/g) ?? [];
    return chars
      .map((byte) => {
        const code = parseInt(byte, 16);
        if (Number.isNaN(code)) return '';
        if (code < 32 || code > 126) return '.';
        return String.fromCharCode(code);
      })
      .join('');
  } catch {
    return '';
  }
}

export function RulesPoliciesPage() {
  const [rules, setRules] = useState<ManagedRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [form, setForm] = useState<RuleFormState>(initialForm);

  const loadRules = async () => {
    try {
      const response = await fetch(`${RULES_API_BASE}/rules`);
      const data: RulesResponse = await response.json();

      if (!response.ok) {
        throw new Error('Failed to load rules');
      }

      setRules(data.vf_rules ?? []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadRules();
  }, []);

  const blockRules = useMemo(() => rules.filter((rule) => rule.action === 'BLOCK').length, [rules]);
  const flagRules = useMemo(() => rules.filter((rule) => rule.action === 'FLAG').length, [rules]);
  const regexRules = useMemo(() => rules.filter((rule) => rule.regex && rule.regex.trim().length > 0).length, [rules]);

  const onChange = <K extends keyof RuleFormState>(key: K, value: RuleFormState[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const submitRule = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      const anchor = form.anchor;

      if (!anchor.trim()) {
        throw new Error('Anchor string is required');
      }

      if (new TextEncoder().encode(anchor).length > 4) {
        throw new Error('Anchor must be 1-4 ASCII characters');
      }

      const response = await fetch(`${RULES_API_BASE}/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: form.id.trim(),
          desc: form.desc.trim(),
          offset: Number(form.offset),
          anchor,
          aho_patterns: form.aho_patterns,
          regex: form.regex.trim(),
        }),
      });

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        throw new Error(data?.detail || 'Failed to create rule');
      }

      setSuccess('Rule added successfully. VF is live; new Aho patterns are active after restarting Janus Core.');
      setForm(initialForm);
      await loadRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create rule');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page-stack">
      <section className="page-hero-row events-hero-row">
        <div>
          <h2 className="page-section-title">Rules & Policies</h2>
          <p className="page-section-subtitle">
            Add Vector Filter anchors, Aho-Corasick signatures, and optional Regex confirmation into the shared rules file.
          </p>
        </div>
      </section>

      {error ? <div className="placeholder-box">{error}</div> : null}
      {success ? <div className="placeholder-box">{success}</div> : null}
      {loading ? <div className="placeholder-box">Loading rules…</div> : null}

      <section className="stats-grid policy-stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Rules</div>
          <div className="stat-value">{formatCompact(rules.length)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Block Rules</div>
          <div className="stat-value">{formatCompact(blockRules)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Flag Rules</div>
          <div className="stat-value">{formatCompact(flagRules)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Regex Rules</div>
          <div className="stat-value">{formatCompact(regexRules)}</div>
        </div>
      </section>

      <section className="policy-layout">
        <SectionCard
          title="Current Rules"
          subtitle="Existing rules from rules.json"
          className="policy-table-card"
        >
          <div className="policy-table-header">
            <span>ID</span>
            <span>Action</span>
            <span>Offset</span>
            <span>Anchor</span>
            <span>Status</span>
          </div>

          <div className="policy-table-body">
            {rules.map((rule, index) => (
              <div key={`${rule.id}-${index}`} className="policy-row">
                <div>
                  <div className="strong">{rule.id}</div>
                  <div className="detail-label">{rule.desc || 'No description'}</div>

                  {rule.aho_patterns && rule.aho_patterns.length > 0 ? (
                    <div className="detail-label">
                      Aho: {rule.aho_patterns.slice(0, 3).join(', ')}
                      {rule.aho_patterns.length > 3 ? ` +${rule.aho_patterns.length - 3} more` : ''}
                    </div>
                  ) : null}

                  {rule.regex && rule.regex.trim().length > 0 ? (
                    <div className="detail-label">
                      Regex: {rule.regex.length > 80 ? `${rule.regex.slice(0, 80)}...` : rule.regex}
                    </div>
                  ) : null}
                </div>

                <div className={`policy-action policy-action-${rule.action.toLowerCase()}`}>{rule.action}</div>

                <div>{rule.offset}</div>

                <div>
                  <div className="strong">{hexToAscii(rule.value_hex) || '-'}</div>
                  <div className="detail-label">
                    len {rule.length} · {rule.value_hex}
                  </div>
                </div>

                <div>
                  <span className="status-pill-inline">Active</span>
                </div>
              </div>
            ))}

            {!loading && rules.length === 0 ? (
              <div className="placeholder-box">No rules found in rules.json.</div>
            ) : null}
          </div>
        </SectionCard>

        <SectionCard
          title="Add New Rule"
          subtitle="Creates a VF anchor with optional Aho-Corasick and Regex confirmation"
          className="rule-editor-card"
        >
          <form className="rule-editor-grid" onSubmit={submitRule}>
            <label className="editor-field">
              <span>Rule ID</span>
              <input
                value={form.id}
                onChange={(event) => onChange('id', event.target.value)}
                placeholder="ENV_DEMO"
                required
              />
            </label>

            <label className="editor-field editor-textarea-field">
              <span>Description</span>
              <textarea
                value={form.desc}
                onChange={(event) => onChange('desc', event.target.value)}
                placeholder="Explain what this rule detects"
              />
            </label>

            <div className="editor-field-row">
              <label className="editor-field">
                <span>Offset</span>
                <input
                  type="number"
                  min={0}
                  value={form.offset}
                  onChange={(event) => onChange('offset', event.target.value)}
                  required
                />
              </label>
            </div>

            <label className="editor-field">
              <span>VF Anchor String (1-4 ASCII chars)</span>
              <input
                value={form.anchor}
                maxLength={4}
                onChange={(event) => onChange('anchor', event.target.value)}
                placeholder="/.en"
                required
              />
            </label>

            <label className="editor-field editor-textarea-field">
              <span>Aho-Corasick Signatures</span>
              <textarea
                value={form.aho_patterns}
                onChange={(event) => onChange('aho_patterns', event.target.value)}
                placeholder={['/.env', 'GET /.env', 'POST /.env'].join('\n')}
              />
            </label>

            <label className="editor-field editor-textarea-field">
              <span>Regex Pattern</span>
              <textarea
                value={form.regex}
                onChange={(event) => onChange('regex', event.target.value)}
                placeholder={'\\/\\.env($|\\?|\\s)'}
              />
            </label>

            <div className="editor-footer-row">
              <button className="primary-button" type="submit" disabled={saving}>
                <Plus size={16} /> {saving ? 'Adding…' : 'Add Rule'}
              </button>
            </div>
          </form>
        </SectionCard>
      </section>
    </div>
  );
}