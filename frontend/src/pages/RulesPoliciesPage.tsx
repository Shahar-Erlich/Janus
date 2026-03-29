import { Plus } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { SectionCard } from '../components/SectionCard';
import { formatCompact } from '../utils/janusDerived';

const RULES_API_BASE = `http://${window.location.hostname || 'localhost'}:8000`;

type ManagedRule = {
  id: string;
  desc: string;
  proto: 'ANY' | 'TCP' | 'UDP';
  action: 'ALLOW' | 'FLAG' | 'BLOCK';
  offset_mode: 'PAYLOAD' | 'EXACT';
  offset: number;
  length: number;
  value_hex: string;
  regex: string;
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
  proto: 'ANY' | 'TCP' | 'UDP';
  action: 'ALLOW' | 'FLAG' | 'BLOCK';
  offset_mode: 'PAYLOAD' | 'EXACT';
  offset: string;
  length: string;
  value_hex: string;
  regex: string;
};

const initialForm: RuleFormState = {
  id: '',
  desc: '',
  proto: 'ANY',
  action: 'FLAG',
  offset_mode: 'PAYLOAD',
  offset: '0',
  length: '4',
  value_hex: '',
  regex: '',
};

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
  const exactRules = useMemo(() => rules.filter((rule) => rule.offset_mode === 'EXACT').length, [rules]);

  const onChange = <K extends keyof RuleFormState>(key: K, value: RuleFormState[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const submitRule = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await fetch(`${RULES_API_BASE}/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: form.id.trim(),
          desc: form.desc.trim(),
          proto: form.proto,
          action: form.action,
          offset_mode: form.offset_mode,
          offset: Number(form.offset),
          length: Number(form.length),
          value_hex: form.value_hex.trim(),
          regex: form.regex.trim(),
        }),
      });

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        throw new Error(data?.detail || 'Failed to create rule');
      }

      setSuccess('Rule added successfully. Janus will reload it on the next packet.');
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
          <p className="page-section-subtitle">Add new Vector Filter rules directly into the shared ICD file.</p>
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
          <div className="stat-label">Exact Offset Rules</div>
          <div className="stat-value">{formatCompact(exactRules)}</div>
        </div>
      </section>

      <section className="policy-layout">
        <SectionCard
          title="Current Rules"
          subtitle="Existing rules from icd.json"
          className="policy-table-card"
        >
          <div className="policy-table-header">
            <span>ID</span>
            <span>Protocol</span>
            <span>Action</span>
            <span>Offset</span>
            <span>Length</span>
            <span>Status</span>
          </div>

          <div className="policy-table-body">
            {rules.map((rule, index) => (
              <div key={`${rule.id}-${index}`} className="policy-row">
                <div>
                  <div className="strong">{rule.id}</div>
                  <div className="detail-label">{rule.desc || 'No description'}</div>
                </div>
                <div>{rule.proto}</div>
                <div className={`policy-action policy-action-${rule.action.toLowerCase()}`}>{rule.action}</div>
                <div>
                  {rule.offset_mode}:{rule.offset}
                </div>
                <div>{rule.length}</div>
                <div>
                  <span className="status-pill-inline">Active</span>
                </div>
              </div>
            ))}

            {!loading && rules.length === 0 ? (
              <div className="placeholder-box">No rules found in icd.json.</div>
            ) : null}
          </div>
        </SectionCard>

        <SectionCard
          title="Add New Rule"
          subtitle="Creates a new VF rule and writes it to icd.json"
          className="rule-editor-card"
        >
          <form className="rule-editor-grid" onSubmit={submitRule}>
            <label className="editor-field">
              <span>Rule ID</span>
              <input
                value={form.id}
                onChange={(event) => onChange('id', event.target.value)}
                placeholder="SQLI_CUSTOM"
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
                <span>Protocol</span>
                <select value={form.proto} onChange={(event) => onChange('proto', event.target.value as RuleFormState['proto'])}>
                  <option value="ANY">ANY</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                </select>
              </label>

              <label className="editor-field">
                <span>Action</span>
                <select value={form.action} onChange={(event) => onChange('action', event.target.value as RuleFormState['action'])}>
                  <option value="ALLOW">ALLOW</option>
                  <option value="FLAG">FLAG</option>
                  <option value="BLOCK">BLOCK</option>
                </select>
              </label>
            </div>

            <div className="editor-field-row">
              <label className="editor-field">
                <span>Offset Mode</span>
                <select
                  value={form.offset_mode}
                  onChange={(event) => onChange('offset_mode', event.target.value as RuleFormState['offset_mode'])}
                >
                  <option value="PAYLOAD">PAYLOAD</option>
                  <option value="EXACT">EXACT</option>
                </select>
              </label>

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

            <div className="editor-field-row">
              <label className="editor-field">
                <span>Length (1-4)</span>
                <input
                  type="number"
                  min={1}
                  max={4}
                  value={form.length}
                  onChange={(event) => onChange('length', event.target.value)}
                  required
                />
              </label>

              <label className="editor-field">
                <span>Value Hex</span>
                <input
                  value={form.value_hex}
                  onChange={(event) => onChange('value_hex', event.target.value.toUpperCase())}
                  placeholder="2F2E656E"
                  required
                />
              </label>
            </div>

            <label className="editor-field editor-textarea-field">
              <span>Regex (optional)</span>
              <textarea
                value={form.regex}
                onChange={(event) => onChange('regex', event.target.value)}
                placeholder="(?i)union\\s+select"
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