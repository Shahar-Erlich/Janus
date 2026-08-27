import { Plus, RefreshCw, ShieldBan, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { SectionCard } from '../components/SectionCard';

const API_BASE = `http://${window.location.hostname || 'localhost'}:8000`;

type BlacklistResponse = {
    path: string;
    count: number;
    addresses: string[];
    raw: string;
};

function formatCompact(value: number): string {
    if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
    if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
    return String(value);
}

export function BlacklistPage() {
    const [addresses, setAddresses] = useState<string[]>([]);
    const [rawText, setRawText] = useState('');
    const [path, setPath] = useState('/blacklists/blacklist file');
    const [newAddress, setNewAddress] = useState('');
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    const loadBlacklist = async () => {
        setLoading(true);

        try {
            const response = await fetch(`${API_BASE}/blacklist`);
            const data: BlacklistResponse = await response.json();

            if (!response.ok) {
                throw new Error('Failed to load blacklist file');
            }

            setAddresses(data.addresses ?? []);
            setRawText(data.raw ?? '');
            setPath(data.path ?? '/blacklists/blacklist file');
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load blacklist file');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        void loadBlacklist();
    }, []);

    const uniqueCount = useMemo(() => new Set(addresses).size, [addresses]);

    const addAddress = async (event: React.FormEvent) => {
        event.preventDefault();

        if (!newAddress.trim()) return;

        setSaving(true);
        setError(null);
        setSuccess(null);

        try {
            const response = await fetch(`${API_BASE}/blacklist`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ address: newAddress.trim() }),
            });

            const data = await response.json().catch(() => null);

            if (!response.ok) {
                throw new Error(data?.detail || 'Failed to add address');
            }

            setSuccess(`${data.address} added to blacklist file`);
            setNewAddress('');
            await loadBlacklist();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to add address');
        } finally {
            setSaving(false);
        }
    };

    const deleteAddress = async (address: string) => {
        setSaving(true);
        setError(null);
        setSuccess(null);

        try {
            const response = await fetch(`${API_BASE}/blacklist/${encodeURIComponent(address)}`, {
                method: 'DELETE',
            });

            const data = await response.json().catch(() => null);

            if (!response.ok) {
                throw new Error(data?.detail || 'Failed to delete address');
            }

            setSuccess(`${address} removed from blacklist file`);
            await loadBlacklist();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to delete address');
        } finally {
            setSaving(false);
        }
    };

    return (
        <div className="page-stack">
            <section className="page-hero-row events-hero-row">
                <div>
                    <h2 className="page-section-title">Blacklist Management</h2>
                    <p className="page-section-subtitle">
                        View and edit the mounted blacklist file file used by Janus SPI filtering.
                    </p>
                </div>

                <button className="secondary-button" type="button" onClick={loadBlacklist} disabled={loading}>
                    <RefreshCw size={16} /> Refresh
                </button>
            </section>

            {error ? <div className="placeholder-box">{error}</div> : null}
            {success ? <div className="placeholder-box">{success}</div> : null}
            {loading ? <div className="placeholder-box">Loading blacklist file…</div> : null}

            <section className="stats-grid policy-stats-grid">
                <div className="stat-card">
                    <div className="stat-label">Blocked Addresses</div>
                    <div className="stat-value">{formatCompact(addresses.length)}</div>
                </div>

                <div className="stat-card">
                    <div className="stat-label">Unique Entries</div>
                    <div className="stat-value">{formatCompact(uniqueCount)}</div>
                </div>

                <div className="stat-card">
                    <div className="stat-label">File Status</div>
                    <div className="stat-value">Mounted</div>
                </div>

                <div className="stat-card">
                    <div className="stat-label">Policy Layer</div>
                    <div className="stat-value">SPI</div>
                </div>
            </section>

            <section className="policy-layout">
                <SectionCard title="Current blacklist file" subtitle={path} className="policy-table-card">
                    <div className="policy-table-header blacklist-table-header">
                        <span>Address</span>
                        <span>Status</span>
                        <span>Action</span>
                    </div>

                    <div className="policy-table-body">
                        {addresses.map((address) => (
                            <div key={address} className="policy-row blacklist-table-row">
                                <div>
                                    <div className="strong">{address}</div>
                                    <div className="detail-label">Source IP block rule</div>
                                </div>

                                <div>
                                    <span className="status-pill-inline">
                                        <ShieldBan size={13} /> Blocked
                                    </span>
                                </div>

                                <div>
                                    <button
                                        className="reset-link-button"
                                        type="button"
                                        disabled={saving}
                                        onClick={() => void deleteAddress(address)}
                                    >
                                        <Trash2 size={14} /> Delete
                                    </button>
                                </div>
                            </div>
                        ))}

                        {!loading && addresses.length === 0 ? (
                            <div className="placeholder-box">blacklist file is empty.</div>
                        ) : null}
                    </div>
                </SectionCard>

                <SectionCard
                    title="Edit Blacklist"
                    subtitle="Adds or removes addresses from the shared mounted file"
                    className="rule-editor-card"
                >
                    <form className="rule-editor-grid" onSubmit={addAddress}>
                        <label className="editor-field">
                            <span>IP Address</span>
                            <input
                                value={newAddress}
                                onChange={(event) => setNewAddress(event.target.value)}
                                placeholder="192.168.0.12"
                                required
                            />
                        </label>

                        <div className="editor-footer-row">
                            <button className="primary-button" type="submit" disabled={saving}>
                                <Plus size={16} /> {saving ? 'Adding…' : 'Add Address'}
                            </button>
                        </div>
                    </form>

                    <div className="blacklist-preview-block">
                        <div className="detail-label">Raw blacklist file preview</div>

                        <textarea
                            className="blacklist-raw-textarea"
                            value={rawText || '# empty blacklist file'}
                            readOnly
                        />
                    </div>
                </SectionCard>
            </section>
        </div>
    );
}