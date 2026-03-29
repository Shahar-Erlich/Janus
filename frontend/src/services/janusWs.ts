import {
    FrontendRequest,
    FrontendResponse,
    SubscribeLiveRequest,
    RecentPacketsRequest,
    PacketDetailsRequest,
    DashboardOverviewRequest,
    Ping,
} from "../generated/janus_frontend";

type LivePacketListener = (response: FrontendResponse) => void;

export class JanusWsClient {
    private ws: WebSocket | null = null;
    private pending = new Map<string, {
        resolve: (response: FrontendResponse) => void;
        reject: (error: Error) => void;
    }>();
    private liveListeners = new Set<LivePacketListener>();
    private isConnecting = false;
    private openPromise: Promise<void> | null = null;

    async connect(url: string): Promise<void> {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return;
        }

        if (this.isConnecting && this.openPromise) {
            return this.openPromise;
        }

        this.isConnecting = true;

        this.openPromise = new Promise<void>((resolve, reject) => {
            const ws = new WebSocket(url);
            ws.binaryType = "arraybuffer";

            ws.onopen = () => {
                this.ws = ws;
                this.isConnecting = false;
                resolve();
            };

            ws.onmessage = (event) => {
                try {
                    const bytes = new Uint8Array(event.data as ArrayBuffer);
                    const response = FrontendResponse.decode(bytes);

                    if (response.livePacketEvent) {
                        for (const listener of this.liveListeners) {
                            listener(response);
                        }
                        return;
                    }

                    if (response.requestId && this.pending.has(response.requestId)) {
                        const pending = this.pending.get(response.requestId)!;
                        this.pending.delete(response.requestId);

                        if (!response.ok) {
                            pending.reject(new Error(response.error || "Unknown backend error"));
                            return;
                        }

                        pending.resolve(response);
                    }
                } catch (err) {
                    console.error("Failed to decode frontend response", err);
                }
            };

            ws.onerror = () => {
                this.isConnecting = false;
                reject(new Error("WebSocket connection failed"));
            };

            ws.onclose = () => {
                this.ws = null;
                this.isConnecting = false;

                for (const [, pending] of this.pending) {
                    pending.reject(new Error("WebSocket closed"));
                }
                this.pending.clear();
            };
        });

        return this.openPromise;
    }

    disconnect(): void {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }

    private ensureOpen(): WebSocket {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("WebSocket is not connected");
        }
        return this.ws;
    }

    private nextRequestId(): string {
        return crypto.randomUUID();
    }

    private sendRequest(message: FrontendRequest): Promise<FrontendResponse> {
        const ws = this.ensureOpen();
        const requestId = message.requestId || this.nextRequestId();
        const request = FrontendRequest.create({
            ...message,
            requestId,
        });

        return new Promise<FrontendResponse>((resolve, reject) => {
            this.pending.set(requestId, { resolve, reject });

            try {
                const bytes = FrontendRequest.encode(request).finish();
                ws.send(bytes);
            } catch (err) {
                this.pending.delete(requestId);
                reject(err instanceof Error ? err : new Error("Failed to send request"));
            }
        });
    }

    async ping(message = "ping"): Promise<FrontendResponse> {
        return this.sendRequest(
            FrontendRequest.create({
                ping: Ping.create({ message }),
            }),
        );
    }

    async subscribeLive(enabled: boolean): Promise<FrontendResponse> {
        return this.sendRequest(
            FrontendRequest.create({
                subscribeLive: SubscribeLiveRequest.create({ enabled }),
            }),
        );
    }

    async getRecentPackets(limit: number): Promise<FrontendResponse> {
        return this.sendRequest(
            FrontendRequest.create({
                recentPackets: RecentPacketsRequest.create({ limit }),
            }),
        );
    }

    async getPacketDetails(dbEventId: number): Promise<FrontendResponse> {
        return this.sendRequest(
            FrontendRequest.create({
                packetDetails: PacketDetailsRequest.create({ dbEventId }),
            }),
        );
    }

    async getDashboardOverview(): Promise<FrontendResponse> {
        return this.sendRequest(
            FrontendRequest.create({
                dashboardOverview: DashboardOverviewRequest.create({}),
            }),
        );
    }

    onLivePacket(listener: LivePacketListener): () => void {
        this.liveListeners.add(listener);
        return () => {
            this.liveListeners.delete(listener);
        };
    }
}