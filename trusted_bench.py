import asyncio
import os

HOST = "0.0.0.0"
PORT_BASE = int(os.getenv("PORT_BASE", "8080"))
PORT_COUNT = int(os.getenv("PORT_COUNT", "16"))
READ_CHUNK = int(os.getenv("READ_CHUNK", "65536"))


class DrainUdp(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        pass


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(READ_CHUNK)
            if not data:
                break
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    loop = asyncio.get_running_loop()
    tcp_servers = []
    udp_transports = []

    for port in range(PORT_BASE, PORT_BASE + PORT_COUNT):
        tcp_server = await asyncio.start_server(
            handle_tcp,
            host=HOST,
            port=port,
            backlog=4096,
            reuse_address=True,
        )
        tcp_servers.append(tcp_server)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: DrainUdp(),
            local_addr=(HOST, port),
        )
        udp_transports.append(transport)

    print(
        f"[trusted_bench] listening TCP+UDP on {HOST} ports {PORT_BASE}-{PORT_BASE + PORT_COUNT - 1}",
        flush=True,
    )

    try:
        await asyncio.gather(*(s.serve_forever() for s in tcp_servers))
    finally:
        for t in udp_transports:
            t.close()
        for s in tcp_servers:
            s.close()
            await s.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())