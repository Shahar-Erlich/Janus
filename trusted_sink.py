import socket
import threading

HOST = "0.0.0.0"
PORT = 8080

def handle(conn, addr):
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1024)

    print(f"[trusted_sink] listening on {HOST}:{PORT}", flush=True)

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()