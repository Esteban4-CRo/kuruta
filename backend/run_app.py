"""Launch Kuruta as a desktop app (window) or as a headless local service."""

from __future__ import annotations

import logging
import sys
import threading
import time
import webbrowser

import uvicorn

from backend.api.app import app, default_data_directory

HOST = "127.0.0.1"
PORT = 8765


def configure_logging() -> None:
    """Write service logs next to the local database when there is no console."""
    log_dir = default_data_directory()
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(log_dir / "kuruta.log"),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if sys.stderr is not None and getattr(sys.stderr, "isatty", lambda: False)():
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(logging.INFO)
        logging.getLogger().addHandler(console)


def wait_until_up(timeout: float = 8.0) -> None:
    """Poll the local health endpoint until the service accepts connections."""
    import urllib.request

    deadline = time.time() + timeout
    url = f"http://{HOST}:{PORT}/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.4) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Kuruta did not start on {url}")


def run_server() -> None:
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


def open_window(url: str) -> bool:
    """Open a native window when a WebView runtime is available."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("esteban4cro.kuruta.ids.0.2.0")
        except Exception:
            pass

    try:
        import webview
    except Exception:
        return False
    window = webview.create_window(
        "Kuruta · IDS & Packet Sniffer",
        url,
        width=1440,
        height=900,
        min_size=(1050, 680),
        background_color="#000000",
    )
    webview.start(gui="edgechromium" if sys.platform == "win32" else None)
    return window is not None


def main() -> None:
    """Start the local API and present the console as an application window."""
    configure_logging()
    headless = "--headless" in sys.argv
    server = threading.Thread(target=run_server, name="kuruta-http", daemon=True)
    server.start()
    wait_until_up()
    url = f"http://{HOST}:{PORT}/"
    if headless:
        server.join()
        return
    if not open_window(url):
        webbrowser.open(url)
        server.join()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        logging.exception("Kuruta failed to start: %s", error)
        sys.exit(1)
