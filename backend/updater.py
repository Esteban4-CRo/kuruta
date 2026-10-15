"""Auto-update checker: compares local version with GitHub Releases API."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

GITHUB_REPO = "Esteban4-CRo/kuruta"
CURRENT_VERSION = "0.3.0"

# Map (platform, arch) -> asset name suffix used in GitHub release
_PLATFORM_ASSET: dict[str, str] = {
    "windows": "kuruta-windows-x64.exe",
    "linux": "kuruta-linux-x64",
}


@dataclass
class UpdateInfo:
    current: str
    latest: str
    has_update: bool
    release_notes: str
    download_url: str
    tag: str


def _platform() -> str:
    return "windows" if os.name == "nt" else "linux"


def _version_tuple(version: str) -> tuple[int, ...]:
    """Convert '1.2.3' -> (1, 2, 3) for comparison."""
    try:
        return tuple(int(x) for x in version.lstrip("v").split("."))
    except ValueError:
        return (0,)


def check_for_update(timeout: float = 8.0) -> UpdateInfo:
    """Poll the GitHub Releases API and return update information."""
    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    req = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"Kuruta-IDS/{CURRENT_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            import json
            data: dict = json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, Exception):
        return UpdateInfo(
            current=CURRENT_VERSION,
            latest=CURRENT_VERSION,
            has_update=False,
            release_notes="",
            download_url="",
            tag="",
        )

    tag: str = data.get("tag_name", "")
    latest = tag.lstrip("v")
    release_notes: str = data.get("body", "")[:1200]

    # Find the matching asset for this platform
    asset_name = _PLATFORM_ASSET.get(_platform(), "")
    download_url = ""
    for asset in data.get("assets", []):
        if asset.get("name", "") == asset_name:
            download_url = asset.get("browser_download_url", "")
            break

    # Fallback: GitHub release page
    if not download_url:
        download_url = data.get("html_url", f"https://github.com/{GITHUB_REPO}/releases/latest")

    has_update = bool(
        latest
        and _version_tuple(latest) > _version_tuple(CURRENT_VERSION)
    )

    return UpdateInfo(
        current=CURRENT_VERSION,
        latest=latest,
        has_update=has_update,
        release_notes=release_notes,
        download_url=download_url,
        tag=tag,
    )


def _download_and_replace(download_url: str) -> None:
    """Download the new binary to a temp file, then replace the running exe."""
    if _platform() != "windows":
        # On Linux, just open the browser to the releases page
        import webbrowser
        webbrowser.open(f"https://github.com/{GITHUB_REPO}/releases/latest")
        return

    exe_path = Path(sys.executable)
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".exe", dir=exe_path.parent)
    os.close(tmp_fd)
    tmp = Path(tmp_path)

    try:
        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": f"Kuruta-IDS/{CURRENT_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            with open(tmp, "wb") as f:
                while chunk := resp.read(65536):
                    f.write(chunk)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"Descarga fallida: {exc}") from exc

    # Rename: current → .old, new → current, then relaunch
    old_path = exe_path.with_suffix(".old.exe")
    old_path.unlink(missing_ok=True)

    # Use a helper batch script so we can rename the running exe
    bat = exe_path.parent / "_kuruta_update.bat"
    bat.write_text(
        f'@echo off\n'
        f'timeout /t 2 /nobreak >nul\n'
        f'move /y "{exe_path}" "{old_path}"\n'
        f'move /y "{tmp}" "{exe_path}"\n'
        f'start "" "{exe_path}"\n'
        f'del "%~f0"\n',
        encoding="ascii",
    )
    subprocess.Popen(
        ["cmd.exe", "/c", str(bat)],
        creationflags=0x00000008,  # DETACHED_PROCESS
        close_fds=True,
    )
    # Gracefully exit so the bat can replace us
    sys.exit(0)


def apply_update_async(download_url: str, on_done=None, on_error=None) -> None:
    """Download and apply update in a background thread (non-blocking)."""
    def _run():
        try:
            _download_and_replace(download_url)
            if on_done:
                on_done()
        except Exception as exc:
            if on_error:
                on_error(str(exc))
    threading.Thread(target=_run, daemon=True).start()
