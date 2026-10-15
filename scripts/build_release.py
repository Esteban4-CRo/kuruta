"""Build self-contained native application assets for Kuruta releases."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

import PyInstaller.__main__
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "release"


def run(command: list[str]) -> None:
    """Run a build command and fail on any non-zero exit code."""
    subprocess.run(command, cwd=ROOT, check=True)


def application_icon() -> Path:
    """Rasterize the official logo into a Windows .ico for the frozen app."""
    DIST.mkdir(parents=True, exist_ok=True)
    icon_path = DIST / "kuruta.ico"
    with Image.open(ROOT / "assets" / "kuruta-logo.png") as logo:
        logo.save(icon_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
    return icon_path


def build_app(platform_name: str) -> Path:
    """Freeze the desktop console, sniffer API, rules, UI, and logo."""
    app_stem = f"kuruta-{platform_name}-x64"
    icon_path = application_icon()
    icon_arguments = ["--icon", str(icon_path)] if platform_name == "windows" else []
    windowed = ["--windowed"] if platform_name == "windows" else []
    PyInstaller.__main__.run(
        [
            str(ROOT / "backend" / "run_app.py"),
            "--clean",
            "--noconfirm",
            "--onefile",
            "--name",
            app_stem,
            "--paths",
            str(ROOT),
            "--add-data",
            f"{ROOT / 'rules'}{os.pathsep}rules",
            "--add-data",
            f"{ROOT / 'frontend'}{os.pathsep}frontend",
            "--add-data",
            f"{ROOT / 'assets'}{os.pathsep}assets",
            "--collect-all",
            "uvicorn",
            "--collect-all",
            "fastapi",
            "--collect-all",
            "pydantic",
            "--collect-all",
            "starlette",
            "--collect-all",
            "scapy",
            "--hidden-import",
            "webview",
            "--hidden-import",
            "backend.sniffer.decode",
            "--hidden-import",
            "backend.sniffer.capture",
            *icon_arguments,
            *windowed,
            "--distpath",
            str(DIST),
            "--workpath",
            str(ROOT / "dist" / "pyinstaller-work"),
            "--specpath",
            str(ROOT / "dist" / "spec"),
        ]
    )
    suffix = ".exe" if sys.platform == "win32" else ""
    executable = DIST / f"{app_stem}{suffix}"
    if not executable.is_file():
        raise FileNotFoundError(f"PyInstaller did not create {executable}")
    return executable


def build_release_assets(platform_name: str, build_agent: bool = True) -> list[Path]:
    """Build the desktop app and host agent as independently downloadable files."""
    is_windows = platform_name == "windows"
    agent_suffix = ".exe" if is_windows else ""
    DIST.mkdir(parents=True, exist_ok=True)
    
    app_source = build_app(platform_name)
    app_asset = DIST / f"kuruta-{platform_name}-x64{agent_suffix}"
    if app_source != app_asset:
        shutil.move(str(app_source), app_asset)

    if not is_windows:
        app_asset.chmod(0o755)

    assets = [app_asset]

    if build_agent:
        cargo_target = (
            "x86_64-pc-windows-msvc"
            if is_windows
            else "x86_64-unknown-linux-gnu"
        )
        run(
            [
                "cargo",
                "build",
                "--release",
                "--target",
                cargo_target,
                "--manifest-path",
                str(ROOT / "agents" / "kuruta-agent" / "Cargo.toml"),
            ]
        )

        agent_source = (
            ROOT
            / "agents"
            / "kuruta-agent"
            / "target"
            / cargo_target
            / "release"
            / f"kuruta-agent{agent_suffix}"
        )
        if not agent_source.is_file():
            raise FileNotFoundError(f"Cargo did not create {agent_source}")

        agent_asset = DIST / f"kuruta-agent-{platform_name}-x64{agent_suffix}"
        shutil.copy2(agent_source, agent_asset)
        if not is_windows:
            agent_asset.chmod(0o755)
        assets.append(agent_asset)

    return assets


def main() -> None:
    """Build binaries for the native runner; cross-compilation is not attempted."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=["windows", "linux"],
        required=True,
        help="Target OS; the runner must match the selected platform.",
    )
    parser.add_argument(
        "--skip-agent",
        action="store_true",
        help="Build only the desktop application, skipping the Rust host agent.",
    )
    args = parser.parse_args()
    if (args.platform == "windows") != (sys.platform == "win32"):
        parser.error("Build each release asset on a native runner for its platform.")
    for asset in build_release_assets(args.platform, build_agent=not args.skip_agent):
        print(f"Created release executable: {asset}")


if __name__ == "__main__":
    main()
