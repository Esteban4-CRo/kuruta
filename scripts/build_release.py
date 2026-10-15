"""Build direct, self-contained native executable assets for Kuruta releases."""

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


def build_server(platform_name: str) -> Path:
    """Freeze the FastAPI service and its rules into a native executable."""
    server_stem = f"kuruta-server-{platform_name}-x64"
    DIST.mkdir(parents=True, exist_ok=True)
    icon_path = DIST / "kuruta.ico"
    with Image.open(ROOT / "assets" / "kuruta-logo.png") as logo:
        logo.save(icon_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
    icon_arguments = ["--icon", str(icon_path)] if platform_name == "windows" else []
    PyInstaller.__main__.run(
        [
            str(ROOT / "backend" / "run_server.py"),
            "--clean",
            "--noconfirm",
            "--onefile",
            "--name",
            server_stem,
            "--paths",
            str(ROOT),
            "--add-data",
            f"{ROOT / 'rules'}{os.pathsep}rules",
            "--collect-all",
            "uvicorn",
            "--collect-all",
            "fastapi",
            "--collect-all",
            "pydantic",
            "--collect-all",
            "starlette",
            *icon_arguments,
            "--distpath",
            str(DIST),
            "--workpath",
            str(ROOT / "dist" / "pyinstaller-work"),
            "--specpath",
            str(ROOT / "dist" / "spec"),
        ]
    )
    suffix = ".exe" if sys.platform == "win32" else ""
    executable = DIST / f"{server_stem}{suffix}"
    if not executable.is_file():
        raise FileNotFoundError(f"PyInstaller did not create {executable}")
    return executable


def build_release_assets(platform_name: str) -> list[Path]:
    """Build the backend and agent as two independently downloadable assets."""
    is_windows = platform_name == "windows"
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

    agent_suffix = ".exe" if is_windows else ""
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

    DIST.mkdir(parents=True, exist_ok=True)
    server_source = build_server(platform_name)
    server_asset = DIST / f"kuruta-server-{platform_name}-x64{agent_suffix}"
    agent_asset = DIST / f"kuruta-agent-{platform_name}-x64{agent_suffix}"
    if server_source != server_asset:
        shutil.move(str(server_source), server_asset)
    shutil.copy2(agent_source, agent_asset)

    if not is_windows:
        server_asset.chmod(0o755)
        agent_asset.chmod(0o755)
    return [server_asset, agent_asset]


def main() -> None:
    """Build binaries for the native runner; cross-compilation is not attempted."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=["windows", "linux"],
        required=True,
        help="Target OS; the runner must match the selected platform.",
    )
    args = parser.parse_args()
    if (args.platform == "windows") != (sys.platform == "win32"):
        parser.error("Build each release asset on a native runner for its platform.")
    for asset in build_release_assets(args.platform):
        print(f"Created release executable: {asset}")


if __name__ == "__main__":
    main()
