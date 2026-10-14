"""Build a self-contained, platform-native Kuruta ZIP release bundle."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def run(command: list[str]) -> None:
    """Run a build command and fail on any non-zero exit code."""
    subprocess.run(command, cwd=ROOT, check=True)


def build_server() -> Path:
    """Freeze the FastAPI service and its rules into a single-file executable."""
    PyInstaller.__main__.run(
        [
            str(ROOT / "backend" / "run_server.py"),
            "--clean",
            "--noconfirm",
            "--onefile",
            "--name",
            "kuruta-server",
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
            "--distpath",
            str(DIST / "server"),
            "--workpath",
            str(DIST / "pyinstaller-work"),
            "--specpath",
            str(DIST / "spec"),
        ]
    )
    suffix = ".exe" if sys.platform == "win32" else ""
    executable = DIST / "server" / f"kuruta-server{suffix}"
    if not executable.is_file():
        raise FileNotFoundError(f"PyInstaller did not create {executable}")
    return executable


def package(platform_name: str) -> Path:
    """Compile the Rust agent and assemble all files needed to run Kuruta."""
    is_windows = platform_name == "windows"
    agent_name = "kuruta-agent.exe" if is_windows else "kuruta-agent"
    server_name = "kuruta-server.exe" if is_windows else "kuruta-server"
    cargo_target = "x86_64-pc-windows-msvc" if is_windows else "x86_64-unknown-linux-gnu"
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
    server_binary = build_server()
    agent_binary = (
        ROOT
        / "agents"
        / "kuruta-agent"
        / "target"
        / cargo_target
        / "release"
        / agent_name
    )
    if not agent_binary.is_file():
        raise FileNotFoundError(f"Cargo did not create {agent_binary}")

    bundle_name = f"kuruta-{platform_name}-x64"
    staging = DIST / bundle_name
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    shutil.copy2(server_binary, staging / server_name)
    shutil.copy2(agent_binary, staging / agent_name)
    shutil.copy2(ROOT / "README.md", staging / "README.md")
    shutil.copy2(ROOT / "LICENSE", staging / "LICENSE.txt")
    shutil.copy2(ROOT / "assets" / "kuruta-logo.png", staging / "kuruta-logo.png")
    shutil.copy2(ROOT / "packaging" / "README.txt", staging / "README-FIRST.txt")

    if is_windows:
        shutil.copy2(ROOT / "packaging" / "start-kuruta.ps1", staging)
        shutil.copy2(ROOT / "packaging" / "stop-kuruta.ps1", staging)
    else:
        shutil.copy2(ROOT / "packaging" / "start-kuruta.sh", staging)
        (staging / "start-kuruta.sh").chmod(0o755)
        (staging / agent_name).chmod(0o755)
        (staging / server_name).chmod(0o755)

    archive = DIST / f"{bundle_name}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        for file_path in sorted(staging.rglob("*")):
            if file_path.is_file():
                zip_file.write(file_path, file_path.relative_to(DIST))
    return archive


def main() -> None:
    """Build the current native OS bundle or both bundles in native CI jobs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=["windows", "linux"],
        required=True,
        help="Target OS; cross-compilation is intentionally not attempted.",
    )
    args = parser.parse_args()
    archive = package(args.platform)
    print(f"Created release archive: {archive}")


if __name__ == "__main__":
    main()
