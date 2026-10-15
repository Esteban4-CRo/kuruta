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
    """Return the official Windows .ico path, creating it from the logo if missing."""
    icon_path = ROOT / "assets" / "kuruta-logo.ico"
    if not icon_path.is_file():
        with Image.open(ROOT / "assets" / "kuruta-logo.png") as logo:
            logo.save(
                icon_path,
                format="ICO",
                sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
            )
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

    # Package distribution installers
    if is_windows:
        iscc = shutil.which("iscc") or r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
        iss_path = ROOT / "packaging" / "windows" / "kuruta_setup.iss"
        if Path(iscc).is_file() and iss_path.is_file():
            print("Compiling Windows Inno Setup installer...")
            run([str(iscc), str(iss_path)])
            installer_exe = DIST / "Kuruta-Setup-windows-x64.exe"
            if installer_exe.is_file():
                assets.append(installer_exe)
    else:
        # Build universal Linux tar.gz bundle with install.sh, desktop file, icon and binary
        import tarfile
        tar_asset = DIST / "kuruta-linux-x64.tar.gz"
        staging = ROOT / "dist" / "kuruta-bundle"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        shutil.copy2(app_asset, staging / "kuruta-linux-x64")
        shutil.copy2(ROOT / "packaging" / "linux" / "install.sh", staging / "install.sh")
        shutil.copy2(ROOT / "packaging" / "linux" / "kuruta.desktop", staging / "kuruta.desktop")
        shutil.copy2(ROOT / "assets" / "kuruta-logo.png", staging / "kuruta-logo.png")
        shutil.copy2(ROOT / "README.md", staging / "README.md")
        (staging / "install.sh").chmod(0o755)
        (staging / "kuruta-linux-x64").chmod(0o755)
        
        with tarfile.open(tar_asset, "w:gz") as tar:
            tar.add(staging, arcname="kuruta-linux-x64")
        assets.append(tar_asset)

        # Build .deb package if dpkg-deb is available
        deb_script = ROOT / "packaging" / "linux" / "build_deb.sh"
        if shutil.which("dpkg-deb") and deb_script.is_file():
            print("Building Debian/Ubuntu .deb package...")
            run(["bash", str(deb_script)])
            deb_pkg = DIST / "kuruta-linux-x64.deb"
            if deb_pkg.is_file():
                assets.append(deb_pkg)

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
