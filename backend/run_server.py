"""Launch the local Kuruta API when used as a normal script or frozen binary."""

from __future__ import annotations

import uvicorn

from backend.api.app import app


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
