Kuruta local release bundle

Windows:
  1. Extract the complete ZIP to a folder you control.
  2. Open PowerShell in that folder.
  3. Run: .\start-kuruta.ps1
  4. Open: http://127.0.0.1:8765/docs
  5. Stop with: .\stop-kuruta.ps1

Linux:
  1. Extract the complete archive to a folder you control.
  2. From that folder run: chmod +x kuruta-agent kuruta-server start-kuruta.sh
  3. Start with: ./start-kuruta.sh
  4. Open: http://127.0.0.1:8765/docs
  5. Stop with Ctrl+C in that terminal.

Kuruta listens only on this computer. The agent observes process starts and
stores events and alerts locally. It does not capture all LAN traffic.

Windows data/logs: %LOCALAPPDATA%\Kuruta
Linux data/logs:   $XDG_DATA_HOME/kuruta or ~/.local/share/kuruta

Read README.md and LICENSE.txt for usage, limits, and license terms.
