# FF Scanner

Anti-cheat screening for Free Fire, PUBG Mobile and COD Mobile tournaments, on PCs, emulators and Android phones.

* `scanner/`: the Windows scanner (`ff_scanner.py`, editable `signatures.json`). See [scanner/README.md](scanner/README.md) for what it checks.
* `public/` and `api/`: the website (FF Scan Desk) for Vercel. Organizers create a session PIN per player, the player runs the scanner with that PIN, and the result appears on the website by itself.

## How it works at the tournament

1. Organizer signs in to the website and creates a session PIN (player name, game, PC or phone).
2. Player downloads `FFScanner.exe` from the website, runs it as administrator and types the PIN.
3. The scanner checks the PC (or phone over USB) and sends the report to the website.
4. Organizer opens the report: Summary, Cheats Found, Key Indications, Suspicious Files, Defender History, Devices Removed, System Information, Alt Accounts.

Each PIN works for one upload within 24 hours. Sessions and reports are kept for 30 days.

## Deploy on Vercel (one time)

1. On vercel.com: **Add New > Project**, import `ff-scanner` from GitHub, framework preset **Other**, then **Deploy**.
2. In the Vercel project: **Storage > Create Database > Upstash for Redis** (free plan), and connect it to this project. It adds the `KV_REST_API_URL` / `KV_REST_API_TOKEN` (or `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`) variables.
3. **Settings > Environment Variables**: add `ADMIN_PASSWORD` with a strong password. This is the organizer sign-in.
4. **Deployments > Redeploy** so the new variables apply.

## Build the scanner exe (GitHub Actions)

1. In GitHub: **Settings > Secrets and variables > Actions > Variables**, add `SCANNER_SERVER_URL` = your site, e.g. `https://ff-scanner.vercel.app`.
2. **Actions > Build scanner > Run workflow**. It builds `FFScanner.exe` on Windows and commits it to `public/`, and Vercel redeploys.
3. The exe is then at `https://<your-site>/FFScanner.exe`. It runs again automatically whenever `scanner/` changes.

Windows Defender sometimes warns about new PyInstaller programs. If it does, check the file on virustotal.com and allow it.

## Limits

This is a screening aid, not proof. Renamed or private hacks, a hack used from another device, or a full Windows reinstall can still get past it. Talk to the player about anything flagged before deciding.
