# FF Scanner

Anti-cheat screening for Free Fire, PUBG Mobile and COD Mobile tournaments, on PCs, emulators and Android phones.

* `scanner/`: the Windows scanner (`ff_scanner.py`, editable `signatures.json`). See [scanner/README.md](scanner/README.md) for what it checks.
* `public/` and `api/`: the website (FF Scan Desk) for Vercel. Organizers create an account, buy a monthly plan, create a session PIN per player, the player runs the scanner with that PIN, and the result appears on the website by itself.

## Plans

| Plan | Price | Devices scanned per month |
|---|---|---|
| Starter | $9.99 / month | 30 |
| Pro | $20 / month | 100 |

Each session PIN that starts a scan counts as one device. Restarting a stopped scan with the same PIN doesn't count again; deleting a session doesn't give the device back. The count starts again on each renewal date.

Payment runs through [Lemon Squeezy](https://www.lemonsqueezy.com) (merchant of record: it takes the card, handles tax and receipts, and pays out to a Sri Lankan bank account). Its webhook turns the plan on, renews it, and switches it off when it is cancelled and the paid month ends.

How copying and reuse are stopped:

* The scanner exe can't scan without a session PIN, and the website only accepts a PIN from an organizer whose plan is active and has devices left. Copying the exe to someone else gives them nothing.
* Each PIN works for one finished scan within 24 hours, and only the organizer who made it can see its report.
* Plans are checked on the server on every PIN and every scan, so an expired plan stops working right away (3 days of grace if a renewal message from Lemon Squeezy is late).
* Limits: anyone who has the Python source can run it without a PIN. **Keep this GitHub repository private**, and know that a determined cracker can still pull apart any exe. What can't be faked is the website side: the dashboard, live results and stored reports.

## How it works at the tournament

1. Organizer signs in to the website and creates a session PIN (player name, game, PC or phone).
2. Player downloads `FFScanner.exe` from the `/dl/<PIN>` link and opens it. It asks for administrator by itself and fills in the PIN.
3. The scanner checks the PC (or phone over USB) and sends findings to the website live while it runs. If the scan is closed halfway, the session shows STOPPED with what was found until then.
4. Organizer opens the report: Summary, Cheats Found, Key Indications, Suspicious Files, Defender History, Devices Removed, System Information, Alt Accounts.

Each PIN takes one final result within 24 hours. Unfinished earlier scans with the same PIN are kept in the report. Sessions and reports are kept for 30 days.

## Deploy on Vercel (one time)

1. On vercel.com: **Add New > Project**, import `ff-scanner` from GitHub, framework preset **Other**, then **Deploy**.
2. In the Vercel project: **Storage > Create Database > Upstash for Redis** (free plan), and connect it to this project. It adds the `KV_REST_API_URL` / `KV_REST_API_TOKEN` (or `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`) variables.
3. **Settings > Environment Variables**: add `OWNER_EMAILS` with your own email (comma-separated for more). Accounts with these emails scan with no plan and no limit.
4. Set up Lemon Squeezy (below), then **Deployments > Redeploy** so the new variables apply.

## Set up Lemon Squeezy (one time)

1. Sign up at lemonsqueezy.com, create a store and finish the identity and payout (bank) setup.
2. **Products > New product** "FF Scanner", type **Subscription**, with two variants: Starter $9.99 monthly and Pro $20 monthly.
3. Copy each variant's **ID** and its **checkout link** (Share > Checkout URL, looks like `https://<store>.lemonsqueezy.com/buy/<id>`).
4. **Settings > Webhooks > +**: URL `https://<your-site>/api/lemon-webhook`, a signing secret you make up, and the events `subscription_created`, `subscription_updated`, `subscription_cancelled`, `subscription_resumed`, `subscription_expired`, `subscription_paused`, `subscription_unpaused`.
5. **Settings > API > +** to make an API key (used to double-check a subscription when a renewal looks late).
6. In Vercel **Settings > Environment Variables** add:

| Variable | Value |
|---|---|
| `LEMONSQUEEZY_STORE_ID` | the store's number (Settings > Stores) |
| `LEMONSQUEEZY_STARTER_VARIANT` / `LEMONSQUEEZY_PRO_VARIANT` | the two variant IDs |
| `LEMONSQUEEZY_STARTER_URL` / `LEMONSQUEEZY_PRO_URL` | the two checkout links |
| `LEMONSQUEEZY_WEBHOOK_SECRET` | the signing secret from step 4 |
| `LEMONSQUEEZY_API_KEY` | the API key from step 5 |

Use test mode first: buy with a test card, check the plan turns on in the dashboard, then switch the store to live.

## Build the scanner exe (GitHub Actions)

1. In GitHub: **Settings > Secrets and variables > Actions > Variables**, add `SCANNER_SERVER_URL` = your site, e.g. `https://ff-scanner.vercel.app`.
2. **Actions > Build scanner > Run workflow**. It builds `FFScanner.exe` on Windows and commits it to `public/`, and Vercel redeploys.
3. The exe is then at `https://<your-site>/FFScanner.exe`. It runs again automatically whenever `scanner/` changes.

Windows Defender sometimes warns about new PyInstaller programs. If it does, check the file on virustotal.com and allow it.

## Limits

This is a screening aid, not proof. Renamed or private hacks, a hack used from another device, or a full Windows reinstall can still get past it. Talk to the player about anything flagged before deciding.
