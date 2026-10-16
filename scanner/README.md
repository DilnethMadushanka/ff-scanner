# FF Scanner (emulator cheat screening for Free Fire, PUBG Mobile and COD Mobile)

A small, portable Windows program you run on a player's PC (with their knowledge) before a match.
It only **reads**. It does not delete, change, or upload anything.

## The scanner window (v3.2)

FFScanner.exe opens a window instead of a black command box: the session PIN (filled in automatically when downloaded from the website's /dl/<PIN> link), game, what to check, player name and a deep-scan option, then a Start button, a progress bar and a colored result with the top findings, "Sent to the organizer", and Open full report.
The text version is still there for testing: `python ff_scanner.py --cli`.

## Live updates and admin prompt (v3.3)

- With a session PIN, the scanner sends what it has found so far to the website every few seconds. The organizer sees a LIVE badge with the current step. If the player closes the scanner or the PC loses contact, the session shows STOPPED with everything found up to that point.
- If the same PIN is scanned again after a stopped scan, the earlier unfinished scan is kept and shown in the report, so stopping and restarting can't hide anything.
- The exe asks for administrator by itself. If Windows doesn't show the prompt, it restarts itself with "Run as administrator". If the player says No, it scans without admin and the report says so.
- The deep emulator-disk step shows a percentage, because a 30 GB disk can take several minutes.

## Website (online sessions)

When `server_url` in `signatures.json` is set (the GitHub Action does this), the scanner asks for the **session PIN** the organizer created on the website. It then uses that session's game, player and check type, and sends the report to the website when it finishes. The built exe needs a PIN from an organizer with an active plan; before scanning it tells the website, which counts one device on that plan and refuses when the plan has expired or run out. Only when running from the Python source can you press Enter (or pass `--offline`) to scan without a PIN.
Options: `--pin 12345678`, `--server https://your-site`, `--offline` (source only).

## Checking Android phones (mobile players)

1. Download Google's **SDK Platform-Tools for Windows** from https://developer.android.com/tools/releases/platform-tools and copy `adb.exe`, `AdbWinApi.dll` and `AdbWinUsbApi.dll` next to `FFScanner.exe`.
2. On the phone: Settings > About phone > tap **Build number** 7 times, then Settings > Developer options > turn on **USB debugging**.
3. Plug the phone into the PC, run the scanner and pick **2. An Android phone** (or `--mode phone`). Tap **Allow** on the phone.

It checks installed cheat apps, the game's installer (not from Play Store = possible mod), apps used or uninstalled before, root/Magisk, unlocked bootloader, custom ROM, hack files in Download/obb, files in `/data/local/tmp`, cheat processes like frida-server, and Google accounts (alt accounts).
iPhones cannot be checked: iOS does not let a PC list apps or files. Turn USB debugging off again after the check.

## How a scan works (v2)

1. Run `FFScanner.exe`. Pick the game: **1** Free Fire / FF MAX, **2** PUBG Mobile / BGMI, **3** COD Mobile, **4** All games.
2. Type the player's name or in-game ID (optional).
3. The scanner shows an 8-digit **Session PIN**. Write it next to the player's name; the report file is named with the PIN and player.
4. The report opens in the browser, with a sidebar like detect.ac:
   * **Summary**: result, counts and past-use timeline
   * **Cheats Found**: every HIGH item
   * **Key Indications**: running programs, run history, browser history, emulator apps
   * **Suspicious Files**: hack-named files, mod APKs, deleted hack files
   * **Defender History**: what Defender caught and folders it was told to ignore
   * **Devices Removed**: USB drives and phones plugged in before but not now (flagged if unplugged within 6 hours of the scan)
   * **System Information**: Windows version and install date, last restart, PC model, CPU, GPU, RAM, and whether the game is installed in the emulator
   * **Alt Accounts**: Windows accounts and user folders on the PC, and Google accounts signed in to the emulator

Command-line options: `--mode pc|phone|both`, `--game freefire|pubgm|codm|all`, `--player "Name"`, `--deep`, `--no-pause`, `--no-open`.
Games are defined under `games` in `signatures.json`, so you can add another game the same way.

## What it checks

1. **Running programs and window titles**: Cheat Engine, injectors, "FF panel" / aimbot windows, debuggers, macro tools.
2. **DLLs loaded inside the emulator** (BlueStacks, MSI App Player, LDPlayer, GameLoop, MEmu, Nox, MuMu): hack DLL names injected into the emulator.
3. **Folders**: Desktop, Downloads, Documents, Pictures, Temp, AppData, Public, emulator shared folders and emulator install folders. Looks at file and folder names, known bad file hashes, and inside APK files (mod Free Fire APKs, cheat libraries).
4. **Apps inside the emulator** using the emulator's own adb: GameGuardian, Lucky Patcher, Lulubox, Magisk/root, Xposed, clone apps, unofficial Free Fire packages, and hack files in the emulator's Download folder.
5. **Recently run programs** (Windows Prefetch) and **recently opened files**. It also warns if the run history looks wiped.
6. **Recycle Bin**: hack files deleted just before the check.
7. **Kernel drivers** that cheats commonly abuse.

### Past use (even if the hack was deleted)

8. **Windows run history**: UserAssist (with how many times and when), BAM (last run time), MuiCache, Compatibility Assistant, Win+R Run box, recent documents and installed programs. These remember programs after they are deleted, and the report says "File is no longer on the PC".
9. **Browser history and downloads** (Chrome, Edge, Brave, Opera, Yandex, Firefox): hack panel videos/pages and downloaded hack files. Add hack-selling websites to `hack_websites` in `signatures.json`.
10. **Windows Defender**: hacks the antivirus caught in the past (HackTool / GameHack), and folders the player told the antivirus to ignore (a common hack-user trick).
11. **Inside the emulator**: leftover folders in `/sdcard/Android/data` and `/sdcard/Android/obb`.

### Deep traces (v2.1): finds hacks that were deleted, renamed or hidden

12. **NTFS change journal**: every file created, renamed or deleted on each drive, with time. Also spots wiped Prefetch and a deleted journal.
13. **Amcache**: path and SHA1 fingerprint of every program that ran. Add hack SHA1s to `known_bad_sha1` to catch them even when renamed.
14. **ShimCache**, **Shellbags** (folders opened in Explorer), **jump lists and shortcuts** (files opened).
15. **Program contents**: .exe/.dll files are opened and checked for hack text (aimbot, no recoil, ...) and for code that writes into the emulator's memory. This catches hacks with innocent names.
16. **Run then deleted**: programs run from Downloads/Desktop in the last days that no longer exist.
17. **Event logs**: cleared logs, old Defender alerts (kept even if Defender history was cleared), antivirus turned off, exclusions added then removed, installs.
18. **Command history**: trace-wiping commands such as `fsutil usn deletejournal` or `wevtutil cl`.
19. **Emulator history**: apps used or uninstalled before (Android usage stats), files in `/data/local/tmp`, hidden files, cheat processes inside the emulator.
20. **Deep scan** (asked at start, or `--deep`): searches the emulator's virtual disk for leftovers of deleted cheat apps. Close the emulator first; it can take several minutes.

Run as **Administrator**; the journal, Amcache and event-log checks need it.

The report has a **Past use timeline** that lists every dated item, newest first.
Windows only keeps some of this for a while, and a player can clear it, so missing history does not prove they never cheated.

## Result

* **SUSPICIOUS** (red): at least one HIGH item. Talk to the player and look at those items.
* **REVIEW** (orange): only MEDIUM items (e.g. a macro tool, rooted emulator). Check by hand.
* **CLEAN** (green): no known signatures found.

A report opens in the browser and is saved in the `reports` folder next to the exe (HTML + TXT), named with the PC name and time.

## How to build the .exe (once, on any Windows PC)

1. Install Python 3 from https://www.python.org/downloads/ and tick **"Add Python to PATH"**.
2. Put `ff_scanner.py`, `signatures.json` and `build.bat` in one folder.
3. Double-click `build.bat`.
4. Copy the `dist` folder (`FFScanner.exe` + `signatures.json`) to a USB drive.

You can also run it without building: `python ff_scanner.py` in an Administrator command prompt.

## How to use at the tournament

1. Ask the player to open their emulator (so the in-emulator app check works).
   For BlueStacks / MSI App Player: Settings > Advanced > turn on **Android Debug Bridge (ADB)**.
2. Plug in the USB, right-click `FFScanner.exe` > **Run as administrator** (it will ask by itself).
3. Wait for the result (usually under a minute or two) and read the report.

Options: `FFScanner.exe --no-pause --no-open` (for running without pressing Enter / without opening the browser).

## Adding new hack names

Open `signatures.json` (next to the exe) in Notepad:

* `keywords_high`: names that almost surely mean a hack (e.g. `"ff panel"`, `"aimbot"`).
* `keywords_medium`: names worth a look but can be innocent (e.g. `"macro"`).
* `process_names_high` / `process_names_medium`: exact .exe names.
* `android_packages_high` / `android_packages_medium`: Android app package names.
* `known_bad_sha256`: exact file fingerprints. To get one on Windows: `certutil -hashfile "file.exe" SHA256`, then add `"thehash": "Name of the hack"`.
* `hack_websites`: website addresses (e.g. `"somehacksite.com"`) that sell or share hacks. Any visit is flagged HIGH.
* `extra_scan_folders`: more folders to scan, e.g. `"D:\\Games"`.

Keep the commas and quotes correct. Short words (3 letters or less, like `esp`) only match as a whole word, so they won't flag `response.dll`.

## Honest limits

This is a **screening aid, not proof**, and no tool can promise 100%. It works on known names and fingerprints. A player can rename files,
use a private hack, run hacks from another PC/phone, or clean traces before the check. A rename can also
cause a false alarm the other way. Always look at the flagged items yourself and talk to the player before
deciding. For stronger protection, combine it with rules like: fresh emulator install, no USB/extra programs
during matches, and watching screens/replays.

## Sinhala summary (සාරාංශය)

v3.3: scan eka yaddi tika tika website ekata live yanava. Player scan eka cancel kalath, e welawa wenakan hoyagaththa dewal organizer ta penawa (STOPPED). Exe eka admin permission eka thaniyama illanava.

* Me software eka player ge PC eke **run karala** hack files, panels, injectors, mod APK, Cheat Engine wage dewal thiyenawada kiyala balanawa. Mukuth delete karanne naha, kisi thanakata yawanne naha.
* **Rathu (SUSPICIOUS)** awoth hack sign thiyenawa. Thambili (REVIEW) nam athin balanna. Kola (CLEAN) nam danna hack ekak hambune naha.
* Aluth hack nam `signatures.json` file eke Notepad walin add karanna puluwan.
* **Kalin use karala delete karapu hack** walath sign (Windows history, browser history, Defender) balanawa. Report eke "Past use timeline" eke kawadada use kale kiyala pennanawa.
* Hack eka rename karala thiyenawa nam hambenne nathi wenna puluwan. E nisa meka **sahathikayak nemei**, check karanna udaw wena tool ekak witharai.
