"""
FF Scanner - Free Fire emulator PC cheat screening tool.

Read-only. Nothing is deleted, changed or sent anywhere. The scanner looks at
running programs, window titles, common folders, emulator installs, Android
packages inside the emulator (through the emulator's own adb), recently run
programs, recently deleted files and loaded drivers, then writes a report.

Signature-based checks can be bypassed (renamed files, private hacks, cleaned
traces). Treat the result as a screening aid for the organizer, not as proof.
"""

import csv
import ctypes
import datetime as dt
import hashlib
import html
import io
import json
import os
import random
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

try:
    import winreg
except ImportError:  # not Windows
    winreg = None

APP_NAME = "FF Scanner"
VERSION = "3.5"

IS_WINDOWS = os.name == "nt"
HIGH, MEDIUM, INFO = "HIGH", "MEDIUM", "INFO"
LEVEL_ORDER = {HIGH: 0, MEDIUM: 1, INFO: 2}

SCAN_EXTS = {".exe", ".dll", ".apk", ".xapk", ".apks", ".sys", ".zip", ".rar", ".7z",
             ".bat", ".cmd", ".ps1", ".ahk", ".lua", ".js", ".vbs", ".reg", ".obb", ".so"}
SKIP_DIRS = {"node_modules", ".git", "cache", "code cache", "gpucache", "webcache", "crx_install",
             "extensions", "service worker", "indexeddb"}
# script/text files are full of words like 'inject', so only strong keywords count for them
WEAK_EXTS = {".js", ".lua", ".vbs", ".ps1", ".bat", ".cmd", ".reg"}
EMU_INSTALL_RX = re.compile(r"\\program files|\\programdata\\|bluestacks|ldplayer|txgameassistant|microvirt|\\nox\\|\\windows\\")
HASH_EXTS = {".exe", ".dll", ".apk", ".xapk", ".sys", ".so"}
APK_EXTS = {".apk", ".xapk", ".apks"}

EMULATOR_PROCESSES = {
    "hd-player.exe": "BlueStacks / MSI App Player",
    "dnplayer.exe": "LDPlayer",
    "ldplayer.exe": "LDPlayer",
    "androidemulatorex.exe": "GameLoop",
    "androidemulatoren.exe": "GameLoop",
    "androidemulator.exe": "GameLoop",
    "memu.exe": "MEmu",
    "nox.exe": "NoxPlayer",
    "mumuplayer.exe": "MuMu Player",
    "nemuplayer.exe": "MuMu Player",
}

# Drivers cheats load or abuse. Hardware-vendor drivers are INFO because they are normal when that vendor's tools are installed.
DRIVER_NOTES = {
    "dbk64": (HIGH, "Cheat Engine kernel driver is loaded."),
    "dbk32": (HIGH, "Cheat Engine kernel driver is loaded."),
    "kdmapper": (HIGH, "kdmapper is a cheat driver loader."),
    "capcom": (HIGH, "Capcom driver, widely abused to load cheat drivers."),
    "kprocesshacker": (MEDIUM, "Process Hacker driver (memory tool). Ask why it is running."),
    "gdrv": (INFO, "Gigabyte driver. Normal if Gigabyte tools (App Center, RGB Fusion) are installed; cheats sometimes abuse it."),
    "rtcore64": (INFO, "MSI Afterburner driver. Normal if Afterburner is installed; cheats sometimes abuse it."),
    "iqvw64e": (INFO, "Intel network diagnostics driver. Normal with Intel tools; kdmapper abuses it."),
}

ADB_PORTS = [5555, 5556, 5557, 5565, 5575, 21503, 62001, 62025, 7555, 16384]

# --------------------------------------------------------------------------- helpers


def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def is_admin():
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def env(name, default=""):
    return os.environ.get(name, default)


def run(cmd, timeout=20):
    try:
        flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        out = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=flags)
        return out.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def fmt_time(ts):
    try:
        return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "?"


def filetime_to_ts(ft):
    """Windows FILETIME (100ns since 1601) to Unix seconds, or 0."""
    if not ft or ft < 116444736000000000:
        return 0
    return (ft - 116444736000000000) / 1e7


def rot13(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def reg_values(root, path):
    """Yield (name, data, type) for every value under a registry key; nothing if missing."""
    if winreg is None:
        return
    try:
        key = winreg.OpenKey(root, path)
    except OSError:
        return
    with key:
        i = 0
        while True:
            try:
                yield winreg.EnumValue(key, i)
            except OSError:
                return
            i += 1


def reg_subkeys(root, path):
    if winreg is None:
        return []
    try:
        key = winreg.OpenKey(root, path)
    except OSError:
        return []
    names = []
    with key:
        i = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, i))
            except OSError:
                return names
            i += 1


def hash_file(path, max_bytes):
    """Return (sha1, sha256) of a file, or (None, None) if too big or unreadable."""
    try:
        if os.path.getsize(path) > max_bytes:
            return None, None
        h1, h2 = hashlib.sha1(), hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h1.update(chunk)
                h2.update(chunk)
        return h1.hexdigest(), h2.hexdigest()
    except Exception:
        return None, None


def time_now():
    return dt.datetime.now().timestamp()


def parse_any_time(text):
    """Parse the date formats Windows tools print (depends on the PC's region settings)."""
    text = (text or "").strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %I:%M:%S %p", "%d.%m.%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    return 0


def parse_shimcache(data):
    """Windows 8.1/10/11 AppCompatCache value -> [(path, file_time)]."""
    out = []
    if len(data) < 0x34:
        return out
    pos = struct.unpack_from("<I", data, 0)[0]
    while pos + 12 <= len(data) and data[pos:pos + 4] in (b"10ts", b"00ts"):
        size = struct.unpack_from("<I", data, pos + 8)[0]
        p = pos + 12
        try:
            plen = struct.unpack_from("<H", data, p)[0]
            path = data[p + 2:p + 2 + plen].decode("utf-16-le", "ignore")
            ft = struct.unpack_from("<q", data, p + 2 + plen)[0] if data[pos:pos + 4] == b"10ts" else 0
        except struct.error:
            break
        out.append((path, filetime_to_ts(ft)))
        pos = pos + 12 + size
    return out


def utf16_strings(data, min_len=4):
    """Printable UTF-16LE strings inside binary data (paths in .lnk, jump lists, shellbags)."""
    return [m.decode("utf-16-le", "ignore") for m in re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)]


def ascii_strings(data, min_len=4):
    return [m.decode("latin-1") for m in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]


VIDEO_SITES = ("youtube.com", "youtu.be", "tiktok.com", "facebook.com", "fb.watch", "instagram.com", "twitch.tv")
SEARCH_SITES = ("google.com", "google.lk", "bing.com", "duckduckgo.com", "yahoo.com", "yandex.com", "yandex.ru")


def url_parts(url):
    """(host, path) of a web address, lower case, without the query string."""
    try:
        u = urllib.parse.urlsplit(url)
        host = (u.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        return host, urllib.parse.unquote(u.path).lower()
    except Exception:
        return "", url.lower().split("?")[0]


def both_encodings(word):
    w = word.lower().encode("latin-1", "ignore")
    return w, word.lower().encode("utf-16-le")


class Matcher:
    """Keyword matcher. Keywords of 3 letters or less only match whole words."""

    def __init__(self, high, medium):
        self.rules = []
        for level, words in ((HIGH, high), (MEDIUM, medium)):
            for w in words:
                w = w.lower().strip()
                if not w:
                    continue
                if len(w.replace(" ", "")) <= 3:
                    rx = re.compile(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])")
                else:
                    # treat spaces in the keyword as "any separator or nothing"
                    rx = re.compile(r"[\s_\-\.]*".join(re.escape(p) for p in w.split()))
                self.rules.append((level, w, rx))

    def match(self, text):
        """Return (level, keyword) of the strongest hit, or None."""
        t = text.lower()
        best = None
        for level, w, rx in self.rules:
            if rx.search(t):
                if best is None or LEVEL_ORDER[level] < LEVEL_ORDER[best[0]]:
                    best = (level, w)
                    if level == HIGH:
                        break
        return best


# --------------------------------------------------------------------------- scanner


class Scanner:
    def __init__(self, cfg, game_keys):
        self.cfg = cfg
        self.findings = []
        self.notes = []
        self.system_info = []   # (label, value)
        self.accounts = []      # (where, account, detail)
        games = [cfg.get("games", {})[k] for k in game_keys]
        self.game_name = " + ".join(g["name"] for g in games)
        self.game_pkgs = {p.lower() for g in games for p in g.get("official_packages", [])}
        self.game_hints = [h.lower() for g in games for h in g.get("name_hints", [])]
        self.game_words = tuple(w.lower() for g in games for w in g.get("context_words", []))
        extra_high = [k for g in games for k in g.get("keywords_high", [])]
        self.matcher = Matcher(cfg.get("keywords_high", []) + extra_high, cfg.get("keywords_medium", []))
        self.recent_cutoff = dt.datetime.now().timestamp() - 86400 * int(cfg.get("recent_days", 7))
        self.max_hash = int(cfg.get("max_hash_size_mb", 150)) * 1024 * 1024
        self.bad_hashes = {k.lower(): v for k, v in cfg.get("known_bad_sha256", {}).items()
                           if not k.startswith("_")}
        self.bad_sha1 = {k.lower(): v for k, v in cfg.get("known_bad_sha1", {}).items() if not k.startswith("_")}
        self.content_kw = [(k, both_encodings(k)) for k in cfg.get("content_keywords", [])]
        self.emu_targets = [(k, both_encodings(k)) for k in cfg.get("emulator_targets", [])]
        self.mem_apis = [(k, both_encodings(k)) for k in cfg.get("memory_apis", [])]
        self.deep = False
        self.mode = "pc"   # pc (PC + emulator), phone (Android phone over USB only), both
        self.deep_note_done = False
        self.proc_high = {p.lower() for p in cfg.get("process_names_high", [])}
        self.proc_med = {p.lower() for p in cfg.get("process_names_medium", [])}
        self.pkg_high = [p.lower() for p in cfg.get("android_packages_high", [])]
        self.pkg_med = [p.lower() for p in cfg.get("android_packages_medium", [])]
        self.seen_files = set()
        self.files_checked = 0
        self.running_emulators = []
        self.current = ""          # what the scan is doing now
        self.step_no, self.step_total = 0, 0
        self.on_change = None      # called when there is something new to send live
        self.show = lambda msg: print("  - " + msg, flush=True)

    def add(self, level, area, what, reason, when=0):
        """when: Unix time the item was last used/seen, if known (goes into the past-use timeline)."""
        self.findings.append({"level": level, "area": area, "what": what, "reason": reason, "when": when or 0})
        if self.on_change and level != INFO:
            self.on_change()

    def match_path(self, path):
        """Match a full path: the file name first, then any folder name (HIGH only for folders)."""
        path = path.replace("/", "\\")
        name = os.path.basename(path.rstrip("\\"))
        if name.lower() in self.proc_high:
            return (HIGH, name)
        hit = self.matcher.match(name)
        if hit:
            return hit
        if name.lower() in self.proc_med:
            return (MEDIUM, name)
        for part in path.split("\\")[:-1]:
            hit = self.matcher.match(part)
            if hit and hit[0] == HIGH:
                return hit
        return None

    def status(self, msg):
        self.current = msg
        self.show(msg)
        if self.on_change:
            self.on_change()

    def progress(self, msg):
        """Update the current step's text (e.g. a percentage) without starting a new step."""
        self.current = msg

    # ---- 1. running processes and window titles
    def scan_processes(self):
        self.status("Checking running programs and window titles")
        if not IS_WINDOWS:
            self.notes.append("Process check skipped (not Windows).")
            return
        out = run(["tasklist", "/v", "/fo", "csv"], timeout=60)
        rows = list(csv.reader(io.StringIO(out)))
        if not rows:
            self.notes.append("Could not read the process list.")
            return
        for r in rows[1:]:
            if len(r) < 2:
                continue
            name = r[0]
            title = r[-1] if len(r) >= 9 else ""
            lname = name.lower()
            if lname in EMULATOR_PROCESSES:
                self.running_emulators.append(lname)
            if lname in self.proc_high:
                self.add(HIGH, "Running program", name, "Known cheat / injector program is running")
                continue
            if lname in self.proc_med:
                self.add(MEDIUM, "Running program", name, "Debugger, memory or macro tool is running")
                continue
            hit = self.matcher.match(name)
            if hit:
                self.add(hit[0], "Running program", name, f"Name contains '{hit[1]}'")
            if title and title.upper() != "N/A":
                hit = self.matcher.match(title)
                if hit:
                    self.add(hit[0], "Window title", f"{title}  ({name})",
                             f"Window title contains '{hit[1]}'")
        if self.running_emulators:
            self.notes.append("Emulator running: " + ", ".join(
                sorted({EMULATOR_PROCESSES[e] for e in self.running_emulators})))

    # ---- 2. DLLs loaded inside the emulator process
    def scan_emulator_modules(self):
        if not IS_WINDOWS or not self.running_emulators:
            return
        self.status("Checking DLLs loaded inside the emulator")
        for exe in sorted(set(self.running_emulators)):
            out = run(["tasklist", "/m", "/fo", "csv", "/fi", f"imagename eq {exe}"], timeout=60)
            rows = list(csv.reader(io.StringIO(out)))
            for r in rows[1:]:
                if len(r) < 3:
                    continue
                for mod in r[2].split(","):
                    mod = mod.strip()
                    if not mod:
                        continue
                    hit = self.matcher.match(mod)
                    if hit:
                        self.add(hit[0] if hit[0] == HIGH else MEDIUM, "Emulator module",
                                 f"{mod} loaded in {exe}", f"DLL name contains '{hit[1]}' (possible injection)")

    # ---- 3. folders on disk
    def scan_folders(self):
        self.status("Scanning Desktop, Downloads, Temp, AppData and emulator folders")
        up = env("USERPROFILE", os.path.expanduser("~"))
        appdata, local = env("APPDATA"), env("LOCALAPPDATA")
        pd = env("ProgramData", r"C:\ProgramData")
        pf, pf86 = env("ProgramFiles", r"C:\Program Files"), env("ProgramFiles(x86)", r"C:\Program Files (x86)")
        targets = [
            (os.path.join(up, "Desktop"), 6),
            (os.path.join(up, "Downloads"), 6),
            (os.path.join(up, "Documents"), 4),
            (os.path.join(up, "OneDrive", "Desktop"), 5),
            (os.path.join(up, "Videos"), 2),
            (os.path.join(up, "Pictures"), 4),
            (env("TEMP"), 4),
            (appdata, 3),
            (local, 2),
            (r"C:\Users\Public", 4),
            # emulator data and shared folders
            (os.path.join(pd, "BlueStacks_nxt"), 5),
            (os.path.join(pd, "BlueStacks_msi5"), 5),
            (os.path.join(pd, "BlueStacks"), 5),
            (os.path.join(up, "Documents", "XuanZhi9"), 6),
            (os.path.join(up, "Documents", "XuanZhi64"), 6),
            (os.path.join(up, "Documents", "leidian9"), 6),
            (os.path.join(up, "Documents", "leidian64"), 6),
            (os.path.join(up, "Pictures", "BlueStacks"), 4),
            (os.path.join(up, "Pictures", "MSI App Player"), 4),
            (os.path.join(up, "Nox_share"), 5),
            (os.path.join(up, "Downloads", "MEmu Download"), 5),
            # emulator installs
            (os.path.join(pf, "BlueStacks_nxt"), 4),
            (os.path.join(pf, "BlueStacks_msi5"), 4),
            (os.path.join(pf, "BlueStacks"), 4),
            (os.path.join(pf, "TxGameAssistant"), 5),
            (os.path.join(pf86, "TxGameAssistant"), 5),
            (os.path.join(pf, "Microvirt"), 4),
            (os.path.join(pf86, "Nox"), 4),
            (r"C:\LDPlayer", 5),
            (r"D:\LDPlayer", 5),
            (r"C:\TxGameDownload", 5),
            (r"D:\TxGameDownload", 5),
        ]
        for extra in self.cfg.get("extra_scan_folders", []):
            targets.append((os.path.expandvars(extra), 6))
        seen_roots = set()
        for root, depth in targets:
            if not root or not os.path.isdir(root):
                continue
            key = os.path.normcase(os.path.abspath(root))
            if key in seen_roots:
                continue
            seen_roots.add(key)
            self.walk(root, depth)

    def walk(self, root, max_depth, depth=0):
        try:
            entries = list(os.scandir(root))
        except Exception:
            return
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir():
                    hit = self.matcher.match(e.name)
                    if hit and hit[0] == HIGH:
                        self.add(HIGH, "Folder", e.path, f"Folder name contains '{hit[1]}'")
                    lname = e.name.lower()
                    if depth < max_depth and lname not in SKIP_DIRS and not lname.startswith("scoped_dir"):
                        self.walk(e.path, max_depth, depth + 1)
                elif e.is_file():
                    self.check_file(e.path, e.name)
            except Exception:
                continue

    def check_file(self, path, name):
        key = os.path.normcase(path)
        if key in self.seen_files:
            return
        self.seen_files.add(key)
        ext = os.path.splitext(name)[1].lower()
        if ext not in SCAN_EXTS:
            return
        self.files_checked += 1
        try:
            mtime = os.path.getmtime(path)
        except Exception:
            mtime = 0
        recent = " (changed in the last %d days)" % self.cfg.get("recent_days", 7) if mtime >= self.recent_cutoff else ""
        hit = self.matcher.match(name)
        if hit and ext in WEAK_EXTS and hit[0] != HIGH:
            hit = None
        if hit:
            self.add(hit[0], "File", path, f"File name contains '{hit[1]}'{recent}  [{fmt_time(mtime)}]", mtime)
        if ext in HASH_EXTS and (self.bad_hashes or self.bad_sha1):
            h1, h2 = hash_file(path, self.max_hash)
            if h2 in self.bad_hashes or h1 in self.bad_sha1:
                self.add(HIGH, "File (hash)", path,
                         f"Exact match with known hack: {self.bad_hashes.get(h2) or self.bad_sha1.get(h1)} (works even if renamed)", mtime)
        if ext in APK_EXTS:
            self.check_apk(path, name, mtime)
        if ext in (".exe", ".dll") and not hit and not EMU_INSTALL_RX.search(path.lower()):
            self.check_content(path, mtime)

    def check_content(self, path, mtime):
        """Look inside a program for hack text and emulator-memory code. Catches renamed hacks."""
        try:
            if os.path.getsize(path) > 60 * 1024 * 1024:
                return
            with open(path, "rb") as f:
                data = f.read().lower()
        except Exception:
            return
        found = lambda items: [k for k, (a, u) in items if a in data or u in data]
        words = found(self.content_kw)
        targets = found(self.emu_targets)
        apis = found(self.mem_apis)
        if targets and apis:
            self.add(HIGH, "File (content)", path,
                     f"Program reads/writes another program's memory ({', '.join(apis[:2])}) and targets "
                     f"{', '.join(targets[:3])}. This is how emulator hacks work, even when renamed.", mtime)
        elif len(words) >= 2 or (words and targets):
            self.add(HIGH, "File (content)", path,
                     f"Program contains hack text: {', '.join(words[:5])}" + (f"; targets {', '.join(targets[:2])}" if targets else ""), mtime)
        elif words:
            self.add(MEDIUM, "File (content)", path, f"Program contains the text '{words[0]}'", mtime)

    def check_apk(self, path, name, mtime):
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                inner = []
                for n in names:
                    if n.lower().endswith(".apk"):  # xapk/apks bundles
                        inner.append(n)
                blob = "\n".join(names).lower()
                manifest_text = ""
                if "androidmanifest.xml" in blob:
                    try:
                        raw = z.read("AndroidManifest.xml")
                        manifest_text = raw.decode("utf-16-le", "ignore").lower() + raw.decode("latin-1").lower()
                    except Exception:
                        pass
        except Exception:
            return
        for n in names:
            hit = self.matcher.match(os.path.basename(n))
            if hit and hit[0] == HIGH:
                self.add(HIGH, "APK contents", f"{path} -> {n}", f"APK contains file named with '{hit[1]}'")
                break
        for pkg in self.pkg_high:
            if pkg in manifest_text:
                self.add(HIGH, "APK", path, f"APK is a known cheat tool ({pkg})")
        lname = name.lower()
        is_game = any(p in manifest_text for p in self.game_pkgs) or any(
            h in lname or h.replace(" ", "") in lname for h in self.game_hints)
        if is_game:
            libs = [n for n in names if n.lower().startswith("lib/") and n.lower().endswith(".so")]
            odd = [n for n in libs if self.matcher.match(os.path.basename(n))]
            if odd:
                self.add(HIGH, "Game APK", path, "Game APK contains suspicious libraries: " +
                         ", ".join(os.path.basename(o) for o in odd[:5]), mtime)
            else:
                self.add(MEDIUM, "Game APK", path,
                         "Game APK file found outside the Play Store. Could be a modded APK; "
                         "ask the player to reinstall from Play Store. [%s]" % fmt_time(mtime), mtime)

    # ---- 4. Android packages inside the emulator, through its own adb
    def adb_devices(self, adb):
        """[(serial, kind)] for every answering Android device, kind 'Phone' or 'Emulator', filtered by scan mode."""
        out = []
        for line in run([adb, "devices"], timeout=10).splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2 or parts[1] != "device":
                continue
            dev = parts[0]
            emu = (dev.startswith(("emulator-", "127.0.0.1", "localhost"))
                   or run([adb, "-s", dev, "shell", "getprop", "ro.kernel.qemu"], timeout=8).strip() == "1")
            kind = "Emulator" if emu else "Phone"
            if self.mode == "both" or (self.mode == "pc") == (kind == "Emulator"):
                out.append((dev, kind))
        return sorted(set(out))

    def scan_adb(self):
        if not self.cfg.get("use_adb", True):
            return
        what = {"pc": "the emulator", "phone": "the phone", "both": "the emulator and phone"}[self.mode]
        self.status(f"Checking apps installed on {what} (adb)")
        adbs = self.find_adb()
        if not adbs:
            self.notes.append("No adb found, so Android apps were not checked. Put adb.exe from Google's platform-tools "
                              "next to FFScanner.exe (see README), or open the emulator and scan again.")
            return
        adb = adbs[0]
        if self.mode != "phone":
            for port in ADB_PORTS:
                run([adb, "connect", f"127.0.0.1:{port}"], timeout=4)
        devices = self.adb_devices(adb)
        if not devices:
            if self.mode == "phone":
                self.add(MEDIUM, "Phone", "No phone answered over USB",
                         "Turn on USB debugging (Settings > Developer options), plug in the phone, tap Allow on the phone, then scan again.")
            else:
                self.notes.append("No running emulator answered adb. Start the emulator (and enable ADB in BlueStacks "
                                  "settings) and scan again.")
            return
        for dev, kind in devices:
            sh = lambda *c, t=30: run([adb, "-s", dev, "shell", *c], timeout=t)
            where = kind.lower()
            out = sh("pm", "list", "packages", "-i")
            pkgs, installer = [], {}
            for l in out.splitlines():
                m = re.match(r"package:(\S+)(?:\s+installer=(\S+))?", l.strip())
                if m:
                    pkgs.append(m.group(1).lower())
                    installer[m.group(1).lower()] = m.group(2) or "null"
            self.notes.append(f"{kind} {dev}: {len(pkgs)} apps installed.")
            for p in pkgs:
                if any(p == k or p.startswith(k) for k in self.pkg_high):
                    self.add(HIGH, f"{kind} app", f"{p}  ({dev})", f"Known cheat app installed on the {where}")
                elif any(p == k or p.startswith(k) for k in self.pkg_med):
                    self.add(MEDIUM, f"{kind} app", f"{p}  ({dev})", f"Root / hook / clone app installed on the {where}")
                else:
                    hit = self.matcher.match(p)
                    if hit:
                        self.add(hit[0], f"{kind} app", f"{p}  ({dev})", f"Package name contains '{hit[1]}'")
                    elif p not in self.game_pkgs and any(h.replace(" ", "") in p for h in self.game_hints):
                        self.add(HIGH, f"{kind} app", f"{p}  ({dev})",
                                 "Unofficial copy of the game (package is not an official one)")
            installed = sorted(self.game_pkgs & set(pkgs))
            self.system_info.append((f"Game on {where} {dev}", ", ".join(
                f"{g} (installed by {installer.get(g)})" for g in installed) or "not installed"))
            for g in installed:
                src = installer.get(g, "null")
                if src not in ("com.android.vending", "com.google.android.packageinstaller.playstore"):
                    self.add(MEDIUM if kind == "Phone" else INFO, f"{kind} app", f"{g}  ({dev})",
                             f"Game was not installed from the Play Store (installer: {src}). Modded APKs are installed this way; "
                             "ask the player to reinstall from the Play Store.")
            accts = sh("dumpsys", "account", t=20)
            for m in re.finditer(r"Account \{name=([^,]+), type=([^}]+)\}", accts):
                self.accounts.append((f"{kind} {dev}", m.group(1), m.group(2)))
            su = sh("which", "su", t=10).strip()
            if su and "not found" not in su:
                self.add(MEDIUM if kind == "Emulator" else HIGH, f"{kind} root", f"{su}  ({dev})",
                         f"The {where} is rooted (su found). Root is needed by most memory hacks.")
            if kind == "Phone":
                prop = lambda k: sh("getprop", k, t=8).strip()
                model = f"{prop('ro.product.manufacturer')} {prop('ro.product.model')}".strip()
                self.system_info.append((f"Phone {dev}", f"{model}, Android {prop('ro.build.version.release')}, "
                                                          f"security patch {prop('ro.build.version.security_patch')}"))
                boot = prop("ro.boot.verifiedbootstate")
                if boot in ("orange", "yellow") or prop("ro.boot.flash.locked") == "0":
                    self.add(HIGH, "Phone root", f"Bootloader unlocked ({dev})",
                             f"Verified boot state is '{boot or 'unlocked'}'. An unlocked phone can run root hacks that hide themselves.")
                if prop("ro.debuggable") == "1" or "test-keys" in prop("ro.build.tags"):
                    self.add(MEDIUM, "Phone root", f"Custom or debug Android build ({dev})",
                             "The phone runs a custom ROM or debug build, which makes hiding hacks easier.")
                if "magisk" in sh("ls", "/sbin", "/debug_ramdisk", t=8).lower():
                    self.add(HIGH, "Phone root", f"Magisk files found ({dev})", "Magisk root is installed, even if its app is hidden.")
            for sd in ("/sdcard/Download", "/sdcard", "/sdcard/Android/obb", "/sdcard/Android/data"):
                listing = sh("ls", "-1", sd, t=15)
                for item in listing.splitlines():
                    hit = self.matcher.match(item)
                    if hit:
                        self.add(hit[0], f"{kind} storage", f"{sd}/{item.strip()}  ({dev})",
                                 f"File name contains '{hit[1]}'")

    def find_adb(self):
        pf, pf86 = env("ProgramFiles", r"C:\Program Files"), env("ProgramFiles(x86)", r"C:\Program Files (x86)")
        candidates = [
            os.path.join(pf, "BlueStacks_nxt", "HD-Adb.exe"),
            os.path.join(pf, "BlueStacks_msi5", "HD-Adb.exe"),
            os.path.join(pf, "BlueStacks", "HD-Adb.exe"),
            r"C:\LDPlayer\LDPlayer9\adb.exe", r"C:\LDPlayer\LDPlayer4.0\adb.exe",
            r"D:\LDPlayer\LDPlayer9\adb.exe",
            os.path.join(pf, "Microvirt", "MEmu", "adb.exe"),
            os.path.join(pf86, "Nox", "bin", "nox_adb.exe"),
            os.path.join(pf, "TxGameAssistant", "ui", "adb.exe"),
            os.path.join(pf86, "TxGameAssistant", "ui", "adb.exe"),
        ]
        bundled = os.path.join(base_dir(), "adb.exe" if IS_WINDOWS else "adb")
        if self.mode == "phone" and os.path.isfile(bundled):
            candidates.insert(0, bundled)  # Google's adb talks to phones most reliably
        else:
            candidates.append(bundled)
        found = [c for c in candidates if os.path.isfile(c)]
        if not found:
            for name in ("adb.exe", "adb"):
                for d in env("PATH").split(os.pathsep):
                    p = os.path.join(d, name)
                    if os.path.isfile(p):
                        found.append(p)
        return found

    # ---- 5. recently run programs (Prefetch) and recent files
    def scan_history(self):
        self.status("Checking recently run programs and recent files")
        windir = env("WINDIR", r"C:\Windows")
        pf_dir = os.path.join(windir, "Prefetch")
        if IS_WINDOWS:
            try:
                items = [e for e in os.scandir(pf_dir) if e.name.lower().endswith(".pf")]
                if len(items) < 15:
                    self.add(MEDIUM, "Prefetch", pf_dir,
                             f"Only {len(items)} entries. Run history may have been wiped recently.")
                for e in items:
                    exe = e.name.rsplit("-", 1)[0]
                    t = e.stat().st_mtime
                    if exe.lower() in self.proc_high:
                        self.add(HIGH, "Recently run", exe, f"Cheat program was run (last {fmt_time(t)})", t)
                        continue
                    hit = self.matcher.match(exe)
                    if hit:
                        lvl = hit[0] if t >= self.recent_cutoff else MEDIUM
                        self.add(lvl, "Recently run", exe, f"Program name contains '{hit[1]}' (last run {fmt_time(t)})", t)
            except PermissionError:
                self.notes.append("Prefetch (recently run programs) needs Administrator. Run as admin for this check.")
            except FileNotFoundError:
                self.notes.append("Prefetch folder not found (may be disabled).")
        recent = os.path.join(env("APPDATA"), "Microsoft", "Windows", "Recent")
        if os.path.isdir(recent):
            try:
                for e in os.scandir(recent):
                    hit = self.matcher.match(e.name)
                    if hit:
                        self.add(hit[0], "Recently opened", e.name[:-4] if e.name.endswith(".lnk") else e.name,
                                 f"Recently opened item contains '{hit[1]}' [{fmt_time(e.stat().st_mtime)}]", e.stat().st_mtime)
            except Exception:
                pass

    # ---- 6. recycle bin (players often delete hacks just before a check)
    def scan_recycle_bin(self):
        if not IS_WINDOWS:
            return
        self.status("Checking Recycle Bin for recently deleted hacks")
        drives = [f"{c}:\\" for c in "CDEFG" if os.path.isdir(f"{c}:\\")]
        for d in drives:
            rb = os.path.join(d, "$Recycle.Bin")
            try:
                sids = list(os.scandir(rb))
            except Exception:
                continue
            for sid in sids:
                try:
                    items = list(os.scandir(sid.path))
                except Exception:
                    continue
                for it in items:
                    if not it.name.startswith("$I"):
                        continue
                    orig, ts = self.parse_recycle_info(it.path)
                    if not orig:
                        continue
                    hit = self.matcher.match(os.path.basename(orig))
                    if hit:
                        self.add(hit[0], "Deleted file", orig,
                                 f"Deleted item contains '{hit[1]}' (deleted {fmt_time(ts)})", ts)

    @staticmethod
    def parse_recycle_info(path):
        try:
            with open(path, "rb") as f:
                data = f.read()
            version = struct.unpack_from("<q", data, 0)[0]
            ft = struct.unpack_from("<q", data, 16)[0]
            when = filetime_to_ts(ft)
            if version == 2:
                n = struct.unpack_from("<i", data, 24)[0]
                name = data[28:28 + n * 2].decode("utf-16-le", "ignore").rstrip("\x00")
            else:
                name = data[24:24 + 520].decode("utf-16-le", "ignore").split("\x00")[0]
            return name, when
        except Exception:
            return None, None

    # ---- 7. kernel drivers
    def scan_drivers(self):
        if not IS_WINDOWS:
            return
        self.status("Checking loaded drivers")
        out = run(["driverquery", "/fo", "csv"], timeout=60)
        kws = [k.lower() for k in self.cfg.get("driver_keywords", [])]
        for r in list(csv.reader(io.StringIO(out)))[1:]:
            if not r:
                continue
            name = r[0].lower()
            desc = r[1] if len(r) > 1 else ""
            for k in kws:
                # whole driver name only (plus a version number), so 'gdrv' won't match 'EhStorTcgDrv'
                if re.fullmatch(re.escape(k) + r"\d*(\.sys)?", name):
                    level, why = DRIVER_NOTES.get(k, (MEDIUM, "Driver often abused by cheats. Can be legit; check it."))
                    self.add(level, "Driver", r[0] + (f"  ({desc})" if desc else ""), why)
                    break

    # ---- 8. past use: Windows remembers programs that ran, even after they are deleted
    def scan_past_registry(self):
        if winreg is None:
            return
        self.status("Checking Windows run history (programs used in the past)")
        HKCU, HKLM = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
        exp = r"Software\Microsoft\Windows\CurrentVersion\Explorer"

        def report(area, path, reason, when=0):
            hit = self.match_path(path)
            if not hit:
                return
            ago = f" (last {fmt_time(when)})" if when else ""
            exists = "" if os.path.exists(path) else " File is no longer on the PC."
            self.add(hit[0], area, path, f"{reason} - matched '{hit[1]}'{ago}.{exists}", when)

        # UserAssist: programs started from Explorer / Start menu, with run count and last run time
        for guid in reg_subkeys(HKCU, exp + r"\UserAssist"):
            for name, data, _ in reg_values(HKCU, exp + rf"\UserAssist\{guid}\Count"):
                path = rot13(name)
                when, count = 0, 0
                if isinstance(data, bytes) and len(data) >= 68:
                    count = struct.unpack_from("<i", data, 4)[0]
                    when = filetime_to_ts(struct.unpack_from("<q", data, 60)[0])
                report("Past use (UserAssist)", path, f"Program was opened {count} time(s)", when)

        # BAM: every program run per user, with last run time (Windows 10/11)
        for base in (r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                     r"SYSTEM\CurrentControlSet\Services\bam\UserSettings"):
            for sid in reg_subkeys(HKLM, base):
                for name, data, _ in reg_values(HKLM, base + "\\" + sid):
                    if not isinstance(data, bytes) or len(data) < 8:
                        continue
                    when = filetime_to_ts(struct.unpack_from("<q", data, 0)[0])
                    path = re.sub(r"^\\Device\\HarddiskVolume\d+", "C:", name)
                    report("Past use (BAM)", path, "Program was run", when)
                    if when >= self.recent_cutoff and not self.match_path(path) and self.user_path_gone(path):
                        self.add(MEDIUM, "Run then deleted", path,
                                 f"Program ran from a user folder on {fmt_time(when)} and was then deleted. "
                                 "Renamed hacks look like this; ask the player what it was.", when)

        # MuiCache and Compatibility Assistant: programs ever run (no time stored)
        for name, _, _ in reg_values(HKCU, r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"):
            path = re.sub(r"\.(FriendlyAppName|ApplicationCompany)$", "", name)
            report("Past use (MuiCache)", path, "Program was run at some time")
        for name, _, _ in reg_values(HKCU, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"):
            report("Past use (AppCompat)", name, "Program was run at some time")
        for root in (HKCU, HKLM):
            for name, data, _ in reg_values(root, r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"):
                report("Past use (AppCompat)", name, f"Program had compatibility/admin settings ({data})")

        # Run box history and recent documents
        for name, data, _ in reg_values(HKCU, exp + r"\RunMRU"):
            if name != "MRUList" and isinstance(data, str):
                report("Past use (Run box)", data.rstrip("\\1"), "Typed in the Win+R Run box")
        for name, data, _ in reg_values(HKCU, exp + r"\RecentDocs"):
            if isinstance(data, bytes) and name != "MRUListEx":
                doc = data.decode("utf-16-le", "ignore").split("\x00")[0]
                report("Past use (Recent docs)", doc, "File was opened")

        # Installed programs (also catches ones installed and later forgotten)
        for root in (HKCU, HKLM):
            for base in (r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                         r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
                for sub in reg_subkeys(root, base):
                    for name, data, _ in reg_values(root, base + "\\" + sub):
                        if name == "DisplayName" and isinstance(data, str):
                            hit = self.matcher.match(data)
                            if hit:
                                self.add(hit[0], "Installed program", data, f"Name contains '{hit[1]}'")

    # ---- 9. past use: browser history and downloads (hack sites, panel downloads)
    def scan_browsers(self):
        self.status("Checking browser history and downloads")
        local, roam = env("LOCALAPPDATA"), env("APPDATA")
        chromium = [
            ("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
            ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
            ("Brave", os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Opera", os.path.join(roam, "Opera Software")),
            ("Yandex", os.path.join(local, "Yandex", "YandexBrowser", "User Data")),
            ("UC Browser", os.path.join(local, "UCBrowser")),
        ]
        sites = [s.lower() for s in self.cfg.get("hack_websites", []) if s and not s.startswith("_")]
        ff_words = self.game_words
        for browser, root in chromium:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, dirs, files in os.walk(root):
                if dirpath.count(os.sep) - root.count(os.sep) > 2:
                    dirs[:] = []
                    continue
                if "History" in files:
                    self.read_history(browser, os.path.join(dirpath, "History"), "chromium", sites, ff_words)
        ff_root = os.path.join(roam, "Mozilla", "Firefox", "Profiles")
        if os.path.isdir(ff_root):
            for prof in os.listdir(ff_root):
                p = os.path.join(ff_root, prof, "places.sqlite")
                if os.path.isfile(p):
                    self.read_history("Firefox", p, "firefox", sites, ff_words)

    def open_sqlite(self, path):
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
            con.execute("select 1 from sqlite_master").fetchall()
            return con, None
        except Exception:
            pass
        # browser is open and the file is locked: read a temporary copy, deleted afterwards
        tmp = os.path.join(env("TEMP", "."), f"ffscan_{os.getpid()}_{abs(hash(path))}.db")
        try:
            shutil.copy2(path, tmp)
            return sqlite3.connect(f"file:{tmp}?mode=ro", uri=True), tmp
        except Exception:
            return None, None

    def read_history(self, browser, path, kind, sites, ff_words):
        con, tmp = self.open_sqlite(path)
        if con is None:
            self.notes.append(f"Could not read {browser} history ({path}). Close the browser and scan again.")
            return
        rows = []
        try:
            if kind == "chromium":
                for url, title, t in con.execute("select url, title, last_visit_time from urls"):
                    rows.append(("Visited", url or "", title or "", filetime_to_ts((t or 0) * 10)))
                for target, url, t in con.execute(
                        "select d.target_path, c.url, d.start_time from downloads d "
                        "left join downloads_url_chains c on c.id = d.id"):
                    rows.append(("Downloaded", url or "", target or "", filetime_to_ts((t or 0) * 10)))
            else:
                for url, title, t in con.execute("select url, title, last_visit_date from moz_places"):
                    rows.append(("Visited", url or "", title or "", (t or 0) / 1e6))
        except Exception as e:
            self.notes.append(f"{browser} history read error: {e}")
        finally:
            con.close()
            if tmp:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
        hits = 0
        for action, url, label, when in sorted(rows, key=lambda r: -r[3]):
            host, page = url_parts(url)
            # only the page title and the address itself; query strings hold random sign-in tokens
            # ("...dFRida762..." is not Frida)
            text = f"{label} {host}{page}".lower()
            level, why = None, ""
            site = next((s for s in sites if s in host + page), None)
            if site:
                level, why = HIGH, f"known hack website '{site}'"
            else:
                hit = self.matcher.match(label if action == "Downloaded" else text)
                video = any(host == v or host.endswith("." + v) for v in VIDEO_SITES)
                search = any(host == v or host.endswith("." + v) for v in SEARCH_SITES) and action == "Visited"
                if hit and hit[0] == HIGH and (video or search):
                    level, why = MEDIUM, (f"watched a video about '{hit[1]}'" if video else f"searched for '{hit[1]}'") + \
                        " (interest, not proof of use)"
                elif hit and hit[0] == HIGH:
                    level, why = HIGH, f"contains '{hit[1]}'"
                elif hit and any(w in text for w in ff_words):
                    level, why = MEDIUM, f"Free Fire page containing '{hit[1]}'"
            if not level:
                continue
            what = label if action == "Downloaded" else (label[:90] + "  " if label else "") + url[:150]
            self.add(level, f"{browser} {action.lower()}", what, f"{action} {fmt_time(when)} - {why}", when)
            hits += 1
            if hits >= 40:
                self.notes.append(f"{browser}: more than 40 matching history items, only the newest 40 shown.")
                break

    # ---- 10. past use: Windows Defender detections and exclusions
    def scan_defender(self):
        if not IS_WINDOWS:
            return
        self.status("Checking Windows Defender history and exclusions")
        ps = ("$t=@{}; Get-MpThreat -ErrorAction SilentlyContinue | % { $t[[string]$_.ThreatID]=$_.ThreatName };"
              "Get-MpThreatDetection -ErrorAction SilentlyContinue | % { 'D|' + $_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm') + '|' + $t[[string]$_.ThreatID] + '|' + ($_.Resources -join ';') };"
              "$p=Get-MpPreference -ErrorAction SilentlyContinue; $p.ExclusionPath | % { 'X|' + $_ }; $p.ExclusionProcess | % { 'X|' + $_ }")
        out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=60)
        for line in out.splitlines():
            parts = line.strip().split("|", 3)
            if parts[0] == "D" and len(parts) == 4:
                when_s, name, res = parts[1], parts[2] or "unknown", parts[3]
                lname = name.lower()
                path_hit = any(self.match_path(r.split("_", 1)[-1]) for r in res.split(";") if r)
                if any(k in lname for k in ("hacktool", "gamehack", "cheat", "injector")) or path_hit:
                    self.add(HIGH, "Defender detected", f"{name}: {res[:200]}", f"Windows Defender caught this on {when_s}")
                else:
                    self.add(INFO, "Defender detected", f"{name}: {res[:200]}", f"Other detection on {when_s}")
            elif parts[0] == "X" and len(parts) == 2 and parts[1] and "N/A" not in parts[1]:
                x = parts[1]
                hit = self.match_path(x)
                user_dirs = ("desktop", "downloads", "temp", "documents", "appdata")
                if hit:
                    self.add(HIGH, "Defender exclusion", x, f"Antivirus is told to ignore this (matched '{hit[1]}')")
                elif any(d in x.lower() for d in user_dirs) or x.lower().endswith(".exe") or re.fullmatch(r"[a-z]:\\?", x.lower()):
                    self.add(MEDIUM, "Defender exclusion", x,
                             "Antivirus is told to ignore this. Hack users often do this; ask why.")
        if not out.strip() and not is_admin():
            self.notes.append("Defender history needs Administrator. Run as admin for this check.")

    # ---- 11. USB drives / phones unplugged (hacks are often carried on a USB and removed before the check)
    def scan_usb(self):
        if not IS_WINDOWS:
            return
        self.status("Checking USB drives and phones that were removed")
        ps = ("Get-PnpDevice -ErrorAction SilentlyContinue | ? { $_.InstanceId -like 'USBSTOR*' -or $_.Class -eq 'WPD' } | % {"
              "$id=$_.InstanceId; $r=(Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_LastRemovalDate' -EA SilentlyContinue).Data;"
              "$a=(Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_LastArrivalDate' -EA SilentlyContinue).Data;"
              "'U|' + $_.FriendlyName + '|' + $_.Present + '|' + $(if($r){$r.ToString('yyyy-MM-dd HH:mm:ss')}) + '|' + $(if($a){$a.ToString('yyyy-MM-dd HH:mm:ss')}) }")
        out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=90)
        now = dt.datetime.now().timestamp()
        for line in out.splitlines():
            parts = line.strip().split("|")
            if len(parts) != 5 or parts[0] != "U":
                continue
            name, present, removed, arrived = parts[1] or "Unknown device", parts[2], parts[3], parts[4]
            if present.lower() == "true":
                continue
            ts = 0
            try:
                ts = dt.datetime.strptime(removed, "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                pass
            if ts and now - ts < 6 * 3600:
                self.add(MEDIUM, "USB device", name,
                         f"Unplugged {removed}, shortly before this scan. Ask the player what was on it.", ts)
            else:
                self.add(INFO, "USB device", name,
                         f"Not connected now. Last removed {removed or 'unknown'}, last plugged in {arrived or 'unknown'}.", ts)

    # ---- 12. system information and accounts on this PC
    def scan_system(self):
        self.status("Collecting system information")
        info = self.system_info
        info.insert(0, ("Game checked", self.game_name))
        info.insert(1, ("Computer name", env("COMPUTERNAME", "?")))
        info.insert(2, ("Windows user", env("USERNAME", "?")))
        info.insert(1, ("Checked", {"pc": "PC + emulator", "phone": "Android phone over USB", "both": "PC + emulator + Android phone"}[self.mode]))
        info.append(("Scanner run as admin", "yes" if is_admin() else "NO (some checks skipped)"))
        if not IS_WINDOWS or self.mode == "phone":
            return
        ps = ("$o=Get-CimInstance Win32_OperatingSystem; $c=Get-CimInstance Win32_ComputerSystem; $p=Get-CimInstance Win32_Processor | select -First 1;"
              "$g=(Get-CimInstance Win32_VideoController | % Name) -join ', ';"
              "'S|Windows|' + $o.Caption + ' ' + $o.Version;"
              "'S|Installed|' + $o.InstallDate.ToString('yyyy-MM-dd HH:mm');"
              "'S|Last restart|' + $o.LastBootUpTime.ToString('yyyy-MM-dd HH:mm');"
              "'S|PC model|' + $c.Manufacturer + ' ' + $c.Model;"
              "'S|CPU|' + $p.Name; 'S|GPU|' + $g;"
              "'S|RAM|' + [math]::Round($c.TotalPhysicalMemory/1GB) + ' GB';"
              "Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | % { 'A|' + $_.Name + '|' + $(if($_.Disabled){'disabled'}else{'enabled'}) }")
        out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=60)
        now = dt.datetime.now()
        for line in out.splitlines():
            parts = line.strip().split("|")
            if parts[0] == "S" and len(parts) == 3:
                label, value = parts[1], parts[2].strip()
                info.append((label, value))
                try:
                    when = dt.datetime.strptime(value, "%Y-%m-%d %H:%M")
                except ValueError:
                    continue
                if label == "Installed" and now - when < dt.timedelta(days=3):
                    self.add(MEDIUM, "System", f"Windows installed {value}",
                             "Windows was installed very recently. A fresh install wipes all history.", when.timestamp())
                if label == "Last restart" and now - when < dt.timedelta(minutes=15):
                    self.add(INFO, "System", f"PC restarted {value}",
                             "PC restarted just before the scan. Running cheats are gone after a restart.", when.timestamp())
                if label == "PC model" and re.search(r"vmware|virtualbox|virtual machine|qemu|hyper-v", value, re.I):
                    self.add(MEDIUM, "System", value, "Scanner is running inside a virtual machine, not on the real PC.")
            elif parts[0] == "A" and len(parts) == 3:
                self.accounts.append(("Windows account", parts[1], parts[2]))
        users_dir = os.path.join(env("SystemDrive", "C:") + os.sep, "Users")
        try:
            for e in os.scandir(users_dir):
                if e.is_dir() and e.name.lower() not in ("public", "default", "default user", "all users", "defaultapppool"):
                    self.accounts.append(("User folder", e.name, f"last changed {fmt_time(e.stat().st_mtime)}"))
        except Exception:
            pass

    # ======================================================================= deep traces
    # Everything below finds traces that stay behind after a hack is deleted or renamed.

    def user_path_gone(self, path):
        """True for a program in a user-writable folder that no longer exists."""
        lp = path.lower()
        name = os.path.basename(lp)
        return (lp.endswith(".exe") and re.search(r"\\downloads\\|\\desktop\\|\\documents\\|\\videos\\|\\pictures\\", lp)
                and not re.search(r"setup|install|update|unins|redist|vc_|driver", name)
                and not os.path.exists(path))

    # ---- 13. NTFS change journal: every file created, renamed or deleted on the drive
    def scan_usn_journal(self):
        if not IS_WINDOWS:
            return
        self.status("Reading the NTFS change journal (finds deleted and renamed files, can take a few minutes)")
        if not is_admin():
            self.notes.append("NTFS journal check needs Administrator.")
            return
        prefilter = re.compile("|".join(rx.pattern for _, _, rx in self.matcher.rules))
        flags = 0x08000000
        for drive in [f"{c}:" for c in "CDEFGH" if os.path.isdir(f"{c}:\\")]:
            q = run(["fsutil", "fsinfo", "volumeinfo", drive + "\\"], timeout=15)
            if "NTFS" not in q:
                continue
            try:
                proc = subprocess.Popen(["fsutil", "usn", "readjournal", drive, "csv"], stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, creationflags=flags)
            except Exception as e:
                self.notes.append(f"Could not read the NTFS journal on {drive}: {e}")
                continue
            header, idx, rows, oldest, pf_deleted, hits = None, {}, 0, None, [], 0
            for raw in proc.stdout:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                if header is None:
                    if "File name" in line and "Reason" in line:
                        header = next(csv.reader([line]))
                        idx = {h.strip().lower(): i for i, h in enumerate(header)}
                    continue
                rows += 1
                try:
                    r = next(csv.reader([line]))
                    name = r[idx["file name"]]
                    reason = r[idx["reason"]]
                    stamp = r[idx["time stamp"]]
                except Exception:
                    continue
                if oldest is None:
                    oldest = stamp
                lname = name.lower()
                if lname.endswith(".pf") and "delete" in reason.lower():
                    pf_deleted.append(stamp)
                if "delete" not in reason.lower() and "rename" not in reason.lower() and "create" not in reason.lower():
                    continue
                if not prefilter.search(lname):
                    continue
                hit = self.matcher.match(name)
                if not hit or (hit[0] == MEDIUM and os.path.splitext(lname)[1] not in SCAN_EXTS):
                    continue
                action = "deleted" if "delete" in reason.lower() else "renamed" if "rename" in reason.lower() else "created"
                when = parse_any_time(stamp)
                self.add(hit[0], "Drive journal", f"{name}  ({drive})",
                         f"File was {action} on {stamp} - matched '{hit[1]}'. The journal keeps this after deletion.", when)
                hits += 1
                if hits > 300:
                    break
            try:
                proc.kill()
            except Exception:
                pass
            self.system_info.append((f"NTFS journal {drive}", f"{rows} records, oldest {oldest or 'unknown'}"))
            if len(pf_deleted) >= 20:
                self.add(HIGH, "Trace cleaning", f"{len(pf_deleted)} Prefetch files deleted ({drive})",
                         f"Run history was wiped (around {pf_deleted[-1]}). Players do this to hide hacks.",
                         parse_any_time(pf_deleted[-1]))
            old_ts = parse_any_time(oldest) if oldest else 0
            if rows and old_ts and time_now() - old_ts < 2 * 86400 and drive == "C:":
                self.add(MEDIUM, "Trace cleaning", f"NTFS journal on {drive} only goes back to {oldest}",
                         "The journal is very short. It may have been deleted to hide file history.", old_ts)

    # ---- 14. Amcache: Windows keeps path + SHA1 of every program that ran, even after deletion
    def scan_amcache(self):
        if not IS_WINDOWS or winreg is None:
            return
        self.status("Reading Amcache (programs that ever ran, with fingerprints)")
        if not is_admin():
            self.notes.append("Amcache check needs Administrator.")
            return
        src = os.path.join(env("WINDIR", r"C:\Windows"), "AppCompat", "Programs", "Amcache.hve")
        tmpdir = os.path.join(env("TEMP", "."), f"ffscan_amc_{os.getpid()}")
        os.makedirs(tmpdir, exist_ok=True)
        copy = os.path.join(tmpdir, "Amcache.hve")
        run(["esentutl.exe", "/y", src, "/vss", "/d", copy], timeout=120)
        if not os.path.isfile(copy):
            try:
                shutil.copy2(src, copy)
            except Exception:
                self.notes.append("Could not copy Amcache (it is locked).")
                shutil.rmtree(tmpdir, ignore_errors=True)
                return
        mount = "FFSCAN_AMCACHE"
        run(["reg", "load", rf"HKLM\{mount}", copy], timeout=30)
        try:
            base = rf"{mount}\Root\InventoryApplicationFile"
            for sub in reg_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
                vals = {n.lower(): d for n, d, _ in reg_values(winreg.HKEY_LOCAL_MACHINE, base + "\\" + sub)}
                path = str(vals.get("lowercaselongpath", ""))
                sha1 = str(vals.get("fileid", ""))[-40:].lower()
                when = 0
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + "\\" + sub) as k:
                        when = filetime_to_ts(winreg.QueryInfoKey(k)[2])
                except OSError:
                    pass
                if sha1 in self.bad_sha1:
                    self.add(HIGH, "Past use (Amcache)", path, f"Fingerprint matches known hack '{self.bad_sha1[sha1]}' (works even if renamed)", when)
                    continue
                hit = self.match_path(path)
                if hit:
                    gone = "" if os.path.exists(path) else " File is no longer on the PC."
                    self.add(hit[0], "Past use (Amcache)", path, f"Program ran - matched '{hit[1]}' (seen {fmt_time(when)}).{gone} SHA1 {sha1}", when)
                elif when >= self.recent_cutoff and self.user_path_gone(path):
                    self.add(MEDIUM, "Run then deleted", path,
                             f"Program ran from a user folder around {fmt_time(when)} and was then deleted. "
                             f"Renamed hacks look like this. SHA1 {sha1} (search it on virustotal.com).", when)
        finally:
            run(["reg", "unload", rf"HKLM\{mount}"], timeout=30)
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ---- 15. ShimCache: another list of programs Windows has seen
    def scan_shimcache(self):
        if winreg is None:
            return
        self.status("Reading ShimCache (programs Windows has seen)")
        data = None
        for name, d, _ in reg_values(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"):
            if name == "AppCompatCache":
                data = d
        if not isinstance(data, bytes):
            return
        for path, when in parse_shimcache(data):
            hit = self.match_path(path)
            if hit:
                gone = "" if os.path.exists(path) else " File is no longer on the PC."
                self.add(hit[0], "Past use (ShimCache)", path, f"Windows saw this program - matched '{hit[1]}' (file date {fmt_time(when)}).{gone}", when)

    # ---- 16. Shellbags: folders opened in Explorer, kept after the folder is deleted
    def scan_shellbags(self):
        if winreg is None:
            return
        self.status("Reading Shellbags (folders that were opened, even if deleted)")
        roots = [r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
                 r"Software\Microsoft\Windows\Shell\BagMRU"]
        seen = set()

        def walk(path, depth):
            if depth > 12:
                return
            for name, data, _ in reg_values(winreg.HKEY_CURRENT_USER, path):
                if isinstance(data, bytes) and name.isdigit():
                    for text in utf16_strings(data, 3) + ascii_strings(data, 4):
                        t = text.strip()
                        if t.lower() in seen:
                            continue
                        seen.add(t.lower())
                        hit = self.matcher.match(t)
                        if hit and hit[0] == HIGH:
                            self.add(HIGH, "Past use (Shellbags)", t,
                                     f"A folder with this name was opened in Explorer - matched '{hit[1]}'. Kept even after the folder is deleted.")
            for sub in reg_subkeys(winreg.HKEY_CURRENT_USER, path):
                walk(path + "\\" + sub, depth + 1)
        for r in roots:
            walk(r, 0)

    # ---- 17. Jump lists and shortcuts: files opened by each app
    def scan_jumplists(self):
        self.status("Reading jump lists and shortcuts (files that were opened)")
        recent = os.path.join(env("APPDATA"), "Microsoft", "Windows", "Recent")
        folders = [recent, os.path.join(recent, "AutomaticDestinations"), os.path.join(recent, "CustomDestinations")]
        seen = set()
        for folder in folders:
            try:
                entries = list(os.scandir(folder))
            except Exception:
                continue
            for e in entries:
                if not e.is_file() or e.stat().st_size > 20 * 1024 * 1024:
                    continue
                try:
                    with open(e.path, "rb") as f:
                        data = f.read()
                except Exception:
                    continue
                when = e.stat().st_mtime
                for text in utf16_strings(data, 6) + ascii_strings(data, 6):
                    if "\\" not in text or text.lower() in seen:
                        continue
                    seen.add(text.lower())
                    hit = self.match_path(text)
                    if hit and (hit[0] == HIGH or os.path.splitext(text.lower())[1] in SCAN_EXTS):
                        gone = "" if os.path.exists(text) else " No longer on the PC."
                        self.add(hit[0], "Past use (Jump list)", text,
                                 f"This file was opened - matched '{hit[1]}' (list updated {fmt_time(when)}).{gone}", when)

    # ---- 18. PowerShell / command history: commands used to wipe traces
    def scan_command_history(self):
        self.status("Checking command history for trace-wiping commands")
        hist = os.path.join(env("APPDATA"), "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
        try:
            with open(hist, encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
            when = os.path.getmtime(hist)
        except Exception:
            return
        hi = [k.lower() for k in self.cfg.get("anti_forensic_high", [])]
        me = [k.lower() for k in self.cfg.get("anti_forensic_medium", [])]
        for line in lines[-5000:]:
            l = line.lower()
            k = next((k for k in hi if k in l), None)
            if k:
                self.add(HIGH, "Trace cleaning", line.strip()[:200], f"Command used to wipe history ('{k}')", when)
                continue
            k = next((k for k in me if k in l), None)
            if k:
                self.add(MEDIUM, "Trace cleaning", line.strip()[:200], f"Command that can hide or delete traces ('{k}')", when)
                continue
            hit = self.matcher.match(l)
            if hit and hit[0] == HIGH:
                self.add(HIGH, "Command history", line.strip()[:200], f"Command mentions '{hit[1]}'", when)

    # ---- 19. Event logs: cleared logs, old Defender alerts, exclusions added then removed, installs
    def scan_event_logs(self):
        if not IS_WINDOWS:
            return
        self.status("Reading Windows event logs (cleared logs, old antivirus alerts)")
        ps = ("$ErrorActionPreference='SilentlyContinue';"
              "function out($e){ $m=($e.Message -replace '\\s+',' '); if($m.Length -gt 700){$m=$m.Substring(0,700)}; 'E|'+$e.Id+'|'+$e.TimeCreated.ToString('yyyy-MM-dd HH:mm')+'|'+$m }"
              "Get-WinEvent -FilterHashtable @{LogName='System';Id=104} -MaxEvents 20 | % { out $_ };"
              "Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 20 | % { out $_ };"
              "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117,5001,5007} -MaxEvents 400 | % { out $_ };"
              "Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='MsiInstaller';Id=11707,1033,1034} -MaxEvents 300 | % { out $_ }")
        out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=120)
        for line in out.splitlines():
            parts = line.strip().split("|", 3)
            if len(parts) != 4 or parts[0] != "E":
                continue
            eid, stamp, msg = parts[1], parts[2], parts[3]
            when = parse_any_time(stamp)
            if eid in ("104", "1102"):
                lvl = HIGH if when >= self.recent_cutoff else MEDIUM
                self.add(lvl, "Trace cleaning", f"Event log cleared {stamp}", "Someone cleared the Windows event logs. Players do this to hide what they ran.", when)
            elif eid in ("1116", "1117"):
                name = re.search(r"Name: ([^ ]+)", msg)
                path = re.search(r"Path: (.+?) Detection Origin", msg)
                label = (name.group(1) if name else "threat") + (f": {path.group(1)}" if path else "")
                lname = label.lower()
                if any(k in lname for k in ("hacktool", "gamehack", "cheat", "injector")) or (path and self.match_path(path.group(1).split("file:_")[-1])):
                    self.add(HIGH, "Defender log", label[:300], f"Defender caught this on {stamp}. The log keeps it even if the Defender history was cleared.", when)
                else:
                    self.add(INFO, "Defender log", label[:300], f"Other Defender detection on {stamp}", when)
            elif eid == "5001":
                self.add(MEDIUM, "Defender log", f"Real-time protection turned off {stamp}", "Antivirus was switched off. Hack users often do this before running a hack.", when)
            elif eid == "5007":
                m = re.search(r"New value: \S*Exclusions\\(Paths|Processes|Extensions)\\(.+?) = ", msg)
                if m:
                    x = m.group(2)
                    hit = self.match_path(x)
                    self.add(HIGH if hit else MEDIUM, "Defender log", f"Exclusion added: {x}",
                             f"On {stamp} the antivirus was told to ignore this (the log keeps it even if the exclusion was removed later)."
                             + (f" Matched '{hit[1]}'." if hit else ""), when)
            else:  # installer events
                hit = self.matcher.match(msg)
                if hit:
                    self.add(hit[0], "Installed (log)", msg[:200], f"Installed or removed on {stamp} - matched '{hit[1]}'", when)

    # ---- 20. Inside the emulator: apps used in the past, uninstalled apps, injected files
    def scan_emulator_history(self):
        if not self.cfg.get("use_adb", True):
            return
        adbs = self.find_adb()
        if not adbs:
            return
        adb = adbs[0]
        devices = self.adb_devices(adb)
        if not devices:
            return
        self.status("Checking Android app history (apps used or uninstalled before)")
        for dev, kind in devices:
            sh = lambda *c, t=30: run([adb, "-s", dev, "shell", *c], timeout=t)
            now_pk = {l[8:].strip().lower() for l in sh("pm", "list", "packages").splitlines() if l.startswith("package:")}
            all_pk = {l[8:].strip().lower() for l in sh("pm", "list", "packages", "-u").splitlines() if l.startswith("package:")}
            usage = set(m.lower() for m in re.findall(r"package=([\w.]+)", sh("dumpsys", "usagestats", t=60)))
            for p in sorted((all_pk - now_pk) | (usage - now_pk)):
                level, why = None, ""
                if any(p.startswith(k) for k in self.pkg_high):
                    level, why = HIGH, "Known cheat app"
                elif any(p.startswith(k) for k in self.pkg_med):
                    level, why = MEDIUM, "Root / hook / clone app"
                else:
                    hit = self.matcher.match(p)
                    if hit:
                        level, why = hit[0], f"Name contains '{hit[1]}'"
                if level:
                    self.add(level, f"{kind} history", f"{p}  ({dev})", f"{why}. It was used or installed before and is now removed.")
            for p in sorted(usage & now_pk):
                pass  # installed apps are already covered by scan_adb
            for folder in ("/data/local/tmp", "/sdcard/Android/data", "/sdcard"):
                for item in sh("ls", "-1a", folder).splitlines():
                    item = item.strip()
                    if not item or item in (".", ".."):
                        continue
                    hit = self.matcher.match(item)
                    if folder == "/data/local/tmp" and not item.startswith("."):
                        self.add(hit[0] if hit else MEDIUM, f"{kind} storage", f"{folder}/{item}  ({dev})",
                                 "File in /data/local/tmp. Injectors and memory tools are pushed here." + (f" Matched '{hit[1]}'." if hit else ""))
                    elif item.startswith(".") and hit:
                        self.add(hit[0], f"{kind} storage", f"{folder}/{item}  ({dev})", f"Hidden file or folder - matched '{hit[1]}'")
            for line in sh("ps", "-A").splitlines()[1:]:
                pname = line.split()[-1] if line.split() else ""
                hit = self.matcher.match(pname)
                if hit and hit[0] == HIGH:
                    self.add(HIGH, f"{kind} process", f"{pname}  ({dev})", f"Running on the {kind.lower()} - matched '{hit[1]}'")

    # ---- 21. Deep scan: search the emulator's virtual disk for traces of deleted cheat apps
    def scan_deep_disk(self):
        if not self.deep:
            return
        pats = [p.lower() for p in self.cfg.get("deep_scan_patterns", [])] + [p for p in self.pkg_high if "." in p]
        pats = sorted(set(pats))
        enc = [(p, both_encodings(p)) for p in pats]
        # an installed app leaves its own folder (/data/app/<package>-xxxx) or apk file name behind;
        # a bare package name also appears in games' own anti-cheat lists, so it is only a lead
        strong = {}
        for p in pats:
            forms = [f"/{p}-", f"{p}.apk", f"/data/data/{p}"] if "." in p else [f"{p}.apk"]
            strong[p] = [both_encodings(x) for x in forms]
        up = env("USERPROFILE", os.path.expanduser("~"))
        pd = env("ProgramData", r"C:\ProgramData")
        pf, pf86 = env("ProgramFiles", r"C:\Program Files"), env("ProgramFiles(x86)", r"C:\Program Files (x86)")
        roots = [os.path.join(pd, "BlueStacks_nxt"), os.path.join(pd, "BlueStacks_msi5"), os.path.join(pd, "BlueStacks"),
                 r"C:\LDPlayer", r"D:\LDPlayer", os.path.join(pf, "Microvirt"), os.path.join(pf86, "Nox"),
                 os.path.join(pf, "Netease"), os.path.join(up, "AppData", "Local", "Nox")]
        images = []
        for r in roots:
            for dirpath, dirs, files in os.walk(r):
                for fn in files:
                    if fn.lower().endswith((".vhd", ".vhdx", ".vmdk", ".vdi", ".img", ".qcow2")):
                        fp = os.path.join(dirpath, fn)
                        try:
                            if os.path.getsize(fp) > 50 * 1024 * 1024:
                                images.append(fp)
                        except Exception:
                            pass
        if not images:
            self.notes.append("Deep scan: no emulator disk images found.")
            return
        for img in images:
            size = os.path.getsize(img)
            self.status(f"Deep scan of emulator disk {os.path.basename(img)} ({size // (1024 * 1024)} MB)")
            found = {}
            done, last = 0, 0.0
            try:
                with open(img, "rb") as f:
                    tail = b""
                    while True:
                        chunk = f.read(32 * 1024 * 1024)
                        if not chunk:
                            break
                        done += len(chunk)
                        now = time.time()
                        if now - last > 1:
                            last = now
                            self.progress(f"Deep scan of emulator disk {os.path.basename(img)}: "
                                          f"{done * 100 // max(1, size)}% of {size // (1024 * 1024)} MB")
                        block = (tail + chunk).lower()
                        for p, (a, u) in enc:
                            if found.get(p) != "strong" and (a in block or u in block):
                                hit = any(sa in block or su in block for sa, su in strong[p])
                                found[p] = "strong" if hit else found.get(p, "weak")
                        tail = chunk[-200:]
            except Exception as e:
                self.notes.append(f"Deep scan could not read {img} ({e}). Close the emulator and scan again.")
                continue
            for p, kind in found.items():
                if kind == "strong":
                    self.add(HIGH, "Emulator disk", f"'{p}' app files in {img}",
                             "The app's install folder or APK name is inside the emulator's virtual disk. "
                             "Leftovers stay here after an app is deleted.")
                else:
                    self.add(MEDIUM, "Emulator disk", f"'{p}' text in {img}",
                             "The name appears inside the emulator's disk, but not as an installed app. Games and "
                             "anti-cheat code also list these names to detect them, so this alone is not proof.")

    def run_all(self):
        steps = [self.scan_processes, self.scan_emulator_modules, self.scan_folders,
                 self.scan_adb, self.scan_history, self.scan_recycle_bin, self.scan_drivers,
                 self.scan_past_registry, self.scan_browsers, self.scan_defender,
                 self.scan_usb, self.scan_system, self.scan_usn_journal, self.scan_amcache,
                 self.scan_shimcache, self.scan_shellbags, self.scan_jumplists, self.scan_command_history,
                 self.scan_event_logs, self.scan_emulator_history, self.scan_deep_disk]
        if self.mode == "phone":
            steps = [self.scan_adb, self.scan_emulator_history, self.scan_system]
        self.step_total = len(steps)
        for i, step in enumerate(steps):
            self.step_no = i
            try:
                step()
            except Exception as e:  # never crash the whole scan
                self.notes.append(f"{step.__name__} failed: {e}")
            self.step_no = i + 1
            if self.on_change:
                self.on_change()
        self.findings = self.clean_findings()
        self.accounts = sorted(set(self.accounts))

    def clean_findings(self):
        """Findings without duplicates, most serious first."""
        uniq, seen = [], set()
        for f in list(self.findings):
            k = (f["area"], f["what"].lower())
            if k in seen:
                continue
            seen.add(k)
            uniq.append(f)
        return sorted(uniq, key=lambda f: (LEVEL_ORDER[f["level"]], f["area"], f["what"]))

    def verdict(self, findings=None):
        levels = {f["level"] for f in (self.findings if findings is None else findings)}
        if HIGH in levels:
            return "SUSPICIOUS", "Hack signs found. Check the items marked HIGH with the player before allowing them to play."
        if MEDIUM in levels:
            return "REVIEW", "No known hack found, but some items need a quick manual look."
        return "CLEAN", "No known hack signatures found. (This is a screening check, not a guarantee.)"


# --------------------------------------------------------------------------- report


FILE_AREAS = {"File", "Folder", "File (hash)", "File (content)", "APK", "APK contents", "Game APK", "Emulator storage", "Phone storage",
              "Deleted file", "Drive journal", "Emulator disk", "Run then deleted"}


def section_of(f):
    if f["area"] in FILE_AREAS:
        return "files"
    if f["area"].startswith("Defender"):
        return "defender"
    if f["area"] == "USB device":
        return "devices"
    return "indications"


def report_data(sc, started, admin, pin, player, run_id="", live=False):
    """The report as the website stores it. live=True: a snapshot taken while the scan is still running."""
    findings = sc.clean_findings() if live else sc.findings
    verdict, summary = sc.verdict(findings)
    data = {
        "schema": "ffscan/1", "version": VERSION, "pin": pin, "player": player, "game": sc.game_name,
        "pc": env("COMPUTERNAME", "pc"), "user": env("USERNAME", "user"),
        "time": started.isoformat(timespec="seconds"), "admin": bool(admin),
        "files_checked": sc.files_checked, "verdict": verdict, "summary": summary,
        "findings": [dict(f, section=section_of(f)) for f in findings],
        "system_info": [[k, str(v)] for k, v in list(sc.system_info)],
        "accounts": [list(a) for a in sorted(set(sc.accounts))], "notes": list(sc.notes),
        "run": run_id,
    }
    if live:
        data["progress"] = {"step": sc.step_no, "total": sc.step_total, "now": sc.current}
    return data


class LiveUploader:
    """Sends what the scan has found so far to the website every few seconds, in the background.

    If the player closes the scanner or pulls the cable halfway, the organizer still has everything
    found up to that point. Network problems never slow down or stop the scan."""

    def __init__(self, server, pin, make_report, every=4):
        self.server, self.pin, self.make_report, self.every = server, pin, make_report, every
        self.wake = threading.Event()
        self.stop_flag = False
        self.last_error = ""
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def changed(self):
        self.wake.set()

    def send(self, stopped=False):
        try:
            report = self.make_report()
            if stopped:
                report["stopped"] = True
            code, data = http_json(f"{self.server}/api/scan", {"pin": self.pin, "live": True, "report": report}, timeout=20)
            self.last_error = "" if code == 200 else data.get("error", f"error {code}")
            return code
        except Exception as e:  # never let live updates break the scan
            self.last_error = str(e)
            return 0

    def loop(self):
        while not self.stop_flag:
            self.wake.wait(30)  # also send a heartbeat during long steps
            if self.stop_flag:
                break
            self.wake.clear()
            if self.send() == 409:  # the final report is already in
                break
            time.sleep(self.every)

    def abort(self):
        """The scanner is being closed mid-scan: send what was found, marked as stopped, right away."""
        self.stop_flag = True
        self.wake.set()
        self.send(stopped=True)

    def close(self, stopped=False):
        """Stop the background loop. stopped=True: tell the site the scan did not finish."""
        self.stop_flag = True
        self.wake.set()
        self.thread.join(timeout=25)
        if stopped:
            self.send(stopped=True)


def write_reports(sc, started, admin, pin, player):
    verdict, summary = sc.verdict()
    stamp = started.strftime("%Y%m%d_%H%M%S")
    pc = env("COMPUTERNAME", "pc")
    user = env("USERNAME", "user")
    out_dir = os.path.join(base_dir(), "reports")
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        out_dir = env("TEMP", ".")
    safe_player = re.sub(r"[^A-Za-z0-9_-]+", "_", player)[:30] or pc
    base = os.path.join(out_dir, f"Scan_{pin}_{safe_player}_{stamp}")

    groups = {"cheats": [f for f in sc.findings if f["level"] == HIGH]}
    for key in ("indications", "files", "defender", "devices"):
        groups[key] = [f for f in sc.findings if section_of(f) == key]
    timeline = sorted((f for f in sc.findings if f["when"] and f["level"] != INFO), key=lambda f: -f["when"])

    # ---- text report
    lines = [f"{APP_NAME} v{VERSION} report",
             f"Session PIN: {pin}   Player: {player or '-'}   Game: {sc.game_name}",
             f"PC: {pc}   User: {user}   Time: {started:%Y-%m-%d %H:%M}   Admin: {'yes' if admin else 'NO'}",
             f"Files checked: {sc.files_checked}", "", f"RESULT: {verdict}", summary]
    titles = {"cheats": "CHEATS FOUND", "indications": "KEY INDICATIONS", "files": "SUSPICIOUS FILES",
              "defender": "DEFENDER HISTORY", "devices": "DEVICES REMOVED"}
    for key, title in titles.items():
        lines += ["", f"== {title} ({len(groups[key])}) =="]
        for f in groups[key]:
            lines.append(f"[{f['level']}] {f['area']}: {f['what']}")
            lines.append(f"        {f['reason']}")
    if timeline:
        lines += ["", "== PAST USE TIMELINE (newest first) =="]
        lines += [f" {fmt_time(f['when'])}  [{f['level']}] {f['area']}: {f['what']}" for f in timeline]
    lines += ["", "== SYSTEM INFORMATION =="] + [f" {k}: {v}" for k, v in sc.system_info]
    lines += ["", "== ACCOUNTS ON THIS PC =="] + [f" {w}: {a} ({d})" for w, a, d in sc.accounts]
    if sc.notes:
        lines += ["", "Notes:"] + [f" - {n}" for n in sc.notes]
    lines += ["", "Signature checks can be bypassed (renamed or private hacks). Use this as a screening aid, not proof."]
    with open(base + ".txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    # ---- html report
    e = html.escape
    badge = {HIGH: "hi", MEDIUM: "me", INFO: "in"}

    def table(items, empty):
        if not items:
            return f"<div class='empty'>{empty}</div>"
        rows = "".join(
            f"<tr><td><span class='b {badge[f['level']]}'>{f['level']}</span></td><td>{e(f['area'])}</td>"
            f"<td class='p'>{e(f['what'])}</td><td>{e(f['reason'])}</td></tr>" for f in items)
        return f"<table><tr><th>Level</th><th>Where</th><th>Item</th><th>Why</th></tr>{rows}</table>"

    vclass = {"SUSPICIOUS": "hi", "REVIEW": "me", "CLEAN": "ok"}[verdict]
    tl_rows = "".join(
        f"<tr><td class='nw'>{fmt_time(f['when'])}</td><td><span class='b {badge[f['level']]}'>{f['level']}</span></td>"
        f"<td>{e(f['area'])}</td><td class='p'>{e(f['what'])}</td></tr>" for f in timeline)
    tl = (f"<table><tr><th>When</th><th>Level</th><th>Where</th><th>Item</th></tr>{tl_rows}</table>"
          if timeline else "<div class='empty'>No dated hack activity found.</div>")
    stat = lambda k, label: f"<a class='stat' href='#' onclick=\"show('{k}');return false\"><b>{len(groups[k])}</b>{label}</a>"
    notes = "".join(f"<li>{e(n)}</li>" for n in sc.notes) or "<li>None</li>"
    sysrows = "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in sc.system_info)
    acc = "".join(f"<tr><td>{e(w)}</td><td class='p'>{e(a)}</td><td>{e(d)}</td></tr>" for w, a, d in sc.accounts)
    acc_tbl = (f"<table><tr><th>Where</th><th>Account</th><th>Detail</th></tr>{acc}</table>" if acc
               else "<div class='empty'>No accounts found.</div>")

    sections = {
        "summary": ("Summary", f"""
<div class='verdict {vclass}'>{verdict}<small>{e(summary)}</small></div>
<div class='stats'>{stat('cheats', 'Cheats found')}{stat('indications', 'Key indications')}{stat('files', 'Suspicious files')}{stat('defender', 'Defender history')}{stat('devices', 'Devices removed')}</div>
<h3>Past use timeline</h3><p class='sub'>When each flagged item was last run, opened, downloaded or deleted, as far as Windows remembers. Newest first.</p>{tl}
<h3>Notes</h3><ul>{notes}</ul>"""),
        "cheats": ("Cheats Found", "<p class='sub'>Strong signs of a cheat: known hack names, programs, apps or files.</p>" + table(groups["cheats"], "No cheats found.")),
        "indications": ("Key Indications", "<p class='sub'>Running programs, run history, browser history, emulator apps and other traces.</p>" + table(groups["indications"], "Nothing found.")),
        "files": ("Suspicious Files", "<p class='sub'>Files, APKs and deleted items with hack names.</p>" + table(groups["files"], "No suspicious files.")),
        "defender": ("Defender History", "<p class='sub'>What Windows Defender caught before, and folders it was told to ignore.</p>" + table(groups["defender"], "No Defender history found (needs Administrator).")),
        "devices": ("Devices Removed", "<p class='sub'>USB drives and phones that were plugged in before but are not connected now.</p>" + table(groups["devices"], "No removed devices found.")),
        "system": ("System Information", f"<table class='kv'>{sysrows}</table>"),
        "accounts": ("Alt Accounts", "<p class='sub'>Windows accounts on this PC and Google accounts signed in to the emulator. More than one may mean a second (alt) account.</p>" + acc_tbl),
    }
    counts = {k: len(v) for k, v in groups.items()}
    counts["system"], counts["accounts"] = len(sc.system_info), len(sc.accounts)

    def nav(k):
        n = counts.get(k)
        cnt = f"<span class='n{' red' if k == 'cheats' and n else ''}'>{n}</span>" if n is not None else ""
        return f"<a id='nav-{k}' href='#' onclick=\"show('{k}');return false\">{sections[k][0]}{cnt}</a>"

    body = "".join(f"<section id='sec-{k}'><h2>{t}</h2>{c}</section>" for k, (t, c) in sections.items())
    page = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scan {pin} {e(player)}</title><style>
:root{{--bg:#0d1117;--side:#111820;--card:#161d26;--line:#253040;--tx:#e6edf3;--mut:#8b98a5;--acc:#3ddc84;--hi:#ff5252;--me:#ffab40;--in:#78909c}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 Segoe UI,Arial,sans-serif;display:flex;min-height:100vh}}
aside{{width:250px;background:var(--side);border-right:1px solid var(--line);padding:18px 14px;flex-shrink:0;position:sticky;top:0;height:100vh;overflow:auto}}
.logo{{font-size:20px;font-weight:700;color:var(--acc);margin-bottom:18px}}.logo span{{color:var(--tx)}}
.grp{{font-size:11px;letter-spacing:.12em;color:var(--mut);margin:18px 8px 6px;text-transform:uppercase}}
aside a{{display:flex;justify-content:space-between;color:var(--tx);text-decoration:none;padding:8px 10px;border-radius:6px;border-left:3px solid transparent}}
aside a:hover{{background:#1b2532}}aside a.on{{background:#14301f;color:var(--acc);border-left-color:var(--acc)}}
.n{{color:var(--mut)}}.n.red{{color:var(--hi);font-weight:700}}
main{{flex:1;padding:26px 32px;max-width:1200px;min-width:0}}
.head{{display:flex;flex-wrap:wrap;gap:22px;align-items:flex-end;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:18px}}
.pin{{font:700 34px Consolas,monospace;color:var(--acc);letter-spacing:.06em}}.lbl{{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.1em}}
section{{display:none}}section.on{{display:block}}h2{{margin:0 0 10px}}h3{{margin:24px 0 6px}}.sub{{color:var(--mut);margin:0 0 12px}}
.verdict{{padding:18px 22px;border-radius:10px;font-size:28px;font-weight:700}}.verdict small{{display:block;font-size:15px;font-weight:400;margin-top:4px}}
.verdict.hi{{background:#4a1515;color:#ffb4b4}}.verdict.me{{background:#4a3210;color:#ffd699}}.verdict.ok{{background:#123a22;color:#9df0bf}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:14px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;color:var(--mut);text-decoration:none}}.stat b{{display:block;font-size:26px;color:var(--tx)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden}}
td,th{{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{color:var(--mut);font-weight:600}}
.kv th{{width:220px}}.p{{font-family:Consolas,monospace;font-size:13px;word-break:break-all}}.nw{{white-space:nowrap}}
.b{{font-size:11px;font-weight:700;padding:2px 7px;border-radius:4px}}.b.hi{{background:#5c1b1b;color:#ff8a8a}}.b.me{{background:#5c3d12;color:#ffc46b}}.b.in{{background:#263238;color:#b0bec5}}
.empty{{background:var(--card);border:1px dashed var(--line);border-radius:8px;padding:22px;color:var(--mut);text-align:center}}
.foot{{color:var(--mut);font-size:12px;margin-top:30px}}
@media(max-width:760px){{body{{display:block}}aside{{width:auto;height:auto;position:static}}main{{padding:16px}}}}
</style></head><body>
<aside><div class="logo">FF<span> Scanner</span></div>
<div class="grp">Forensic report</div>{nav('summary')}
<div class="grp">Findings</div>{nav('cheats')}{nav('indications')}{nav('files')}{nav('defender')}{nav('devices')}
<div class="grp">Context</div>{nav('system')}{nav('accounts')}</aside>
<main><div class="head">
<div><div class="lbl">Session PIN</div><div class="pin">{pin}</div></div>
<div><div class="lbl">Player</div><b>{e(player or '-')}</b></div>
<div><div class="lbl">Game</div><b>{e(sc.game_name)}</b></div>
<div><div class="lbl">PC</div><b>{e(pc)}</b> ({e(user)})</div>
<div><div class="lbl">Scanned</div><b>{started:%Y-%m-%d %H:%M}</b></div>
<div><div class="lbl">Files checked</div><b>{sc.files_checked}</b></div></div>
{body}
<p class="foot">{APP_NAME} v{VERSION}. Read-only scan. Signature checks can be bypassed (renamed or private hacks, cleaned traces), so use this report as a screening aid, not as proof.</p>
</main><script>
function show(k){{document.querySelectorAll('section').forEach(s=>s.classList.toggle('on',s.id==='sec-'+k));
document.querySelectorAll('aside a').forEach(a=>a.classList.toggle('on',a.id==='nav-'+k));window.scrollTo(0,0)}}
show('summary');
</script></body></html>"""
    with open(base + ".html", "w", encoding="utf-8") as fh:
        fh.write(page)

    # ---- json report, for uploading to the web dashboard
    data = report_data(sc, started, admin, pin, player)
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
    return base + ".html", base + ".txt", verdict, summary


# --------------------------------------------------------------------------- main


def load_config():
    path = os.path.join(base_dir(), "signatures.json")
    if not os.path.isfile(path) and getattr(sys, "frozen", False):
        bundled = os.path.join(getattr(sys, "_MEIPASS", base_dir()), "signatures.json")
        if os.path.isfile(bundled):
            try:  # copy the default list next to the exe so organizers can edit it
                with open(bundled, "rb") as s, open(path, "wb") as d:
                    d.write(s.read())
            except Exception:
                path = bundled
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def bundled_setting(name):
    """A value from the signatures.json built into the exe (an older copy next to the exe may lack it)."""
    try:
        with open(os.path.join(getattr(sys, "_MEIPASS", base_dir()), "signatures.json"), encoding="utf-8") as f:
            return json.load(f).get(name)
    except Exception:
        return None


def arg_value(name):
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


def pick_game(cfg, interactive):
    games = cfg.get("games", {})
    keys = list(games)
    chosen = arg_value("--game")
    if chosen:
        if chosen == "all":
            return keys
        if chosen in games:
            return [chosen]
        print(f"  Unknown game '{chosen}'. Choose from: {', '.join(keys)}, all")
    if not interactive:
        return keys[:1]
    print("  Select the game to check:\n")
    for i, k in enumerate(keys, 1):
        print(f"    {i}. {games[k]['name']}")
    print(f"    {len(keys) + 1}. All games\n")
    while True:
        ans = input(f"  Enter number (1-{len(keys) + 1}) [1]: ").strip() or "1"
        if ans.isdigit() and 1 <= int(ans) <= len(keys) + 1:
            n = int(ans)
            return keys if n == len(keys) + 1 else [keys[n - 1]]
        print("  Please type one of the numbers above.")


def http_json(url, payload=None, timeout=30):
    """GET (payload None) or POST JSON. Returns (status, dict)."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": f"FFScanner/{VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": f"Could not reach the website ({e})"}


def device_id():
    """A hash of this PC's Windows install ID, so the organizer's report can tell the same PC scanned twice."""
    raw = ""
    if IS_WINDOWS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                raw = winreg.QueryValueEx(k, "MachineGuid")[0]
        except Exception:
            pass
    raw = raw or env("COMPUTERNAME", "pc")
    return hashlib.sha256(("ffscan:" + raw).encode("utf-8")).hexdigest()[:32]


def start_scan(server, pin):
    """Tell the website the scan is starting. It counts one device on the organizer's monthly plan
    and refuses when the plan has run out. Returns (ok, message)."""
    code, data = http_json(f"{server}/api/scan", {"pin": pin, "start": True, "device": device_id()}, timeout=30)
    if code == 200:
        return True, ""
    return False, data.get("error") or f"Could not start the scan (error {code})."


def offline_allowed():
    """Scanning without a PIN is only for development from the source code. The exe always needs a
    PIN from an organizer with an active plan."""
    return not getattr(sys, "frozen", False)


def online_session(server, interactive):
    """Ask for the organizer's session PIN and fetch its settings. Returns the session dict or None."""
    pin = arg_value("--pin")
    if pin is None and getattr(sys, "frozen", False):
        # the website names each download FFScanner-<PIN>.exe, so the player doesn't have to type it
        m = re.search(r"(?<!\d)(\d{8})(?!\d)", os.path.basename(sys.executable))
        if m:
            pin = m.group(1)
            print(f"  Session PIN {pin} (from the download)")
    ask = "  Session PIN from the organizer" + (" (press Enter to scan offline): " if offline_allowed() else ": ")
    for attempt in range(3):
        if pin is None:
            if not interactive:
                return None
            pin = input(ask).strip().replace(" ", "")
        if not pin and offline_allowed():
            return None
        if re.fullmatch(r"\d{8}", pin or ""):
            code, data = http_json(f"{server}/api/scan?pin={pin}")
            if code == 200 and data.get("status") != "done":
                return data
            msg = "This PIN was already used. Ask the organizer for a new one." if code == 200 else data.get("error", f"Error {code}")
        else:
            msg = "The PIN is 8 digits."
        print(f"  {msg}")
        pin = None
        if not interactive:
            return None
    if offline_allowed():
        print("  Continuing offline. Upload the .json report to the website by hand later.")
    return None


def relaunch_as_admin():
    """Windows: start this exe again with the 'Run as administrator' prompt. True if the new copy started."""
    if not IS_WINDOWS or is_admin() or "--no-elevate" in sys.argv:
        return False
    if getattr(sys, "frozen", False):
        exe, args = sys.executable, sys.argv[1:]
    else:
        exe, args = sys.executable, [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    params = subprocess.list2cmdline(args + ["--no-elevate"])
    try:
        # 'runas' shows the Windows admin prompt; returns > 32 when the new process started
        return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32
    except Exception:
        return False  # the player said No: carry on without admin (some checks are skipped)


def main():
    if relaunch_as_admin():
        return 0
    if "--cli" not in sys.argv and (getattr(sys, "frozen", False) or "--gui" in sys.argv):
        try:
            import ff_gui
        except Exception as e:  # no window support: fall back to the text version
            print(f"  Window could not open ({e}); using the text version.")
        else:
            return ff_gui.run()
    if IS_WINDOWS:
        os.system("")  # enable ANSI colours in the console
    red, orange, green, reset = "\033[91m", "\033[93m", "\033[92m", "\033[0m"
    print(f"\n  {APP_NAME} v{VERSION}  -  PC, emulator and phone cheat screening (read-only)\n")
    interactive = "--no-pause" not in sys.argv
    try:
        cfg = load_config()
    except Exception as e:
        print(f"  Could not read signatures.json: {e}")
        if interactive:
            input("\n  Press Enter to close...")
        return 2
    server = (arg_value("--server") or cfg.get("server_url") or bundled_setting("server_url") or "").rstrip("/")
    offline = "--offline" in sys.argv and offline_allowed()
    session = online_session(server, interactive) if server and not offline else None
    if session:
        ok, msg = start_scan(server, session["pin"])
        if not ok:
            print(f"  {red}{msg}{reset}")
            session = None
    if not session and not offline_allowed():
        print(f"  {red}This scanner needs a session PIN from a tournament organizer with an active FF Scanner plan.{reset}")
        if interactive:
            input("\n  Press Enter to close...")
        return 2
    if session:
        games = cfg.get("games", {})
        game_keys = list(games) if session.get("game") == "all" else [session["game"]] if session.get("game") in games else list(games)[:1]
        print(f"  Session found: {session.get('player') or 'player'} - {session.get('gameName')}")
        if session.get("mode") in ("pc", "phone", "both") and "--mode" not in sys.argv:
            sys.argv += ["--mode", session["mode"]]
        if session.get("player") and "--player" not in sys.argv:
            sys.argv += ["--player", session["player"]]
    else:
        game_keys = pick_game(cfg, interactive)
    mode = arg_value("--mode")
    if mode not in ("pc", "phone", "both"):
        mode = "pc"
        if interactive and arg_value("--mode") is None:
            print("\n  What are you checking?\n\n    1. This PC and its emulator\n    2. An Android phone plugged in by USB\n    3. Both\n")
            ans = input("  Enter number (1-3) [1]: ").strip()
            mode = {"2": "phone", "3": "both"}.get(ans, "pc")
    if mode != "pc":
        print("\n  On the phone: Settings > About phone > tap 'Build number' 7 times, then Settings > Developer options >"
              "\n  turn on 'USB debugging'. Plug it in and tap 'Allow' when the phone asks.")
    player = arg_value("--player")
    if player is None:
        player = input("\n  Player name / in-game ID (optional): ").strip() if interactive else ""
    pin = session["pin"] if session else f"{random.SystemRandom().randint(0, 99999999):08d}"
    print(f"\n  SESSION PIN: {green}{pin}{reset}   (write this next to the player's name)\n")
    deep = "--deep" in sys.argv
    if not deep and interactive and mode != "phone":
        deep = input("  Deep scan of the emulator's virtual disk? Finds deleted cheat apps, takes longer. (y/N): ").strip().lower() in ("y", "yes")
    admin = is_admin()
    if not admin:
        print(f"  {orange}Not running as Administrator: some checks will be skipped.{reset}\n")
    started = dt.datetime.now()
    sc = Scanner(cfg, game_keys)
    sc.deep = deep
    sc.mode = mode
    print(f"  Checking for: {sc.game_name}\n")
    run_id = f"{random.SystemRandom().randint(0, 2**32):08x}"
    live = None
    if session:
        live = LiveUploader(server, pin, lambda: report_data(sc, started, admin, pin, player, run_id, live=True))
        sc.on_change = live.changed
        print("  The organizer can follow this scan live on the website.\n")
    try:
        sc.run_all()
    except KeyboardInterrupt:
        if live:
            live.close(stopped=True)
        raise
    if live:
        live.close()
    html_path, txt_path, verdict, summary = write_reports(sc, started, admin, pin, player)
    col = {"SUSPICIOUS": red, "REVIEW": orange, "CLEAN": green}[verdict]
    print(f"\n  RESULT: {col}{verdict}{reset}   (PIN {pin})\n  {summary}\n")
    for f in sc.findings[:25]:
        c = red if f["level"] == HIGH else orange if f["level"] == MEDIUM else ""
        print(f"  {c}[{f['level']}]{reset} {f['area']}: {f['what']}\n         {f['reason']}")
    if len(sc.findings) > 25:
        print(f"  ... and {len(sc.findings) - 25} more in the report")
    print(f"\n  Report saved: {html_path}")
    json_path = html_path[:-5] + ".json"
    if session:
        print("  Sending the result to the organizer...")
        try:
            with open(json_path, encoding="utf-8") as fh:
                report = json.load(fh)
        except Exception as e:
            report = None
            print(f"  {red}Could not read the report: {e}{reset}")
        if report is not None:
            report["run"] = run_id
            code, data = http_json(f"{server}/api/scan", {"pin": pin, "report": report}, timeout=60)
            if code == 200:
                print(f"  {green}Sent. The organizer can see the result now.{reset}")
            else:
                print(f"  {red}Not sent: {data.get('error', code)}{reset}\n  Give the organizer this file instead: {json_path}")
    else:
        print(f"  Upload {os.path.basename(json_path)} to the web dashboard to keep all scans in one place.")
    if IS_WINDOWS and "--no-open" not in sys.argv:
        try:
            os.startfile(html_path)
        except Exception:
            pass
    if interactive:
        input("\n  Press Enter to close...")
    return {"SUSPICIOUS": 1, "REVIEW": 0, "CLEAN": 0}[verdict]


if __name__ == "__main__":
    sys.exit(main())
