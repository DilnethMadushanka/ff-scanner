"""
FF Scanner window. Same checks as the command-line scanner, with a simple screen:
pick the session (or game), press Start, watch the progress, read the result.
"""

import datetime as dt
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
from tkinter import ttk

import ff_scanner as core

BG, PANEL, RAISED, LINE = "#0f1411", "#161d19", "#1d2620", "#2a362f"
FG, MUT, ACCENT, ACCENT_DK = "#e4ece6", "#93a399", "#4cc97f", "#173524"
HI, ME, OK = "#ff7a70", "#f2a94b", "#5fd28f"
VERDICT = {"SUSPICIOUS": (HI, "#3d1715"), "REVIEW": (ME, "#3a2810"), "CLEAN": (OK, "#163322")}
FONT = "Segoe UI"
MONO = "Consolas"
MODES = [("pc", "This PC and its emulator"), ("phone", "Android phone plugged in by USB"), ("both", "PC and phone")]


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.session = None
        self.html_path = None
        try:
            self.cfg = core.load_config()
        except Exception as e:
            self.cfg = None
            self.load_error = str(e)
        self.server = (core.arg_value("--server") or (self.cfg or {}).get("server_url") or core.bundled_setting("server_url") or "").rstrip("/")
        self.games = (self.cfg or {}).get("games", {})
        self.admin = core.is_admin()

        root.title(f"FF Scanner {core.VERSION}")
        root.configure(bg=BG)
        root.geometry("640x700")
        root.minsize(560, 620)
        self.style()

        wrap = tk.Frame(root, bg=BG)
        wrap.pack(fill="both", expand=True, padx=22, pady=18)
        head = tk.Frame(wrap, bg=BG)
        head.pack(fill="x")
        tk.Label(head, text="FF", font=(FONT, 20, "bold"), fg=FG, bg=BG).pack(side="left")
        tk.Label(head, text=" Scanner", font=(FONT, 20, "bold"), fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(head, text=f"v{core.VERSION}", font=(FONT, 10), fg=MUT, bg=BG).pack(side="left", padx=(8, 0), pady=(8, 0))
        tk.Label(wrap, text="Tournament anti-cheat check. Read-only: nothing is changed or deleted on this PC.",
                 font=(FONT, 10), fg=MUT, bg=BG, anchor="w", justify="left", wraplength=580).pack(fill="x", pady=(2, 12))

        self.body = tk.Frame(wrap, bg=BG)
        self.body.pack(fill="both", expand=True)
        if self.cfg is None:
            self.message(f"Could not read signatures.json: {self.load_error}")
            return
        self.setup_screen()
        root.after(100, self.poll)

    # ------------------------------------------------------------------ look
    def style(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure("TCombobox", fieldbackground=RAISED, background=RAISED, foreground=FG, arrowcolor=FG,
                    bordercolor=LINE, lightcolor=RAISED, darkcolor=RAISED, padding=6)
        s.map("TCombobox", fieldbackground=[("readonly", RAISED), ("disabled", PANEL)],
              foreground=[("disabled", MUT)], selectbackground=[("readonly", RAISED)], selectforeground=[("readonly", FG)])
        self.root.option_add("*TCombobox*Listbox.background", RAISED)
        self.root.option_add("*TCombobox*Listbox.foreground", FG)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT_DK)
        s.configure("Green.Horizontal.TProgressbar", troughcolor=RAISED, background=ACCENT, bordercolor=LINE,
                    lightcolor=ACCENT, darkcolor=ACCENT, thickness=10)

    def clear(self):
        for w in self.body.winfo_children():
            w.destroy()

    def card(self, parent=None, **pack):
        f = tk.Frame(parent or self.body, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        f.pack(**({"fill": "x", "pady": (0, 12)} | pack))
        inner = tk.Frame(f, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=16, pady=14)
        return inner

    def label(self, parent, text, size=10, color=MUT, bold=False, **kw):
        return tk.Label(parent, text=text, font=(FONT, size, "bold" if bold else "normal"), fg=color, bg=parent["bg"],
                        anchor="w", justify="left", **kw)

    def button(self, parent, text, cmd, primary=False):
        b = tk.Button(parent, text=text, command=cmd, font=(FONT, 11, "bold"), relief="flat", cursor="hand2",
                      bg=ACCENT if primary else RAISED, fg=BG if primary else FG,
                      activebackground="#3fb06d" if primary else LINE, activeforeground=BG if primary else FG,
                      padx=18, pady=8, bd=0, highlightthickness=0)
        return b

    def message(self, text):
        self.clear()
        c = self.card()
        self.label(c, text, 11, FG, wraplength=560).pack(fill="x")

    # ------------------------------------------------------------------ screen 1: setup
    def setup_screen(self):
        self.clear()
        c = self.card()
        self.label(c, "SESSION PIN", 9, MUT, True).pack(fill="x")
        row = tk.Frame(c, bg=PANEL)
        row.pack(fill="x", pady=(4, 2))
        self.pin_var = tk.StringVar()
        self.pin_entry = tk.Entry(row, textvariable=self.pin_var, font=(MONO, 22, "bold"), width=10, fg=ACCENT,
                                  bg=RAISED, insertbackground=FG, relief="flat", highlightthickness=1,
                                  highlightbackground=LINE, highlightcolor=ACCENT,
                                  disabledbackground=RAISED, disabledforeground=ACCENT)
        self.pin_entry.pack(side="left", ipady=4)
        self.check_btn = self.button(row, "Use PIN", self.lookup_pin)
        self.check_btn.pack(side="left", padx=(10, 0))
        self.session_lbl = self.label(c, "Type the 8-digit PIN from the organizer, or leave it empty to scan offline.",
                                      10, MUT, wraplength=560)
        self.session_lbl.pack(fill="x", pady=(6, 0))
        if not self.server:
            self.pin_entry.configure(state="disabled")
            self.check_btn.configure(state="disabled")
            self.session_lbl.configure(text="This scanner is not linked to a website. Choose the game below and scan offline.")

        c2 = self.card()
        grid = tk.Frame(c2, bg=PANEL)
        grid.pack(fill="x")
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        self.label(grid, "Game", 9, MUT, True).grid(row=0, column=0, sticky="w")
        self.label(grid, "What to check", 9, MUT, True).grid(row=0, column=1, sticky="w", padx=(12, 0))
        names = [g["name"] for g in self.games.values()] + ["All games"]
        self.game_box = ttk.Combobox(grid, values=names, state="readonly", font=(FONT, 11))
        self.game_box.current(0)
        self.game_box.grid(row=1, column=0, sticky="ew", pady=(4, 10))
        self.mode_box = ttk.Combobox(grid, values=[m[1] for m in MODES], state="readonly", font=(FONT, 11))
        self.mode_box.current(0)
        self.mode_box.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(4, 10))
        self.label(grid, "Player name or in-game ID", 9, MUT, True).grid(row=2, column=0, columnspan=2, sticky="w")
        self.player_var = tk.StringVar()
        self.player_entry = tk.Entry(grid, textvariable=self.player_var, font=(FONT, 11), bg=RAISED, fg=FG,
                                     insertbackground=FG, relief="flat", highlightthickness=1,
                                     highlightbackground=LINE, highlightcolor=ACCENT)
        self.player_entry.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 10), ipady=6)
        self.deep_var = tk.BooleanVar(value=False)
        tk.Checkbutton(grid, text="Deep scan of the emulator disk (finds deleted cheat apps, takes longer)",
                       variable=self.deep_var, font=(FONT, 10), fg=FG, bg=PANEL, selectcolor=RAISED,
                       activebackground=PANEL, activeforeground=FG, anchor="w").grid(row=4, column=0, columnspan=2, sticky="w")
        self.phone_hint = self.label(c2, "", 9, ME, wraplength=560)
        self.phone_hint.pack(fill="x", pady=(8, 0))
        self.mode_box.bind("<<ComboboxSelected>>", lambda e: self.update_hint())

        if not self.admin:
            self.label(self.body, "Not running as administrator, so some checks will be skipped. "
                                  "Close this and choose Run as administrator.", 10, ME, wraplength=580).pack(fill="x", pady=(0, 10))
        self.start_btn = self.button(self.body, "Start scan", self.start, primary=True)
        self.start_btn.pack(fill="x", ipady=4)

        pin = core.arg_value("--pin")
        if pin is None and getattr(sys, "frozen", False):
            m = re.search(r"(?<!\d)(\d{8})(?!\d)", os.path.basename(sys.executable))
            pin = m.group(1) if m else None
        if pin and self.server:
            self.pin_var.set(pin)
            self.lookup_pin()

    def update_hint(self):
        mode = MODES[self.mode_box.current()][0]
        self.phone_hint.configure(text="" if mode == "pc" else
                                  "On the phone: Settings > About phone > tap Build number 7 times, then Developer options > "
                                  "USB debugging on. Plug it in and tap Allow on the phone.")

    def lookup_pin(self):
        pin = self.pin_var.get().strip().replace(" ", "")
        if not pin:
            return
        if not re.fullmatch(r"\d{8}", pin):
            self.session_lbl.configure(text="The PIN is 8 digits.", fg=HI)
            return
        self.session_lbl.configure(text="Checking the PIN...", fg=MUT)
        self.check_btn.configure(state="disabled")
        threading.Thread(target=lambda: self.q.put(("session", pin, *core.http_json(f"{self.server}/api/scan?pin={pin}"))),
                         daemon=True).start()

    def apply_session(self, pin, code, data):
        self.check_btn.configure(state="normal")
        if code == 200 and data.get("status") == "done":
            self.session, msg, color = None, "This PIN was already used. Ask the organizer for a new one.", HI
        elif code == 200:
            self.session = data
            msg = f"Session found: {data.get('player') or 'player'} - {data.get('gameName')}. The result is sent to the organizer."
            color = OK
            keys = list(self.games)
            if data.get("game") == "all":
                self.game_box.current(len(keys))
            elif data.get("game") in keys:
                self.game_box.current(keys.index(data["game"]))
            modes = [m[0] for m in MODES]
            if data.get("mode") in modes:
                self.mode_box.current(modes.index(data["mode"]))
            if data.get("player"):
                self.player_var.set(data["player"])
            for w in (self.game_box, self.mode_box):
                w.configure(state="disabled")
            self.pin_entry.configure(state="disabled")
            self.check_btn.configure(state="disabled")
            self.update_hint()
        else:
            self.session, msg, color = None, data.get("error") or f"Could not check the PIN (error {code}).", HI
        self.session_lbl.configure(text=msg, fg=color)

    # ------------------------------------------------------------------ screen 2: progress
    def start(self):
        if self.pin_var.get().strip() and not self.session and self.server:
            self.session_lbl.configure(text="Press Use PIN first, or clear the PIN to scan offline.", fg=HI)
            return
        keys = list(self.games)
        gi = self.game_box.current()
        game_keys = keys if gi >= len(keys) else [keys[gi]]
        mode = MODES[self.mode_box.current()][0]
        player = self.player_var.get().strip()
        deep = self.deep_var.get() and mode != "phone"
        pin = self.session["pin"] if self.session else f"{core.random.SystemRandom().randint(0, 99999999):08d}"

        self.clear()
        c = self.card()
        self.label(c, "SCANNING", 9, MUT, True).pack(fill="x")
        self.step_lbl = self.label(c, "Starting...", 12, FG, True, wraplength=560)
        self.step_lbl.pack(fill="x", pady=(4, 10))
        self.bar = ttk.Progressbar(c, style="Green.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.bar.pack(fill="x")
        self.count_lbl = self.label(c, "", 9, MUT)
        self.count_lbl.pack(fill="x", pady=(6, 0))
        lc = self.card(pady=(0, 0), fill="both", expand=True)
        self.log = tk.Text(lc, font=(FONT, 10), bg=PANEL, fg=MUT, relief="flat", height=14, wrap="word",
                           highlightthickness=0, bd=0)
        self.log.pack(fill="both", expand=True)
        self.log.tag_configure("done", foreground=MUT)
        self.log.tag_configure("now", foreground=FG)
        self.label(self.body, "Keep this window open. A full scan can take a few minutes.", 9, MUT).pack(fill="x", pady=(8, 0))
        self.steps_seen = 0
        threading.Thread(target=self.worker, args=(game_keys, mode, player, deep, pin), daemon=True).start()

    def worker(self, game_keys, mode, player, deep, pin):
        try:
            started = dt.datetime.now()
            sc = core.Scanner(self.cfg, game_keys)
            sc.mode, sc.deep = mode, deep
            sc.status = lambda msg: self.q.put(("step", msg))
            total = 3 if mode == "phone" else 21
            self.q.put(("total", total))
            sc.run_all()
            self.q.put(("step", "Writing the report"))
            html_path, txt_path, verdict, summary = core.write_reports(sc, started, self.admin, pin, player)
            sent = None
            if self.session:
                self.q.put(("step", "Sending the result to the organizer"))
                with open(html_path[:-5] + ".json", encoding="utf-8") as fh:
                    report = json.load(fh)
                code, data = core.http_json(f"{self.server}/api/scan", {"pin": pin, "report": report}, timeout=60)
                sent = (code == 200, data.get("error", f"error {code}") if code != 200 else "")
            self.q.put(("done", sc, verdict, summary, html_path, pin, sent))
        except Exception as e:
            self.q.put(("error", str(e)))

    def poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                kind = item[0]
                if kind == "session":
                    self.apply_session(*item[1:])
                elif kind == "total":
                    self.total = item[1]
                elif kind == "step":
                    msg = item[1]
                    self.steps_seen += 1
                    self.step_lbl.configure(text=msg)
                    self.bar["value"] = min(97, self.steps_seen * 100 / max(1, getattr(self, "total", 20) + 2))
                    self.log.tag_remove("now", "1.0", "end")
                    self.log.insert("end", ("\n" if self.steps_seen > 1 else "") + "✓  " + msg, "now")
                    self.log.see("end")
                elif kind == "done":
                    self.result_screen(*item[1:])
                elif kind == "error":
                    self.message(f"The scan stopped with an error: {item[1]}")
        except queue.Empty:
            pass
        self.root.after(120, self.poll)

    # ------------------------------------------------------------------ screen 3: result
    def result_screen(self, sc, verdict, summary, html_path, pin, sent):
        self.html_path = html_path
        self.clear()
        fg, bg = VERDICT[verdict]
        banner = tk.Frame(self.body, bg=bg)
        banner.pack(fill="x", pady=(0, 12))
        tk.Label(banner, text=verdict, font=(FONT, 26, "bold"), fg=fg, bg=bg, anchor="w").pack(fill="x", padx=18, pady=(14, 0))
        tk.Label(banner, text=summary, font=(FONT, 10), fg=fg, bg=bg, anchor="w", justify="left",
                 wraplength=560).pack(fill="x", padx=18, pady=(0, 14))

        stats = tk.Frame(self.body, bg=BG)
        stats.pack(fill="x", pady=(0, 12))
        groups = {"Cheats found": sum(f["level"] == core.HIGH for f in sc.findings),
                  "To review": sum(f["level"] == core.MEDIUM for f in sc.findings),
                  "Files checked": sc.files_checked}
        for i, (name, n) in enumerate(groups.items()):
            box = tk.Frame(stats, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
            box.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0))
            stats.columnconfigure(i, weight=1)
            color = HI if name == "Cheats found" and n else FG
            tk.Label(box, text=str(n), font=(FONT, 20, "bold"), fg=color, bg=PANEL, anchor="w").pack(fill="x", padx=12, pady=(8, 0))
            tk.Label(box, text=name, font=(FONT, 9), fg=MUT, bg=PANEL, anchor="w").pack(fill="x", padx=12, pady=(0, 8))

        btns = tk.Frame(self.body, bg=BG)
        btns.pack(side="bottom", fill="x")
        self.button(btns, "Open full report", self.open_report, primary=True).pack(side="left")
        self.button(btns, "Close", self.root.destroy).pack(side="right")
        if sent is not None:
            ok, err = sent
            self.label(self.body, "Sent to the organizer." if ok else f"Not sent: {err}. Give the organizer the .json file "
                       f"from the reports folder.", 10, OK if ok else HI, wraplength=580).pack(side="bottom", fill="x", pady=(0, 10))
        c = self.card(pady=(0, 12), fill="both", expand=True)
        self.label(c, f"SESSION PIN  {pin}", 9, MUT, True).pack(fill="x")
        top = [f for f in sc.findings if f["level"] in (core.HIGH, core.MEDIUM)][:3]
        if top:
            for f in top:
                row = tk.Frame(c, bg=PANEL)
                row.pack(fill="x", pady=(8, 0))
                tk.Label(row, text=f["level"], font=(FONT, 8, "bold"), fg=HI if f["level"] == core.HIGH else ME,
                         bg=PANEL, width=8, anchor="w").pack(side="left", anchor="n")
                txt = tk.Frame(row, bg=PANEL)
                txt.pack(side="left", fill="x", expand=True)
                what = f["what"] if len(f["what"]) < 70 else "..." + f["what"][-67:]
                tk.Label(txt, text=f"{f['area']}: {what}", font=(FONT, 10), fg=FG, bg=PANEL, anchor="w",
                         justify="left", wraplength=470).pack(fill="x")
                tk.Label(txt, text=f["reason"][:120], font=(FONT, 9), fg=MUT, bg=PANEL, anchor="w",
                         justify="left", wraplength=470).pack(fill="x")
            more = len([f for f in sc.findings if f["level"] != core.INFO]) - len(top)
            if more > 0:
                self.label(c, f"...and {more} more in the full report.", 9, MUT).pack(fill="x", pady=(8, 0))
        else:
            self.label(c, "Nothing suspicious was found.", 11, FG).pack(fill="x", pady=(8, 0))


    def open_report(self):
        try:
            os.startfile(self.html_path)  # Windows only
        except Exception:
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(self.html_path))


def run():
    # a windowed exe has no console; keep stray prints from crashing
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")
    root = tk.Tk()
    try:
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # sharp text on high-DPI screens
    except Exception:
        pass
    App(root)
    root.mainloop()
    return 0
