# MemWatch

A small Windows tool that tells you, in plain English, which programs are
misbehaving (leaking or using too much memory) and lets you restart them with
one click. It also warns when Windows driver memory is leaking, which only a
reboot can fix.

## Requirements

Windows 10/11 with .NET Framework 4.x (built in). No installer, no dependencies.

## Files

- `MemWatch.cs`  - source (single file, C#/WinForms)
- `build.bat`    - compiles with the built-in .NET Framework csc.exe
- `README.md`    - this file

## Use

Build it (below), then run `MemWatch.exe`. It does NOT start with Windows (no Run key, no startup
entry). It works without admin; "Run as administrator" lets it see and restart
a few more programs.

### What you see

- Top banner: one plain sentence about overall health, for example
  "2 programs are worth watching. Needs attention: Windows driver memory,
  Disk space (see below)." or "Everything looks fine."
  Green = all fine, yellow = something to watch, red = act on it.
- "Always watching" panel (always visible, see below): seven one-line
  checks with a colored dot each.
- The list: only programs that need attention, worst first.
  - Status: red "Restart suggested", yellow "Watch", green "OK".
  - Program: friendly name (e.g. "Google Chrome", "Windows Explorer").
  - Memory: how much memory the program holds. If it also holds 512 MB or
    more of graphics (GPU) memory, that is shown too, e.g.
    "525 MB (+13.4 GB graphics)".
  - Why: one short sentence, e.g. "Likely leaking (running 22 days) -
    restarting frees it" or "Growing fast (+600 MB per 10 min)".
  - Restart: a button on each problem row (red for "Restart suggested").
- If nothing is wrong you just see "Everything looks fine."
- "Show all programs" lists every program (OK ones too).
- "Advanced details" switches to the full numbers view (see below).
- Right-click a row: Restart, Open file location, Show details.

### Copy to clipboard (to paste into a chat)

Everything can be copied as plain ASCII text that starts with a line like
"MemWatch snapshot 2026-11-11 13:30:56 (computer NAME, not running as admin)".

- Program rows: right-click > "Copy to clipboard" (or Ctrl+C). Select several
  rows with Ctrl/Shift-click to copy them all. Each program gets a summary:
  friendly and exe name, path, status and why, process count, memory
  (working set + private), handles, threads, growth over 10 minutes and
  since start, oldest start time / uptime, and its PIDs.
- "Copy problems to clipboard" button (top bar), or right-click > "Copy all
  problems to clipboard": the health summary, system numbers, and every
  program that is not OK, in one block.
- Banner: right-click > "Copy to clipboard" copies the health text plus RAM,
  commit, nonpaged/paged pool, the largest pool tags and the driver that
  owns them.
- Advanced lists (programs and instances): right-click > "Copy row(s)" (or
  Ctrl+C) copies the selected rows, or all rows if none are selected, with a
  header line, tab-separated.

If another app is holding the clipboard, MemWatch retries a few times and
shows a message in the status bar instead of failing.

### Restart

Clicking Restart asks first, in plain words, e.g.
"Restart Notepad++? It will close and reopen. Unsaved work in it may be
lost." (A small details line lists the exact processes.) "No" is the default.

MemWatch asks the program's windows to close, waits 5 seconds, force-closes
anything left, then starts the program again with the same options.
Windows Explorer is special: it is ended and started again (the taskbar
blinks).

### Always watching panel

Seven cards above the problem list, always shown. Each card has a colored
left bar and dot (green = fine, amber = keep an eye on it, red = act, gray =
information), a short title, one big value, a thin bar where the value is a
fraction (screen drawing toward its restart point, Explorer handles, RAM,
graphics card, disk), one short gray line, and a small Restart button where
there is an action. Hover a card for the full plain-English explanation.
The cards wrap onto two rows on narrow windows. (Light theme only.)

1. Screen drawing (dwm): its graphics memory, growth per hour, when it will
   reach the restart point, and when it was last restarted (and how much
   that freed). Yellow at 3 GB, red at 6 GB. Restart button (always
   available; same confirmation / UAC flow as below).
2. Windows driver memory: nonpaged + paged kernel pool, growth per day, the
   likely cause (e.g. a security product's file filter driver). Red when nonpaged is over 1 GB,
   yellow when paged is over 6 GB. "Only a reboot clears this." No button.
3. Windows Explorer (taskbar, folders): handles, memory, how long it has run.
   Yellow over 5,000 handles, red over 10,000. Restart button.
4. Memory: RAM used and how full the commit limit is. Yellow at 75%, red at
   85% of the commit limit.
5. Graphics card memory: used of total. Yellow at 85%, red at 95%.
6. Disk: the fullest fixed drive (the card says how many others are low;
   hover for all drives). Red under 10% or under 20 GB free, yellow under
   15%; suggests what to clean. Checked once a minute. Card only: disk
   space never causes a pop-up, never turns the tray icon red and is not
   counted in the banner's "Needs attention" sentence.
7. Computer uptime: information only; turns yellow after 30 days with "A
   reboot clears driver and graphics leaks". Never causes a pop-up.

Growth rates are a straight-line fit through one sample per minute over the
last 6 hours; for the first 15 minutes they say "measuring...". Samples are
saved in HKCU\Software\MemWatch (DwmHistory, PoolHistory; last hour every
minute, older every 10 minutes, about 1.5 KB each at most) so the rate
survives MemWatch restarts. They start over when dwm restarts (new PID) or
Windows reboots. The last dwm restart (time, before/after) is saved there
too.

The whole panel is included in "Copy problems to clipboard" and the banner
copy; right-click the panel to copy just these lines.

Background: on some Windows 11 builds with NVIDIA drivers, dwm has been reported to leak graphics memory in the multiplane overlay (MPO) present path. Disabling MPO is a possible workaround (takes effect at the next reboot). Restarting dwm frees the memory in the meantime.

### Restart Windows screen drawing (dwm)

dwm.exe (Desktop Window Manager) draws your screen. After weeks of uptime it
can hoard graphics memory (e.g. 13 GB), which makes windows and scrolling
lag. When it crosses its limits it shows up as "Screen drawing (dwm)" with a
Restart button. The confirmation says:

"This restarts the part of Windows that draws your screen. The screen will
flash black for a second or two and come back; your open programs keep
running. Rarely Windows may sign you out instead, so save your work first."

Windows starts a new dwm.exe by itself. Ending dwm needs administrator
rights: if MemWatch is not elevated, a Windows permission (UAC) prompt
appears after you confirm (it runs "taskkill /f /im dwm.exe"). MemWatch then
checks that a new dwm.exe appeared within 10 seconds and shows the graphics
memory before and after in the status bar. dwm can never be killed any other
way from MemWatch; every other Windows process is still refused.

### Programs MemWatch will not restart

- Parts of Windows (System, svchost, lsass, csrss, dwm, Defender, anything in
  C:\Windows\System32, ...). They show "Part of Windows".
- Programs that run your coding agents and terminals: Node.js, Claude,
  PowerShell, Python, cmd, bash, WSL, Windows Terminal. These never get a
  Restart button, because closing all of them would kill the agents. The Why
  text says "close unused sessions yourself". (Advanced details lets you end
  one single process after showing its command line.)
- MemWatch itself.

### Tray

- Tray icon is blue normally, red when something needs a restart or driver
  memory is high. Hover for a one-line summary.
- Minimizing hides to the tray; click the tray icon to show it again. Closing
  the window exits MemWatch.
- Pop-up alerts (balloons) are kept rare:
  - Driver memory high: once per Windows boot. It survives MemWatch
    restarts and only shows again after a reboot, or if driver memory grows
    another 2 GB beyond the level last reported.
  - A program needing a restart: once per MemWatch session, and again only
    if that program was restarted and became a problem again.
  - Disk space never causes a pop-up (it is shown on the Disk card only).
  - Never more than one balloon per 30 minutes overall (anything held back
    is included in the next one).
  - The tray icon stays red and the banner text stays while a problem
    exists, even when no balloon is shown.
- Tray right-click > "Pop-up alerts: On/Off" silences balloons entirely
  (also on the Advanced toolbar). The setting is remembered.
- Alert state and the on/off setting are stored in the registry under
  HKCU\Software\MemWatch (this is not a startup entry). Delete that key to
  reset them.

## Advanced details

Ticking "Advanced details" shows the full view, off by default:

- System numbers: RAM, commit charge, Pool Nonpaged (red above 1 GB), Pool
  Paged (orange above 6 GB), total handles, processes, threads, and the
  largest kernel pool tags with the third-party driver that owns them.
- Program list grouped by exe path: count, working set, private bytes,
  handles, threads, growth over 10 minutes and since start, oldest start,
  uptime, technical reason, path. Click headers to sort.
- Instances list for the selected program: each PID with its command line.
- Actions: Restart program, Kill all instances, Restart / Kill one process,
  Open file location, Copy details. Every action is confirmed first.
- Refresh interval (default 5 s), Pause.

## How "likely cause" is found

When driver memory is above 1 GB, MemWatch reads the kernel pool tags once
(the same data poolmon shows), takes the 15 largest, and searches the
installed kernel drivers for those tag names. Each tag's memory is shared
among the third-party drivers that contain it, and the driver holding the
most (and at least 5% of the pool) is named. If no third-party driver stands
out, no cause is shown.

## Thresholds

Constants at the top of `MemWatch.cs` (class `Cfg`); edit and rebuild to tune.
They apply per process, never to Windows' own processes.

| Check                         | Watch (yellow)   | Restart suggested (red) |
|-------------------------------|------------------|-------------------------|
| Handles held                  | 5,000            | 10,000                  |
| Private memory                | 4 GB             | 8 GB                    |
| Threads                       | 1,000            | 2,000                   |
| Steady handle growth          | +500 / 10 min    | +1,000 / 10 min         |
| Steady memory growth          | +250 MB / 10 min | +500 MB / 10 min        |
| All copies of one program     | -                | 150,000 handles         |
| Driver memory (nonpaged pool) | -                | 1 GB                    |
| Graphics memory, one program  | 2 GB             | 4 GB                    |
| Graphics memory, dwm.exe      | 3 GB             | 6 GB                    |
| Steady graphics memory growth | +250 MB / 10 min | +500 MB / 10 min        |
| Graphics card full (banner)   | -                | 85% of card memory      |

Graphics memory = "Dedicated Usage" from the Windows "GPU Process Memory"
performance counters, summed over a program's processes (Advanced details
also shows "Shared Usage"). Card size comes from nvidia-smi if present,
otherwise the display driver's registry entry; card usage from "GPU Adapter
Memory". Per-process counters can add up to more than the card holds
(Windows counts some memory more than once), so treat them as relative.

"Steady" growth needs at least 5 minutes of history and must not go down in
at least 75% of 10 slices across the window, so one-off spikes are ignored.
Problems are ranked by how far past the red line they are.

## Footprint

Each check uses one Process.GetProcesses() snapshot (no WMI). Measured on a
busy ~800-process system: about 25 ms per check, ~70 MB RAM, about 1% of one CPU
core. The first check takes a few seconds (performance counter setup).

## Diagnostic switch

`MemWatch.exe --selftest-copy=problems|banner|rows|advanced|dwm` takes one full
sample, copies that text to the clipboard, and exits. It is used to test the
copy feature; normal use needs no arguments. The "dwm" mode reports how
dwm.exe is listed (status, reason, whether Restart is allowed and kill
refused) and the confirmation text, without ending anything.

`MemWatch.exe --selftest-trend` checks the growth-rate math with simulated
samples (measuring period, steady/flat/noisy/shrinking growth, reset when dwm
restarts, 6-hour window, time-to-limit), copies a PASS/FAIL report to the
clipboard and exits with code 0 if all passed.

`MemWatch.exe --selftest-alerts` runs simulated pop-up alert scenarios
(repeat suppression, MemWatch restart, reboot, +2 GB growth, program
restarted, 30-minute cap, alerts off) without touching the registry, copies
a PASS/FAIL report to the clipboard and exits with code 0 if all passed.

## Rebuild

Double-click `build.bat`, or:

    csc /target:winexe /optimize+ /out:MemWatch.exe /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Management.dll /reference:System.Windows.Forms.dll MemWatch.cs

Requires only .NET Framework 4.x (ships with Windows 10/11). Close MemWatch
before rebuilding (the running exe is locked).
