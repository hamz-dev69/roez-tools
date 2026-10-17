#!/usr/bin/env python3

import argparse
import collections
import glob
import importlib.util
import itertools
import json
import os
import platform
import re
import shutil
import signal
import site
import socket
import ssl
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time

RED    = "\033[1;31m"
GREEN  = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[1;36m"
WHITE  = "\033[1;37m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

LOGO = [
    r"██████╗  ██████╗ ███████╗███████╗  ████████╗ ██████╗  ██████╗ ██╗     ███████╗",
    r"██╔══██╗██╔═══██╗██╔════╝╚══███╔╝  ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝",
    r"██████╔╝██║   ██║█████╗    ███╔╝      ██║   ██║   ██║██║   ██║██║     ███████╗",
    r"██╔══██╗██║   ██║██╔══╝   ███╔╝       ██║   ██║   ██║██║   ██║██║     ╚════██║",
    r"██║  ██║╚██████╔╝███████╗███████╗     ██║   ╚██████╔╝╚██████╔╝███████╗███████║",
    r"╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝     ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝",
    r"",
]

GRADIENT = [196, 202, 208, 214, 220, 226]


# ═══════════════════════════ CONFIGURATION ═══════════════════════════

# Private virtual environment used only by ROEZ TOOLS. Installing there avoids
# PEP 668 errors and keeps the system Python untouched.
APP_DIR   = os.path.join(
    os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"),
    "roez-tools",
)
VENV_DIR  = os.path.join(APP_DIR, "venv")
VENV_PY   = os.path.join(VENV_DIR, "bin", "python")
LOG_FILE  = os.path.join(APP_DIR, "install.log")
SKIP_FILE = os.path.join(APP_DIR, "skip_setup")

HOLEHE_TIMEOUT         = 300   # seconds, total limit for an email scan
SHERLOCK_REQ_TIMEOUT   = 15    # seconds per request (sherlock default is 60)
SHERLOCK_TOTAL_TIMEOUT = 900   # seconds, total limit for a username scan

# key -> package info. "probe" is an import statement proving the package really works.
DEPS = collections.OrderedDict([
    ("phonenumbers", {"pip": "phonenumbers",     "module": "phonenumbers",    "probe": "import phonenumbers",
                      "script": None,            "min_py": None}),
    ("holehe",       {"pip": "holehe",           "module": "holehe",          "probe": "import holehe.core",
                      "script": "holehe",        "min_py": None}),
    ("sherlock",     {"pip": "sherlock-project", "module": "sherlock_project", "probe": "import sherlock_project.sherlock",
                      "script": "sherlock",      "min_py": (3, 9)}),
])

# holehe calls check_update() BEFORE scanning: it runs `pip3 install --upgrade holehe`
# and then exit()s with no results whenever its version differs from PyPI (always fails
# on PEP 668 systems, crashes when offline). It is disabled here; everything else runs as-is.
HOLEHE_BOOT = (
    "import holehe.core as c\n"
    "if hasattr(c, 'check_update'):\n"
    "    c.check_update = lambda *a, **k: None\n"
    "c.main()\n"
)

EMAIL_RE    = re.compile(r"^(?!-)[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^(?!-)\S{1,64}$")
ANSI_RE     = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
SHERLOCK_FOUND_RE = re.compile(r"^\[\+\]\s*(.+?):\s*(https?://\S+)\s*$")


# ═══════════════════════════ UI ═══════════════════════════

def clear():
    sys.stdout.write("\033[H\033[2J\033[3J")
    sys.stdout.flush()


def get_terminal_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 100


def print_header():
    width = get_terminal_width()
    for i, line in enumerate(LOGO):
        c = GRADIENT[min(i, len(GRADIENT) - 1)]
        print(f"\033[1;38;5;{c}m" + line.center(width) + RESET)
    tagline = "OSINT  •  NETWORK  •  SYSTEM"
    print(CYAN + tagline.center(width) + RESET)
    print()


def print_menu():
    items = [
        ("1 ",  "Check Your IP"),
        ("2 ",  "Search Locate with IP"),
        ("3 ",  "Check System"),
        ("4 ",  "Search Email"),
        ("5 ",  "Search Username"),
        ("6 ",  "Phone Number OSINT"),
        ("7 ",  "ExifTool Metadata"),
        ("8 ",  "Subdomain Finder"),
        ("9 ",  "Security Headers + SSL"),
        ("10", "Whois + DNS Lookup"),
        ("11", "Exit"),
    ]
    inner = 40
    pad = " " * max((get_terminal_width() - inner - 2) // 2, 0)
    print(pad + CYAN + "╔" + "═" * inner + "╗" + RESET)
    print(pad + CYAN + "║" + GREEN + BOLD + "MENU".center(inner) + CYAN + "║" + RESET)
    print(pad + CYAN + "╠" + "═" * inner + "╣" + RESET)
    for k, name in items:
        color = RED if k == "11" else WHITE
        row = f"  [{k:>2}]  {name}".ljust(inner)
        print(pad + CYAN + "║" + color + row + CYAN + "║" + RESET)
    print(pad + CYAN + "╚" + "═" * inner + "╝" + RESET)
    print(pad + GREEN + BOLD + "Made by github@hamz-dev69".center(inner + 2) + RESET)
    print()


def pause():
    print()
    try:
        input(CYAN + "  Press Enter to return to the menu..." + RESET)
    except EOFError:
        pass


def screen(title):
    clear()
    print_header()
    width = get_terminal_width()
    print(YELLOW + BOLD + f"  {title}".center(width) + RESET)
    print()


def confirm(prompt, default=True):
    """Ask a yes/no question. Without an interactive terminal, return the default."""
    if not sys.stdin.isatty():
        return default
    try:
        ans = input(CYAN + prompt + WHITE).strip().lower()
    except EOFError:
        ans = ""
    finally:
        sys.stdout.write(RESET)
    if not ans:
        return default
    return ans in ("y", "yes")


# ═══════════════════════════ TEXT UTILITIES ═══════════════════════════

def strip_ansi(text):
    return ANSI_RE.sub("", text or "")


def tail_lines(text, n=5):
    """Last n meaningful lines (no blank lines or progress bars)."""
    out = []
    for raw in strip_ansi(text).splitlines():
        line = raw.strip()
        if not line or "%|" in line or "it/s]" in line:
            continue
        out.append(line)
    return out[-n:]


def fmt_duration(seconds):
    return "%d minutes" % (seconds // 60) if seconds >= 60 and seconds % 60 == 0 else "%d seconds" % seconds


def clean_domain(raw):
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d


def valid_domain(d):
    return bool(re.match(r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", d))


def extend_path():
    """Append bin folders that are often missing from PATH (~/.local/bin, ~/go/bin, ...)."""
    home = os.path.expanduser("~")
    extra = [
        os.path.join(home, ".local", "bin"),
        os.path.join(home, "go", "bin"),
        "/usr/local/go/bin", "/snap/bin", "/usr/local/bin",
        "/usr/local/sbin", "/usr/sbin", "/sbin",
    ]
    gopath = os.environ.get("GOPATH")
    if gopath:
        extra.append(os.path.join(gopath, "bin"))
    current = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    add = [p for p in extra if os.path.isdir(p) and p not in current]
    if add:
        os.environ["PATH"] = os.pathsep.join(current + add)


def has_cmd(cmd):
    return shutil.which(cmd) is not None


def check_internet(timeout=2):
    """True if outbound connections work. The check is skipped when a proxy is configured."""
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        if os.environ.get(k):
            return True
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53), ("github.com", 443)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


# ═══════════════════════════ PROCESS RUNNER ═══════════════════════════

RunResult = collections.namedtuple("RunResult", "out err rc timed_out interrupted")


def _signal_group(proc, sig):
    try:
        os.killpg(proc.pid, sig)
    except Exception:
        try:
            proc.send_signal(sig)
        except Exception:
            pass


def _terminate(proc):
    """SIGTERM the whole process group; SIGKILL it if still alive after 3 seconds."""
    if proc.poll() is not None:
        return
    _signal_group(proc, signal.SIGTERM)

    def _escalate():
        time.sleep(3)
        if proc.poll() is None:
            _signal_group(proc, signal.SIGKILL)

    threading.Thread(target=_escalate, daemon=True).start()


def run_command(cmd, timeout=120, cwd=None, on_line=None):
    """
    Run a command and read its stdout line by line (live), with a time limit.
    A non-zero exit code is not an exception. Ctrl+C kills the child process and is
    reported through `interrupted`, so partial results can still be shown.
    """
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"       # otherwise Python children deliver all output at the very end
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONWARNINGS"] = "ignore"

    errf = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="ignore")
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errf,
            cwd=cwd, env=env, text=True, encoding="utf-8", errors="ignore",
            bufsize=1, start_new_session=True,
        )
    except OSError as e:
        errf.close()
        return RunResult("", str(e), 127, False, False)

    state = {"timed_out": False}

    def _on_timeout():
        state["timed_out"] = True
        _terminate(proc)

    timer = threading.Timer(timeout, _on_timeout)
    timer.daemon = True
    timer.start()

    lines = []
    interrupted = False
    try:
        for raw in proc.stdout:
            line = raw.rstrip("\r\n")
            lines.append(line)
            if on_line:
                try:
                    on_line(line)
                except Exception:
                    pass
    except KeyboardInterrupt:
        interrupted = True
        _terminate(proc)
    finally:
        timer.cancel()

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _signal_group(proc, signal.SIGKILL)
        proc.wait()
    try:
        proc.stdout.close()
    except Exception:
        pass
    try:
        errf.seek(0)
        err = errf.read()
    except Exception:
        err = ""
    finally:
        errf.close()

    return RunResult("\n".join(lines), err, proc.returncode, state["timed_out"], interrupted)


class Spinner(object):
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, label, elapsed=True):
        self.label = label
        self.elapsed = elapsed
        self._stop = threading.Event()
        self._thread = None
        self._t0 = time.time()
        self._tty = sys.stdout.isatty()

    def _text(self):
        try:
            text = self.label() if callable(self.label) else str(self.label)
        except Exception:
            text = "Working"
        text += "..."
        if self.elapsed:
            s = int(time.time() - self._t0)
            text += " %02d:%02d" % (s // 60, s % 60)
        return text

    def _run(self):
        for ch in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            sys.stdout.write("\r\033[K%s  %s %s%s" % (CYAN, ch, self._text(), RESET))
            sys.stdout.flush()
            time.sleep(0.08)

    def __enter__(self):
        self._t0 = time.time()
        if self._tty:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join()
        if self._tty:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        return False


def run_with_spinner(cmd, text="Scanning", timeout=120, cwd=None):
    """Simple variant: return stdout (str). Raises only if there is no output at all."""
    with Spinner(text):
        res = run_command(cmd, timeout=timeout, cwd=cwd)
    if res.interrupted:
        raise KeyboardInterrupt
    has_out = bool(res.out.strip())
    if res.timed_out:
        if not has_out:
            raise RuntimeError("Timed out after %d seconds" % timeout)
        print(YELLOW + "  ⚠ Timed out after %d seconds - results may be incomplete." % timeout + RESET)
    elif res.rc != 0 and not has_out:
        tail = tail_lines(res.err, 3)
        raise RuntimeError(" | ".join(tail) if tail else "process exited with code %s" % res.rc)
    return res.out


def run_text(cmd, timeout=15):
    """Run a command and return its stdout (no error even if the exit code is non-zero)."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return r.stdout.decode(errors="ignore")
    except Exception:
        return ""


# ═══════════════════════════ DEPENDENCY MANAGER ═══════════════════════════
#
# Why the OSINT tools used to be "not found" for many users:
#  1. pip3 install is refused on Ubuntu 23.04+/Debian 12+/recent Kali (PEP 668).
#  2. pip install -r fails ATOMICALLY: one failing package (e.g. sherlock-project needs
#     Python 3.9+) means holehe and phonenumbers are not installed either.
#  3. Scripts in ~/.local/bin are not on PATH, so `which holehe` fails.
#  4. phonenumbers was installed for a different Python/pip than the `python3` running the tool.
# Fix: packages are installed ONE BY ONE into a private venv and used through its interpreter.

_STATUS_CACHE = {}


def reset_status_cache():
    _STATUS_CACHE.clear()


def log(msg):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 1024 * 1024:
            os.remove(LOG_FILE)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except OSError:
        pass


def extra_site_paths():
    """Private-venv site-packages plus the user site, for in-process imports (phonenumbers)."""
    paths = []
    for p in sorted(glob.glob(os.path.join(VENV_DIR, "lib", "python3*", "site-packages"))):
        paths.append(p)
    try:
        paths.append(site.getusersitepackages())
    except Exception:
        pass
    return [p for p in paths if os.path.isdir(p)]


def try_import_phonenumbers():
    """(module | None, error_text). Also tries the private venv's site-packages."""
    err = ""
    for attempt in (0, 1):
        try:
            import phonenumbers
            return phonenumbers, ""
        except ImportError as e:
            err = str(e)
        except Exception as e:                       # broken package
            return None, "%s: %s" % (type(e).__name__, e)
        if attempt == 0:
            for p in extra_site_paths():
                if p not in sys.path:
                    sys.path.append(p)
            importlib.invalidate_caches()
    return None, err


def shebang_python(path):
    """Interpreter named in a script's shebang (e.g. holehe/sherlock installed with pipx)."""
    try:
        with open(path, "rb") as f:
            first = f.readline(512).decode("utf-8", "ignore").strip()
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    parts = first[2:].split()
    if not parts:
        return None
    if os.path.basename(parts[0]) == "env":
        for tok in parts[1:]:
            if not tok.startswith("-"):
                return shutil.which(tok)
        return None
    return parts[0] if os.path.exists(parts[0]) else None


def candidate_pythons(dep):
    cands = []

    def add(p):
        if p and os.path.exists(p) and p not in cands:
            cands.append(p)

    add(sys.executable)
    add(VENV_PY)
    if dep.get("script"):
        exe = shutil.which(dep["script"])
        if exe:
            add(shebang_python(exe))
    return cands


def module_present(py, module):
    r = run_command(
        [py, "-c", "import importlib.util as u, sys; sys.exit(0 if u.find_spec(sys.argv[1]) else 1)", module],
        timeout=30,
    )
    return r.rc == 0


def import_probe(py, probe):
    r = run_command([py, "-c", probe], timeout=90)
    if r.rc == 0:
        return True, ""
    return False, " | ".join(tail_lines(r.err or r.out, 3)) or "import failed (code %s)" % r.rc


def dep_status(key, deep=False):
    """
    -> (ok, python_path, error_text)
    deep=False: quick check (is the module there?)   deep=True: actually import it (proven to work)
    """
    ck = (key, deep)
    if ck in _STATUS_CACHE:
        return _STATUS_CACHE[ck]
    dep = DEPS[key]

    if key == "phonenumbers":
        mod, err = try_import_phonenumbers()
        res = (mod is not None, sys.executable if mod else None,
               err if mod is None and "No module named" not in err else "")
        _STATUS_CACHE[ck] = res
        return res

    res = (False, None, "")
    first_err = ""
    for py in candidate_pythons(dep):
        if not module_present(py, dep["module"]):
            continue
        if not deep:
            res = (True, py, "")
            break
        ok, err = import_probe(py, dep["probe"])
        if ok:
            res = (True, py, "")
            break
        first_err = first_err or err
    else:
        res = (False, None, first_err)
    _STATUS_CACHE[ck] = res
    return res


def venv_healthy():
    if not os.path.isfile(VENV_PY):
        return False
    return run_command([VENV_PY, "-m", "pip", "--version"], timeout=60).rc == 0


def ensure_venv():
    if venv_healthy():
        return True
    if os.path.isdir(VENV_DIR) and os.path.basename(VENV_DIR) == "venv":
        shutil.rmtree(VENV_DIR, ignore_errors=True)       # broken venv (e.g. system Python was upgraded)
    try:
        os.makedirs(APP_DIR, exist_ok=True)
    except OSError as e:
        print(RED + "  ✘ Cannot create folder %s: %s" % (APP_DIR, e) + RESET)
        return False
    with Spinner("Creating isolated environment"):
        r = run_command([sys.executable, "-m", "venv", VENV_DIR], timeout=180)
    log("venv create rc=%s\n%s\n%s" % (r.rc, r.out, r.err))
    if r.rc == 0 and venv_healthy():
        return True
    if os.path.isdir(VENV_DIR) and os.path.basename(VENV_DIR) == "venv":
        shutil.rmtree(VENV_DIR, ignore_errors=True)
    low = (r.out + r.err).lower()
    if "ensurepip" in low or "python3-venv" in low or "-venv" in low:
        print(YELLOW + "  ⚠ The venv module is not installed. Install it first:" + RESET)
        print(CYAN + "    sudo apt install python3-venv python3-pip" + RESET)
    else:
        for line in tail_lines(r.out + "\n" + r.err, 3):
            print(RED + "    " + line + RESET)
    return False


def pip_hint(text, pkg):
    low = (text or "").lower()
    if "externally-managed-environment" in low:
        return "Global pip is blocked (PEP 668). Fix: sudo apt install python3-venv, then run python3 roez-tools.py --setup"
    if "no matching distribution" in low or "requires a different python" in low or "requires-python" in low:
        return "Your Python version (%d.%d) is not supported by %s." % (sys.version_info[0], sys.version_info[1], pkg)
    if "failed building wheel" in low or "python.h" in low or "gcc" in low:
        return "Build failed. Try: sudo apt install build-essential python3-dev"
    if ("name resolution" in low or "connection" in low or "timed out" in low
            or "network is unreachable" in low or "ssl" in low):
        return "Network or DNS problem while downloading packages."
    if "permission denied" in low:
        return "Permission denied. Do not mix sudo and non-sudo for the same folder."
    return ""


def pip_install(py, pkg, repair=False, user=False, break_system=False):
    cmd = [py, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--upgrade"]
    if repair:
        cmd.append("--force-reinstall")
    if user:
        cmd.append("--user")
    if break_system:
        cmd.append("--break-system-packages")
    cmd.append(pkg)
    with Spinner("Installing %s" % pkg):
        r = run_command(cmd, timeout=900)
    log("pip install %s rc=%s timed_out=%s\n%s\n%s" % (pkg, r.rc, r.timed_out, r.out, r.err))
    return r


def user_install(pkg, repair=False):
    """Fallback when the venv cannot be created: pip --user (PEP 668 needs explicit consent)."""
    r = pip_install(sys.executable, pkg, repair=repair, user=True)
    text = r.out + "\n" + r.err
    if r.rc != 0 and "externally-managed-environment" in text.lower():
        print(YELLOW + "  ⚠ The system blocks global pip (PEP 668)." + RESET)
        if confirm("  Continue with --user --break-system-packages? [y/N]: ", False):
            r = pip_install(sys.executable, pkg, repair=repair, user=True, break_system=True)
    elif r.rc != 0 and "no module named pip" in text.lower():
        print(YELLOW + "  ⚠ pip is not installed: sudo apt install python3-pip" + RESET)
    return r


def setup_environment(keys=None, repair=False):
    """Install the OSINT dependencies one by one. Returns {key: bool}."""
    keys = list(keys) if keys else list(DEPS)
    results = {}
    todo = []
    for k in keys:
        mp = DEPS[k]["min_py"]
        if mp and sys.version_info[:2] < mp:
            print(YELLOW + "  ⚠ %s requires Python %d.%d+ (you are using %d.%d) - skipped." % (
                DEPS[k]["pip"], mp[0], mp[1], sys.version_info[0], sys.version_info[1]) + RESET)
            results[k] = False
        else:
            todo.append(k)
    if not todo:
        return results

    if not check_internet():
        print(RED + "  ✘ No internet connection. Installation canceled." + RESET)
        for k in todo:
            results[k] = False
        return results

    use_venv = ensure_venv()

    for k in todo:
        pkg = DEPS[k]["pip"]
        r = pip_install(VENV_PY, pkg, repair=repair) if use_venv else user_install(pkg, repair=repair)
        reset_status_cache()
        ok, _, err = dep_status(k, deep=True)
        if ok:
            print(GREEN + "  ✔ %s is ready" % pkg + RESET)
        else:
            print(RED + "  ✘ %s failed" % pkg + RESET)
            hint = pip_hint(r.out + "\n" + r.err, pkg)
            if hint:
                print(YELLOW + "    " + hint + RESET)
            for line in (tail_lines(err, 2) if err else tail_lines(r.err or r.out, 3)):
                print(WHITE + "    " + line + RESET)
            print(CYAN + "    Full log: " + LOG_FILE + RESET)
        results[k] = ok

    if all(results.get(k) for k in todo):
        try:
            os.remove(SKIP_FILE)
        except OSError:
            pass
    return results


def ensure_dep(key):
    """Make sure a dependency is usable; offer to install it if not. Returns bool."""
    ok, _, err = dep_status(key, deep=True)
    if ok:
        return True
    dep = DEPS[key]
    name = dep["pip"]
    if err:
        print(RED + "  ✘ %s is installed but fails to run:" % name + RESET)
        print(WHITE + "    " + err + RESET)
    else:
        print(RED + "  ✘ %s not found!" % name + RESET)

    mp = dep["min_py"]
    if mp and sys.version_info[:2] < mp:
        print(YELLOW + "  ⚠ %s requires Python %d.%d+ (you are using %d.%d). Please upgrade Python." % (
            name, mp[0], mp[1], sys.version_info[0], sys.version_info[1]) + RESET)
        return False

    manual = "python3 roez-tools.py --setup" + (" --repair" if err else "")
    if not sys.stdin.isatty():
        print(WHITE + "  Install it with:" + RESET)
        print(CYAN + "    " + manual + RESET)
        return False
    if not confirm("  Install it now in an isolated environment? [Y/n]: ", True):
        print(WHITE + "  Install it later with:" + RESET)
        print(CYAN + "    " + manual + RESET)
        return False
    print()
    return bool(setup_environment([key], repair=bool(err)).get(key))


def startup_check():
    """Quick check at startup. If something is missing, offer to install it."""
    if os.path.exists(SKIP_FILE) or not sys.stdin.isatty():
        return
    missing = []
    for k, dep in DEPS.items():
        mp = dep["min_py"]
        if mp and sys.version_info[:2] < mp:
            continue
        if not dep_status(k)[0]:
            missing.append(k)
    if not missing:
        return
    screen("OSINT DEPENDENCY SETUP")
    print(WHITE + "  Missing components: " + YELLOW + ", ".join(DEPS[k]["pip"] for k in missing) + RESET)
    print(WHITE + "  They will be installed in an isolated environment:" + RESET)
    print(CYAN + "    " + VENV_DIR + RESET)
    print()
    if confirm("  Install now? [Y/n]: ", True):
        print()
        setup_environment(missing)
        pause()
    else:
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            open(SKIP_FILE, "w").close()
        except OSError:
            pass


def doctor():
    screen("DOCTOR - ENVIRONMENT DIAGNOSTICS")

    def row(label, value, ok=None):
        mark = "" if ok is None else ((GREEN + "✔ ") if ok else (RED + "✘ "))
        print(GREEN + f"  {label:<16}: " + mark + WHITE + str(value) + RESET)

    row("Python", "%s (%s)" % (platform.python_version(), sys.executable))
    row("System", "%s %s" % (platform.system(), platform.release()))
    pep668 = os.path.exists(os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED"))
    row("Global pip", "blocked by PEP 668" if pep668 else "unrestricted")
    healthy = venv_healthy()
    row("Private venv", VENV_DIR if healthy else "missing or broken (%s)" % VENV_DIR, healthy)
    print()
    print(YELLOW + BOLD + "  PYTHON DEPENDENCIES" + RESET)
    for k, dep in DEPS.items():
        mp = dep["min_py"]
        if mp and sys.version_info[:2] < mp:
            row(dep["pip"], "requires Python %d.%d+" % mp, False)
            continue
        ok, py, err = dep_status(k, deep=True)
        row(dep["pip"], py if ok else (err or "not found"), ok)
    print()
    print(YELLOW + BOLD + "  EXTERNAL TOOLS" + RESET)
    for c in ("curl", "whois", "dig", "exiftool", "subfinder", "neofetch", "fastfetch"):
        p = shutil.which(c)
        row(c, p or "not found", bool(p))
    print()
    net = check_internet()
    row("Internet", "connected" if net else "not detected", net)
    row("Install log", LOG_FILE)
    pause()


# ═══════════════════════════ FEATURES 1-3 ═══════════════════════════

def check_ip():
    screen("CHECK YOUR IP")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "Unavailable"
    try:
        public_ip = subprocess.check_output(
            ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        public_ip = "Unavailable (check your connection)"
    print(GREEN + f"  Hostname   : {WHITE}{socket.gethostname()}" + RESET)
    print(GREEN + f"  Local IP   : {WHITE}{local_ip}" + RESET)
    print(GREEN + f"  Public IP  : {WHITE}{public_ip}" + RESET)
    pause()


def search_locate():
    screen("SEARCH LOCATE WITH IP")
    target = input(GREEN + "  Enter IP (leave empty = your own public IP): " + WHITE).strip()
    print(RESET)
    if target and not (re.fullmatch(r"[0-9a-fA-F:.]+", target) or valid_domain(clean_domain(target))):
        print(RED + "  ✘ Invalid input (enter an IP address or a domain)." + RESET)
        pause()
        return
    print(CYAN + "  Fetching information..." + RESET)
    print()
    try:
        url = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,isp,org,as,mobile,proxy,hosting,query"
        result = subprocess.check_output(
            ["curl", "-s", "--max-time", "8", url],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        data = json.loads(result)
        if data.get("status") == "fail":
            print(RED + f"  ✘ Failed: {data.get('message', 'Unknown error')}" + RESET)
        else:
            fields = [
                ("IP", data.get("query", "-")),
                ("Country", data.get("country", "-")),
                ("Region", data.get("regionName", "-")),
                ("City", data.get("city", "-")),
                ("Postal Code", data.get("zip", "-")),
                ("ISP", data.get("isp", "-")),
                ("Organization", data.get("org", "-")),
                ("AS", data.get("as", "-")),
                ("Mobile/Data", "Yes" if data.get("mobile") else "No"),
                ("Proxy/VPN", "Yes" if data.get("proxy") else "No"),
                ("Hosting", "Yes" if data.get("hosting") else "No"),
            ]
            for label, value in fields:
                print(GREEN + f"  {label:<13}: {WHITE}{value}" + RESET)
    except FileNotFoundError:
        print(RED + "  ✘ curl not found. Install: sudo apt install curl" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
    pause()


def check_system():
    screen("CHECK SYSTEM")
    for cmd in ["neofetch", "fastfetch"]:
        if has_cmd(cmd):
            subprocess.call([cmd])
            pause()
            return
    distro = platform.version()
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    distro = line.strip().split("=", 1)[1].strip('"')
                    break
    except Exception:
        pass
    info = [
        ("OS", platform.system() + " " + platform.release()),
        ("Distro", distro),
        ("Hostname", platform.node()),
        ("Architecture", platform.machine()),
        ("Processor", platform.processor() or "N/A"),
        ("Python", platform.python_version()),
    ]
    for label, value in info:
        print(GREEN + f"  {label:<13}: {WHITE}{value}" + RESET)
    pause()


# ═══════════════════════════ FEATURE 4: EMAIL (HOLEHE) ═══════════════════════════

def parse_holehe_output(text):
    """
    Parse holehe's stdout. The legend line ("[+] Email used, [-] Email not used, ...")
    also starts with [+], so it must be dropped or it would count as a fake platform.
    Returns None if there is no sign that holehe ran normally.
    """
    found, notused, limited, checked = [], 0, 0, None
    marker = False
    for raw in re.split(r"[\r\n]+", strip_ansi(text)):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("[+] Email used"):
            marker = True
            continue
        m = re.match(r"^(\d+)\s+websites checked", line)
        if m:
            checked = int(m.group(1))
            marker = True
            continue
        if line.startswith("[+]"):
            item = line[3:].strip()
            if item and item not in found:
                found.append(item)
        elif line.startswith("[-]"):
            notused += 1
        elif line.startswith("[x]"):
            limited += 1
    if not (marker or found or notused or limited):
        return None
    return {"found": found, "notused": notused, "limited": limited, "checked": checked}


def holehe_check():
    screen("HOLEHE - EMAIL OSINT")
    if not ensure_dep("holehe"):
        pause()
        return
    py = dep_status("holehe", deep=True)[1]

    email = input(GREEN + "  Enter target email: " + WHITE).strip()
    print(RESET)
    if not EMAIL_RE.match(email):
        print(RED + "  ✘ Invalid email address!" + RESET)
        pause()
        return
    if not check_internet():
        print(RED + "  ✘ No internet connection." + RESET)
        pause()
        return

    width = get_terminal_width()
    sep = "─" * width
    print(CYAN + f"  Scanning email: {WHITE}{email}" + RESET)
    print()
    print(CYAN + sep + RESET)

    cmd = [py, "-c", HOLEHE_BOOT, "--no-color", "--no-clear", "--", email]
    with Spinner("Scanning email"):
        res = run_command(cmd, timeout=HOLEHE_TIMEOUT)

    parsed = parse_holehe_output(res.out)
    if res.interrupted:
        print(YELLOW + "  ⚠ Scan canceled (Ctrl+C)." + RESET)
    elif parsed is None:
        if res.timed_out:
            print(RED + f"  ✘ Timed out after {fmt_duration(HOLEHE_TIMEOUT)} without results." + RESET)
        else:
            print(RED + "  ✘ holehe failed to run:" + RESET)
            for line in tail_lines(res.err or res.out, 4):
                print(WHITE + "    " + line + RESET)
    else:
        found = parsed["found"]
        if found:
            plural = "" if len(found) == 1 else "s"
            print(GREEN + BOLD + f"  ✔ Email [{email}] is registered on {len(found)} platform{plural}:" + RESET)
            print()
            for i, p in enumerate(found, 1):
                print(GREEN + f"  [{i:02d}] " + WHITE + p + RESET)
        else:
            print(YELLOW + f"  ⚠ No platforms found for: {email}" + RESET)
    print()
    print(CYAN + sep + RESET)
    pause()


# ═══════════════════════════ FEATURE 5: USERNAME (SHERLOCK) ═══════════════════════════

def parse_sherlock_line(line):
    """A sherlock result line -> (name, url) or None."""
    line = strip_ansi(line).strip()
    if not line.startswith("[+]"):
        return None
    m = SHERLOCK_FOUND_RE.match(line)
    if m:
        return (m.group(1).strip(), m.group(2))
    rest = line[3:].strip()
    return (rest, "") if rest else None


def sherlock_check():
    screen("SHERLOCK - USERNAME OSINT")
    if not ensure_dep("sherlock"):
        pause()
        return
    py = dep_status("sherlock", deep=True)[1]

    username = input(GREEN + "  Enter target username: " + WHITE).strip().lstrip("@")
    print(RESET)
    if not username:
        print(RED + "  ✘ Username cannot be empty!" + RESET)
        pause()
        return
    if not USERNAME_RE.match(username):
        print(RED + "  ✘ Invalid username (no spaces, max 64 characters, cannot start with '-')." + RESET)
        pause()
        return
    if not check_internet():
        print(RED + "  ✘ No internet connection." + RESET)
        pause()
        return

    width = get_terminal_width()
    sep = "─" * width
    print(CYAN + f"  Scanning username: {WHITE}{username}" + RESET)
    print()
    print(CYAN + sep + RESET)

    found = []
    seen = set()

    def on_line(line):
        item = parse_sherlock_line(line)
        if item and item[1] + item[0] not in seen:
            seen.add(item[1] + item[0])
            found.append(item)

    # Temporary working directory: sherlock writes <username>.txt into it, so keep it from littering.
    workdir = tempfile.mkdtemp(prefix="roez-sherlock-")
    try:
        cmd = [py, "-m", "sherlock_project", "--no-color", "--timeout", str(SHERLOCK_REQ_TIMEOUT), "--", username]
        with Spinner(lambda: f"Scanning username ({len(found)} found)"):
            res = run_command(cmd, timeout=SHERLOCK_TOTAL_TIMEOUT, cwd=workdir, on_line=on_line)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    started = any(l.strip().startswith("[*]") for l in strip_ansi(res.out).splitlines())
    if not found and not started and not res.interrupted:
        if res.timed_out:
            print(RED + f"  ✘ Timed out after {fmt_duration(SHERLOCK_TOTAL_TIMEOUT)} without results." + RESET)
        else:
            print(RED + "  ✘ sherlock failed to run:" + RESET)
            for line in tail_lines(res.err or res.out, 4):
                print(WHITE + "    " + line + RESET)
    else:
        if found:
            plural = "" if len(found) == 1 else "s"
            print(GREEN + BOLD + f"  ✔ Username [{username}] found on {len(found)} platform{plural}:" + RESET)
            print()
            for i, (name, url) in enumerate(found, 1):
                print(GREEN + f"  [{i:02d}] " + WHITE + (f"{name}: {url}" if url else name) + RESET)
        else:
            print(YELLOW + f"  ⚠ Username [{username}] was not found on any platform." + RESET)
        if res.interrupted:
            print()
            print(YELLOW + "  ⚠ Scan canceled (Ctrl+C) - partial results." + RESET)
        elif res.timed_out:
            print()
            print(YELLOW + f"  ⚠ Scan stopped after {fmt_duration(SHERLOCK_TOTAL_TIMEOUT)} - partial results." + RESET)
    print()
    print(CYAN + sep + RESET)
    pause()


# ═══════════════════════════ FEATURE 6: PHONE ═══════════════════════════

def phone_osint():
    screen("PHONE NUMBER OSINT")
    if not ensure_dep("phonenumbers"):
        pause()
        return
    phonenumbers, _ = try_import_phonenumbers()
    from phonenumbers import geocoder, carrier, timezone

    raw = input(GREEN + "  Enter number (e.g. +6281234567890 / 081234567890): " + WHITE).strip()
    print(RESET)
    if not raw:
        print(RED + "  ✘ Number cannot be empty!" + RESET)
        pause()
        return

    try:
        num = phonenumbers.parse(raw, "ID")
    except Exception as e:
        print(RED + f"  ✘ Invalid number format: {e}" + RESET)
        pause()
        return

    T = phonenumbers.PhoneNumberType
    names = {
        "MOBILE": "Mobile", "FIXED_LINE": "Fixed Line", "FIXED_LINE_OR_MOBILE": "Fixed Line / Mobile",
        "TOLL_FREE": "Toll Free", "PREMIUM_RATE": "Premium Rate", "SHARED_COST": "Shared Cost",
        "VOIP": "VoIP", "PERSONAL_NUMBER": "Personal Number", "PAGER": "Pager", "UAN": "UAN",
        "VOICEMAIL": "Voicemail", "UNKNOWN": "Unknown",
    }
    types = {getattr(T, k): v for k, v in names.items() if hasattr(T, k)}
    ntype = phonenumbers.number_type(num)
    tz = ", ".join(timezone.time_zones_for_number(num)) or "-"
    fields = [
        ("Valid", "Yes" if phonenumbers.is_valid_number(num) else "No"),
        ("International", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)),
        ("National", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)),
        ("Country Code", f"+{num.country_code}"),
        ("Location", geocoder.description_for_number(num, "en") or geocoder.description_for_number(num, "id") or "-"),
        ("Carrier", carrier.name_for_number(num, "en") or carrier.name_for_number(num, "id") or "-"),
        ("Type", types.get(ntype, "Other")),
        ("Time Zone", tz),
    ]
    for label, value in fields:
        print(GREEN + f"  {label:<14}: {WHITE}{value}" + RESET)
    pause()


# ═══════════════════════════ FEATURES 7-10 ═══════════════════════════

def exif_check():
    screen("EXIFTOOL - METADATA READER")
    if not has_cmd("exiftool"):
        print(RED + "  ✘ exiftool not found!" + RESET)
        print(WHITE + "  Install it with:" + RESET)
        print(CYAN + "    sudo apt install libimage-exiftool-perl" + RESET)
        pause()
        return

    path = input(GREEN + "  Enter file path: " + WHITE).strip().strip("'\"")
    print(RESET)
    path = os.path.expanduser(path)
    if not path or not os.path.isfile(path):
        print(RED + "  ✘ File not found!" + RESET)
        pause()
        return
    path = os.path.abspath(path)          # keeps a file name starting with '-' from being read as an option

    width = get_terminal_width()
    sep = "─" * width
    print(CYAN + sep + RESET)
    try:
        result = run_with_spinner(["exiftool", path], "Reading metadata", timeout=60)
        lines = [l for l in result.splitlines() if ":" in l]
        if not lines:
            print(YELLOW + "  ⚠ No metadata found." + RESET)
        else:
            print(GREEN + BOLD + f"  ✔ {len(lines)} metadata fields found:" + RESET)
            print()
            has_gps = False
            for line in lines:
                key, val = line.split(":", 1)
                key, val = key.strip(), val.strip()
                if "GPS" in key:
                    has_gps = True
                    print(YELLOW + f"  {key[:28]:<28}: {val}" + RESET)
                else:
                    print(GREEN + f"  {key[:28]:<28}: {WHITE}{val}" + RESET)
            if has_gps:
                print()
                print(YELLOW + "  ⚠ This file contains GPS location data." + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
    print()
    print(CYAN + sep + RESET)
    pause()


def subfinder_check():
    screen("SUBFINDER - SUBDOMAIN FINDER")
    if not has_cmd("subfinder"):
        print(RED + "  ✘ subfinder not found!" + RESET)
        print(WHITE + "  Install it with:" + RESET)
        print(CYAN + "    sudo apt install subfinder" + RESET)
        print(WHITE + "  or:" + RESET)
        print(CYAN + "    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" + RESET)
        pause()
        return

    domain = clean_domain(input(GREEN + "  Enter target domain (e.g. example.com): " + WHITE))
    print(RESET)
    if not valid_domain(domain):
        print(RED + "  ✘ Invalid domain!" + RESET)
        pause()
        return

    print(CYAN + f"  Scanning domain: {WHITE}{domain}" + RESET)
    print()
    width = get_terminal_width()
    sep = "─" * width
    print(CYAN + sep + RESET)
    try:
        result = run_with_spinner(["subfinder", "-d", domain, "-silent"], "Finding subdomains", timeout=300)
        found = sorted(set(l.strip() for l in result.splitlines() if l.strip()))
        if found:
            plural = "" if len(found) == 1 else "s"
            print(GREEN + BOLD + f"  ✔ Found {len(found)} subdomain{plural} for [{domain}]:" + RESET)
            print()
            for i, s in enumerate(found, 1):
                print(GREEN + f"  [{i:02d}] " + WHITE + s + RESET)
        else:
            print(YELLOW + f"  ⚠ No subdomains found for: {domain}" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
    print()
    print(CYAN + sep + RESET)
    pause()


def headers_ssl_check():
    screen("SECURITY HEADERS + SSL CHECKER")
    host = clean_domain(input(GREEN + "  Enter domain (e.g. example.com): " + WHITE))
    print(RESET)
    if not valid_domain(host):
        print(RED + "  ✘ Invalid domain!" + RESET)
        pause()
        return

    width = get_terminal_width()
    sep = "─" * width

    # ---- Security Headers ----
    print(CYAN + sep + RESET)
    print(YELLOW + BOLD + "  SECURITY HEADERS" + RESET)
    print()
    try:
        raw = run_with_spinner(
            ["curl", "-sIL", "--max-time", "10", f"https://{host}"],
            "Fetching headers", timeout=30
        )
        blocks = [b for b in raw.replace("\r", "").split("\n\n") if b.strip()]
        if not blocks:
            raise ValueError("No response from server")
        last = blocks[-1]
        headers = {}
        for line in last.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        checks = [
            ("Strict-Transport-Security", "strict-transport-security"),
            ("Content-Security-Policy  ", "content-security-policy"),
            ("X-Frame-Options          ", "x-frame-options"),
            ("X-Content-Type-Options   ", "x-content-type-options"),
            ("Referrer-Policy          ", "referrer-policy"),
            ("Permissions-Policy       ", "permissions-policy"),
        ]
        score = 0
        for label, key in checks:
            if key in headers:
                score += 1
                val = headers[key]
                val = val if len(val) <= 40 else val[:37] + "..."
                print(GREEN + f"  ✔ {label}: {WHITE}{val}" + RESET)
            else:
                print(RED + f"  ✘ {label}: {YELLOW}missing" + RESET)
        print()
        color = GREEN if score >= 5 else (YELLOW if score >= 3 else RED)
        print(color + BOLD + f"  Score: {score}/{len(checks)} security headers enabled" + RESET)
        if "server" in headers:
            print(GREEN + f"  Server: {WHITE}{headers['server']}" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)

    # ---- SSL Certificate ----
    print()
    print(CYAN + sep + RESET)
    print(YELLOW + BOLD + "  SSL CERTIFICATE" + RESET)
    print()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                tls_version = ss.version()
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        expire_ts = ssl.cert_time_to_seconds(cert["notAfter"])
        days_left = int((expire_ts - time.time()) / 86400)
        sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]

        print(GREEN + f"  {'Common Name':<12}: {WHITE}{subject.get('commonName', '-')}" + RESET)
        print(GREEN + f"  {'Issuer':<12}: {WHITE}{issuer.get('organizationName', issuer.get('commonName', '-'))}" + RESET)
        print(GREEN + f"  {'Valid from':<12}: {WHITE}{cert.get('notBefore', '-')}" + RESET)
        print(GREEN + f"  {'Valid until':<12}: {WHITE}{cert.get('notAfter', '-')}" + RESET)
        print(GREEN + f"  {'TLS Version':<12}: {WHITE}{tls_version}" + RESET)
        print(GREEN + f"  {'SAN':<12}: {WHITE}{len(sans)} domains" + RESET)
        print()
        if days_left < 0:
            print(RED + BOLD + f"  ✘ Certificate EXPIRED {abs(days_left)} days ago!" + RESET)
        elif days_left < 30:
            print(YELLOW + BOLD + f"  ⚠ Certificate expires in {days_left} days" + RESET)
        else:
            print(GREEN + BOLD + f"  ✔ Certificate is valid, {days_left} days left" + RESET)
    except ssl.SSLCertVerificationError as e:
        print(RED + f"  ✘ Invalid certificate: {e.verify_message}" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)

    print()
    print(CYAN + sep + RESET)
    pause()


def whois_dns_check():
    screen("WHOIS + DNS LOOKUP")
    domain = clean_domain(input(GREEN + "  Enter domain (e.g. example.com): " + WHITE))
    print(RESET)
    if not valid_domain(domain):
        print(RED + "  ✘ Invalid domain!" + RESET)
        pause()
        return

    width = get_terminal_width()
    sep = "─" * width

    # ---- WHOIS ----
    print(CYAN + sep + RESET)
    print(YELLOW + BOLD + "  WHOIS" + RESET)
    print()
    if not has_cmd("whois"):
        print(RED + "  ✘ whois not found!" + RESET)
        print(CYAN + "    Install: sudo apt install whois" + RESET)
    else:
        try:
            result = run_with_spinner(["whois", domain], "Fetching whois data", timeout=30)
            wanted = [
                ("domain name", "Domain"),
                ("registrar:", "Registrar"),
                ("creation date", "Created"),
                ("updated date", "Updated"),
                ("registry expiry date", "Expires"),
                ("expiry date", "Expires"),
                ("registrant organization", "Organization"),
                ("registrant country", "Country"),
                ("domain status", "Status"),
                ("name server", "Nameserver"),
            ]
            shown = set()
            count = 0
            for line in result.splitlines():
                low = line.strip().lower()
                for key, label in wanted:
                    if low.startswith(key) and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        tag = (label, val)
                        if val and tag not in shown and count < 20:
                            shown.add(tag)
                            count += 1
                            print(GREEN + f"  {label:<12}: {WHITE}{val}" + RESET)
                        break
            if count == 0:
                print(YELLOW + "  ⚠ Whois data not found or hidden." + RESET)
        except Exception as e:
            print(RED + f"  ✘ Error: {e}" + RESET)

    # ---- DNS ----
    print()
    print(CYAN + sep + RESET)
    print(YELLOW + BOLD + "  DNS RECORDS" + RESET)
    print()
    if not has_cmd("dig"):
        print(RED + "  ✘ dig not found!" + RESET)
        print(CYAN + "    Install: sudo apt install dnsutils" + RESET)
    else:
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            out = run_text(["dig", "+short", rtype, domain], timeout=8)
            records = [l.strip() for l in out.splitlines() if l.strip()]
            if records:
                print(GREEN + BOLD + f"  {rtype}" + RESET)
                for r in records:
                    r = r if len(r) <= width - 8 else r[:width - 11] + "..."
                    print(WHITE + f"    {r}" + RESET)
            else:
                print(YELLOW + f"  {rtype}: no records" + RESET)
            print()

    print(CYAN + sep + RESET)
    pause()


# ─────────────────────────── MAIN ───────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="roez-tools",
        description="ROEZ TOOLS - a menu-driven terminal toolkit for OSINT, network, and system checks.",
    )
    p.add_argument("--setup", action="store_true",
                   help="install the OSINT dependencies (phonenumbers, holehe, sherlock) in an isolated environment")
    p.add_argument("--repair", action="store_true",
                   help="force a clean reinstall of the OSINT dependencies")
    p.add_argument("--doctor", action="store_true",
                   help="diagnose the environment: Python, dependencies, external tools, connectivity")
    return p.parse_args()


def main():
    args = parse_args()
    if os.name != "posix":
        print("ROEZ TOOLS supports Linux/macOS only. On Windows, run it through WSL.")
        sys.exit(1)
    extend_path()

    if args.doctor:
        doctor()
        return
    if args.setup or args.repair:
        screen("OSINT DEPENDENCY SETUP")
        setup_environment(repair=args.repair)
        pause()
        return

    startup_check()

    actions = {
        "1": check_ip,
        "2": search_locate,
        "3": check_system,
        "4": holehe_check,
        "5": sherlock_check,
        "6": phone_osint,
        "7": exif_check,
        "8": subfinder_check,
        "9": headers_ssl_check,
        "10": whois_dns_check,
    }

    while True:
        clear()
        print_header()
        print_menu()
        try:
            choice = input(CYAN + "  roez" + WHITE + "@" + GREEN + "tools" + CYAN + " ❯ " + WHITE).strip()
        except (EOFError, KeyboardInterrupt):
            choice = "11"
        print(RESET)
        if choice in actions:
            try:
                actions[choice]()
            except KeyboardInterrupt:
                print()
                print(YELLOW + "  ⚠ Canceled." + RESET)
                time.sleep(0.8)
            except EOFError:
                choice = "11"
            except Exception as e:                      # a bug in one feature must not kill the whole menu
                print(RED + f"  ✘ Unexpected error: {type(e).__name__}: {e}" + RESET)
                log("unexpected error in menu %s: %r" % (choice, e))
                pause()
        elif choice != "11":
            print(RED + "  ✘ Invalid choice. Press Enter to try again..." + RESET)
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                choice = "11"
        if choice == "11":
            clear()
            print()
            print(CYAN + "  Thank you for using ROEZ TOOLS. Goodbye!" + RESET)
            print()
            sys.exit(0)


if __name__ == "__main__":
    main()
