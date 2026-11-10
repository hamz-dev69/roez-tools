#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import glob
import importlib.util
import ipaddress
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
import urllib.parse

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

APP_DIR   = os.path.join(
    os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"),
    "roez-tools",
)
VENV_DIR  = os.path.join(APP_DIR, "venv")
VENV_PY   = os.path.join(VENV_DIR, "bin", "python")
LOG_FILE  = os.path.join(APP_DIR, "install.log")
SKIP_FILE = os.path.join(APP_DIR, "skip_setup")

HOLEHE_TIMEOUT         = 300   
SHERLOCK_REQ_TIMEOUT   = 15    
SHERLOCK_TOTAL_TIMEOUT = 900   

DEPS = collections.OrderedDict([
    ("phonenumbers", {"pip": "phonenumbers",     "module": "phonenumbers",    "probe": "import phonenumbers",
                      "script": None,            "min_py": None}),
    ("holehe",       {"pip": "holehe",           "module": "holehe",          "probe": "import holehe.core",
                      "script": "holehe",        "min_py": None}),
    ("sherlock",     {"pip": "sherlock-project", "module": "sherlock_project", "probe": "import sherlock_project.sherlock",
                      "script": "sherlock",      "min_py": (3, 9)}),
])

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
        ("11", "SQL Injection (sqlmap)"),
        ("12", "XSS Scanner (XSStrike)"),
        ("0 ", "Exit"),
    ]
    inner = 40
    pad = " " * max((get_terminal_width() - inner - 2) // 2, 0)
    print(pad + CYAN + "╔" + "═" * inner + "╗" + RESET)
    print(pad + CYAN + "║" + GREEN + BOLD + "MENU".center(inner) + CYAN + "║" + RESET)
    print(pad + CYAN + "╠" + "═" * inner + "╣" + RESET)
    for k, name in items:
        color = RED if k.strip() == "0" else WHITE
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


def clean_domain(raw: str) -> str:
    d = raw.strip().lower().rstrip(".")
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split(":")[0]
    if "@" in d:
        d = d.rsplit("@", 1)[-1]
    return d


def valid_domain(d: str) -> bool:
    if not d:
        return False
    try:
        ascii_d = d.encode("idna").decode("ascii")
    except Exception:
        ascii_d = d
    return bool(re.match(r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", ascii_d))


def valid_url(u: str) -> bool:
    """
    True for a syntactically valid http(s) URL with a usable host: a domain name,
    "localhost", a bare IPv4 address, or a bracketed IPv6 address (e.g. "http://[::1]:8080/").
    Rejects missing schemes/hosts, malformed netlocs (stray spaces, no host), and
    out-of-range or non-numeric ports.
    """
    if not u or not isinstance(u, str):
        return False
    try:
        parts = urllib.parse.urlsplit(u.strip())
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    try:
        host = parts.hostname       # None for a missing host
        _ = parts.port              # raises ValueError if out of range / non-numeric
    except ValueError:
        return False
    if not host or " " in parts.netloc:
        return False
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return valid_domain(host)


def is_local_target(host: str) -> bool:
    """
    True if `host` clearly refers to this machine or a private/lab network
    (localhost, loopback, RFC1918/link-local addresses) - i.e. somewhere that
    does not require outbound internet access to reach. Used so that local
    security-lab targets (DVWA, Juice Shop, etc. on 127.0.0.1/192.168.x.x)
    are never blocked by the "no internet connection" check.
    """
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


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


def check_internet(timeout: int = 2) -> bool:
    """
    True if *outbound internet* connectivity works (tests well-known public
    hosts). This says nothing about whether any particular scan target is
    reachable - that is the scan tool's job to report. Callers that may be
    pointed at a local/lab target should check is_local_target() first and
    skip this call entirely for those, rather than treating "no internet"
    as "can't reach the target". The check is skipped when a proxy is configured.
    """
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


def prompt_domain(prompt_text: str) -> str | None:
    """
    Prompt for a domain, normalize it, and validate it. On invalid input, prints
    the error and pauses, returning None so the caller can simply `return`.
    Dedupes the identical prompt/validate/pause block used by several features.
    """
    domain = clean_domain(input(GREEN + prompt_text + WHITE))
    print(RESET)
    if not valid_domain(domain):
        print(RED + "  ✘ Invalid domain!" + RESET)
        pause()
        return None
    return domain


def prompt_authorized_target_url(prompt_text: str) -> str | None:
    """
    Prompt for a target URL for an active scan (sqlmap/XSStrike-style tool):
    validates the URL, then requires outbound internet UNLESS the target is
    local (localhost, loopback, or a private/lab IP - so local lab
    environments are never blocked). Returns the URL, or None if the caller
    should abort (the message has already been shown).
    """
    url = input(GREEN + prompt_text + WHITE).strip()
    print(RESET)
    if not valid_url(url):
        print(RED + "  ✘ Invalid URL (must be http:// or https://, with a valid host)." + RESET)
        pause()
        return None
    host = urllib.parse.urlsplit(url).hostname or ""
    if not is_local_target(host) and not check_internet():
        print(RED + "  ✘ No internet connection." + RESET)
        pause()
        return None
    return url


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
    env["PYTHONUNBUFFERED"] = "1"       
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
        log_exception("run_command exec failed (%s)" % (cmd[0] if cmd else "?"), e)
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
                except Exception as e:
                    log_exception("run_command on_line callback", e)
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


def run_text(cmd: list, timeout: int = 15) -> str:
    """
    Run a short-lived command and return its stdout as text. A non-zero exit
    code is not an error (e.g. `dig` legitimately exits non-zero for "no records").
    A missing executable or a timeout returns "" and is logged (command name
    only - never the arguments, which may carry a user-supplied target).
    """
    name = cmd[0] if cmd else "?"
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return r.stdout.decode("utf-8", errors="ignore")
    except FileNotFoundError as e:
        log_exception("run_text exec not found (%s)" % name, e)
        return ""
    except subprocess.TimeoutExpired as e:
        log_exception("run_text timed out (%s)" % name, e)
        return ""
    except Exception as e:
        log_exception("run_text failed (%s)" % name, e)
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


def log(msg: str) -> None:
    """
    Append a line to the install/diagnostic log (rotated at 1 MB).
    Callers must not pass raw user input here (emails, usernames, phone numbers,
    domains/URLs, credentials) - log only command names, exception types, and
    other non-identifying diagnostic context. See log_exception() below.
    """
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 1024 * 1024:
            os.remove(LOG_FILE)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except OSError:
        pass


def log_exception(context: str, exc: Exception) -> None:
    """
    Log that something failed, for later diagnosis, without the exception's own
    message - which may embed the raw target the user typed (a domain, email,
    phone number, or URL). Only the feature name and exception type are recorded.
    """
    log("%s: %s" % (context, type(exc).__name__))


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


def parse_locate_target(raw):
    """-> normalized IP/domain for ip-api, "" for "use my own IP", or None if invalid."""
    raw = raw.strip()
    if not raw:
        return ""
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    d = clean_domain(raw)
    return d if valid_domain(d) else None


def search_locate():
    screen("SEARCH LOCATE WITH IP")
    target = input(GREEN + "  Enter IP (leave empty = your own public IP): " + WHITE).strip()
    print(RESET)
    query = parse_locate_target(target)
    if query is None:
        print(RED + "  ✘ Invalid input (enter an IP address or a domain)." + RESET)
        pause()
        return
    print(CYAN + "  Fetching information..." + RESET)
    print()
    try:
        url = f"http://ip-api.com/json/{query}?fields=status,message,country,regionName,city,zip,isp,org,as,mobile,proxy,hosting,query"
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
        log_exception("search_locate", e)
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
        log_exception("exif_check", e)
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

    domain = prompt_domain("  Enter target domain (e.g. example.com): ")
    if domain is None:
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
        log_exception("subfinder_check", e)
    print()
    print(CYAN + sep + RESET)
    pause()


def headers_ssl_check():
    screen("SECURITY HEADERS + SSL CHECKER")
    host = prompt_domain("  Enter domain (e.g. example.com): ")
    if host is None:
        return

    width = get_terminal_width()
    sep = "─" * width

    # ---- Security Headers ----
    print(CYAN + sep + RESET)
    print(YELLOW + BOLD + "  SECURITY HEADERS" + RESET)
    print()
    try:
        raw = run_with_spinner(
            ["curl", "-sL", "-A", "Mozilla/5.0 (X11; Linux x86_64) roez-tools",
             "--max-time", "10", "-D", "-", "-o", "/dev/null", f"https://{host}"],
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

        def header_ok(key, val):
            if key == "x-content-type-options":
                return "nosniff" in val.lower()
            if key == "strict-transport-security":
                m = re.search(r"max-age=(\d+)", val, re.I)
                return bool(m) and int(m.group(1)) > 0
            if key == "x-frame-options":
                return val.strip().upper() in ("DENY", "SAMEORIGIN")
            return True

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
            val = headers.get(key)
            if val is None and key == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", "").lower():
                print(GREEN + f"  ✔ {label}: {WHITE}via CSP frame-ancestors" + RESET)
                score += 1
                continue
            if val is None:
                print(RED + f"  ✘ {label}: {YELLOW}missing" + RESET)
                continue
            disp = val if len(val) <= 40 else val[:37] + "..."
            if header_ok(key, val):
                score += 1
                print(GREEN + f"  ✔ {label}: {WHITE}{disp}" + RESET)
            else:
                print(YELLOW + f"  ⚠ {label}: {WHITE}{disp} (weak value)" + RESET)
        print()
        color = GREEN if score >= 5 else (YELLOW if score >= 3 else RED)
        print(color + BOLD + f"  Score: {score}/{len(checks)} security headers enabled" + RESET)
        if "server" in headers:
            print(GREEN + f"  Server: {WHITE}{headers['server']}" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
        log_exception("headers_ssl_check(headers)", e)

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
        if days_left < 30:
            print(YELLOW + BOLD + f"  ⚠ Certificate expires in {days_left} days" + RESET)
        else:
            print(GREEN + BOLD + f"  ✔ Certificate is valid, {days_left} days left" + RESET)
    except ssl.SSLCertVerificationError as e:
        msg = str(e.verify_message or e)
        if "expired" in msg.lower():
            print(RED + BOLD + "  ✘ Certificate has EXPIRED." + RESET)
        else:
            print(RED + f"  ✘ Invalid certificate: {msg}" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
        log_exception("headers_ssl_check(ssl)", e)

    print()
    print(CYAN + sep + RESET)
    pause()


def whois_dns_check():
    screen("WHOIS + DNS LOOKUP")
    domain = prompt_domain("  Enter domain (e.g. example.com): ")
    if domain is None:
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
            label_cap = {"Nameserver": 8, "Status": 6}
            counts = collections.Counter()
            shown = set()
            total = 0
            for line in result.splitlines():
                low = line.strip().lower()
                for key, label in wanted:
                    if low.startswith(key) and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        tag = (label, val)
                        cap = label_cap.get(label, 1)
                        if val and tag not in shown and counts[label] < cap:
                            shown.add(tag)
                            counts[label] += 1
                            total += 1
                            print(GREEN + f"  {label:<12}: {WHITE}{val}" + RESET)
                        break
            if total == 0:
                print(YELLOW + "  ⚠ Whois data not found or hidden." + RESET)
        except Exception as e:
            print(RED + f"  ✘ Error: {e}" + RESET)
            log_exception("whois_dns_check", e)

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
            out = run_text(["dig", "+time=3", "+tries=1", "+short", rtype, domain], timeout=8)
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


# ═══════════════════════════ FEATURE 11: SQLMAP ═══════════════════════════

SQLMAP_TIMEOUT = 600

SqlmapResult = collections.namedtuple("SqlmapResult", "status parameters reason")
# status is one of: "vulnerable", "not_vulnerable", "inconclusive"

_SQLMAP_ERROR_PATTERNS = [
    (re.compile(r"unable to connect to the target url", re.I), "could not connect to the target URL"),
    (re.compile(r"\[CRITICAL\]", re.I), "sqlmap reported a critical error"),
    (re.compile(r"WAF/IPS", re.I), "a WAF/IPS was detected and may have blocked testing"),
    (re.compile(r"all testable parameters.*(?:skip|excluded)", re.I), "sqlmap skipped the parameters"),
    (re.compile(r"no parameter\(s\) (?:found|to test)", re.I), "sqlmap found no testable parameter in the URL"),
    (re.compile(r"connection (?:timed out|refused|reset)", re.I), "a connection error occurred during the scan"),
]

_SQLMAP_SAFE_PATTERNS = [
    re.compile(r"does not seem to be injectable", re.I),
    re.compile(r"all tested parameters do not appear to be injectable", re.I),
    re.compile(r"parameter.*(?:is|appears) not injectable", re.I),
]


def parse_sqlmap_output(text: str) -> SqlmapResult:
    """
    Classify sqlmap's stdout as vulnerable / not_vulnerable / inconclusive.

    A confirmed "Parameter: x (...)" injection point always wins - that is
    sqlmap's own positive finding. A scan is only ever reported "not_vulnerable"
    when sqlmap's own not-injectable verdict is present AND no error/WAF/
    connection-problem line was also seen; the mere ABSENCE of a vulnerable
    match (empty output, a crash, a connection failure) is never enough to
    call a target safe - it falls back to "inconclusive" instead.
    """
    clean = strip_ansi(text or "")
    if not clean.strip():
        return SqlmapResult("inconclusive", [], "sqlmap produced no output")

    vulnerable = []
    for line in clean.splitlines():
        m = re.match(r"^Parameter:\s*(.+?)\s*\(", line.strip())
        if m and m.group(1) not in vulnerable:
            vulnerable.append(m.group(1))
    if vulnerable:
        return SqlmapResult("vulnerable", vulnerable, "")

    for pattern, reason in _SQLMAP_ERROR_PATTERNS:
        if pattern.search(clean):
            return SqlmapResult("inconclusive", [], reason)

    if any(p.search(clean) for p in _SQLMAP_SAFE_PATTERNS):
        return SqlmapResult("not_vulnerable", [], "")

    return SqlmapResult("inconclusive", [], "sqlmap's verdict could not be determined from its output")


def sqlmap_check():
    screen("SQLMAP - SQL INJECTION SCANNER")
    if not has_cmd("sqlmap"):
        print(RED + "  ✘ sqlmap not found!" + RESET)
        print(WHITE + "  Install it with:" + RESET)
        print(CYAN + "    sudo apt install sqlmap" + RESET)
        print(CYAN + "    or: git clone https://github.com/sqlmapproject/sqlmap.git" + RESET)
        pause()
        return

    url = prompt_authorized_target_url(
        "  Enter target URL with a parameter (e.g. http://example.com/page.php?id=1): "
    )
    if url is None:
        return

    width = get_terminal_width()
    sep = "─" * width
    print(CYAN + f"  Scanning: {WHITE}{url}" + RESET)
    print()
    print(CYAN + sep + RESET)

    cmd = ["sqlmap", "-u", url, "--batch", "--random-agent", "--level=5", "--risk=1"]
    with Spinner("Running sqlmap"):
        res = run_command(cmd, timeout=SQLMAP_TIMEOUT)

    if res.interrupted:
        print(YELLOW + "  ⚠ Scan canceled (Ctrl+C) - result is incomplete." + RESET)
    else:
        result = parse_sqlmap_output(res.out)
        if result.status == "vulnerable":
            plural = "" if len(result.parameters) == 1 else "s"
            print(RED + BOLD + f"  ✘ {len(result.parameters)} vulnerable parameter{plural} found:" + RESET)
            print()
            for i, p in enumerate(result.parameters, 1):
                print(RED + f"  [{i:02d}] " + WHITE + p + RESET)
        elif result.status == "not_vulnerable":
            print(GREEN + "  ✔ No injectable parameters found (reported by sqlmap)." + RESET)
        else:
            if res.timed_out:
                print(RED + f"  ✘ Timed out after {fmt_duration(SQLMAP_TIMEOUT)} - result is inconclusive." + RESET)
            else:
                print(YELLOW + f"  ⚠ Inconclusive: {result.reason}." + RESET)
            tail = tail_lines(res.err or res.out, 5)
            if tail:
                print()
                for line in tail:
                    print(WHITE + "    " + line + RESET)
        if res.timed_out and not res.interrupted and result.status != "inconclusive":
            print()
            print(YELLOW + f"  ⚠ Scan stopped after {fmt_duration(SQLMAP_TIMEOUT)} - partial result." + RESET)
    print()
    print(CYAN + sep + RESET)
    pause()


# ═══════════════════════════ FEATURE 12: XSSTRIKE ═══════════════════════════

XSSTRIKE_TIMEOUT = 300


XSStrikeResult = collections.namedtuple("XSStrikeResult", "status findings reason")
# status is one of: "vulnerable", "not_vulnerable", "inconclusive"

# [+] and [!] are XSStrike's generic info/warning prefixes (progress, WAF notices,
# parameter counts, etc.) - NOT findings by themselves. Only count a line as a
# finding when it actually names a vulnerability, and only if it is not a
# negated statement ("not vulnerable", "no vulnerabilities found").
_XSS_VECTOR_RE = re.compile(r"^\s*vector for\b", re.I)
# Exact word "vulnerable" only - NOT "vulnerab\w*", which also matches the plain
# noun "vulnerabilities" used in harmless progress messages ("Checking for DOM
# vulnerabilities"). That broader match was a real false-positive source caught
# by this module's own test suite (see tests/test_roez_tools.py).
_XSS_VULN_WORD_RE = re.compile(r"\bvulnerable\b", re.I)
_XSS_NEGATION_RE = re.compile(r"\b(no|not|n[’']t|zero|0)\b[^.\n]{0,20}\bvulnerable\b", re.I)

_XSS_ERROR_PATTERNS = [
    re.compile(r"traceback \(most recent call last\)", re.I),
    re.compile(r"connectionerror|max retries exceeded", re.I),
    re.compile(r"connection (?:refused|timed out|reset)", re.I),
    re.compile(r"no parameters? to test", re.I),
    re.compile(r"waf detected", re.I),
    re.compile(r"unable to (?:connect|fetch)", re.I),
]

_XSS_SAFE_PATTERNS = [
    re.compile(r"no reflections? found", re.I),
    re.compile(r"\b0\s+reflections\b", re.I),
    re.compile(r"no vulnerabilit(?:y|ies) found", re.I),
]


def parse_xsstrike_output(text: str) -> XSStrikeResult:
    """
    Best-effort classification of XSStrike's stdout as vulnerable / not_vulnerable
    / inconclusive. XSStrike has no single structured "result" line, so this is
    necessarily pattern-based (see the module docstring note in the README); the
    goals are to avoid two specific failure modes:
      - false positive: treating every informational [+]/[!] line as a finding
      - false negative: missing a finding because the line also contains a
        negation ("not vulnerable") is handled by NOT excluding on negation
        alone - only lines that are themselves phrased as a negative verdict
        are excluded, via _XSS_NEGATION_RE.
    When the output doesn't clearly match either verdict, the result is
    "inconclusive" - it is never silently reported as safe.
    """
    clean = strip_ansi(text or "")
    if not clean.strip():
        return XSStrikeResult("inconclusive", [], "XSStrike produced no output")

    findings = []
    for raw in clean.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _XSS_VECTOR_RE.match(line):
            findings.append(line)
        elif _XSS_VULN_WORD_RE.search(line) and not _XSS_NEGATION_RE.search(line):
            findings.append(line)

    seen = set()
    findings = [f for f in findings if not (f in seen or seen.add(f))]
    if findings:
        return XSStrikeResult("vulnerable", findings, "")

    for pattern in _XSS_ERROR_PATTERNS:
        if pattern.search(clean):
            return XSStrikeResult("inconclusive", [], "XSStrike reported a connection/environment problem")

    if any(p.search(clean) for p in _XSS_SAFE_PATTERNS):
        return XSStrikeResult("not_vulnerable", [], "")

    return XSStrikeResult("inconclusive", [], "XSStrike's verdict could not be determined from its output")


def xsstrike_check():
    screen("XSSTRIKE - XSS SCANNER")
    if not has_cmd("xsstrike"):
        print(RED + "  ✘ xsstrike not found!" + RESET)
        print(WHITE + "  Install it with:" + RESET)
        print(CYAN + "    git clone https://github.com/s0md3v/XSStrike.git" + RESET)
        print(CYAN + "    cd XSStrike && pip install -r requirements.txt --break-system-packages" + RESET)
        print(CYAN + "    sudo ln -s \"$(pwd)/xsstrike.py\" /usr/local/bin/xsstrike" + RESET)
        print(CYAN + "    sudo chmod +x /usr/local/bin/xsstrike" + RESET)
        pause()
        return

    url = prompt_authorized_target_url(
        "  Enter target URL with a parameter (e.g. http://example.com/search?q=test): "
    )
    if url is None:
        return

    width = get_terminal_width()
    sep = "─" * width
    print(CYAN + f"  Scanning: {WHITE}{url}" + RESET)
    print()
    print(CYAN + sep + RESET)

    cmd = ["xsstrike", "-u", url, "--skip"]
    with Spinner("Running XSStrike"):
        res = run_command(cmd, timeout=XSSTRIKE_TIMEOUT)

    if res.interrupted:
        print(YELLOW + "  ⚠ Scan canceled (Ctrl+C) - result is incomplete." + RESET)
    else:
        result = parse_xsstrike_output(res.out)
        if result.status == "vulnerable":
            print(RED + BOLD + f"  ✘ {len(result.findings)} finding(s):" + RESET)
            print()
            for i, line in enumerate(result.findings, 1):
                print(RED + f"  [{i:02d}] " + WHITE + line + RESET)
        elif result.status == "not_vulnerable":
            print(GREEN + "  ✔ No XSS findings reported by XSStrike." + RESET)
        else:
            if res.timed_out:
                print(RED + f"  ✘ Timed out after {fmt_duration(XSSTRIKE_TIMEOUT)} - result is inconclusive." + RESET)
            else:
                print(YELLOW + f"  ⚠ Inconclusive: {result.reason}." + RESET)
            tail = tail_lines(res.err or res.out, 4)
            if tail:
                print()
                for line in tail:
                    print(WHITE + "    " + line + RESET)
        if res.timed_out and not res.interrupted and result.status != "inconclusive":
            print()
            print(YELLOW + f"  ⚠ Scan stopped after {fmt_duration(XSSTRIKE_TIMEOUT)} - partial result." + RESET)
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
        "11": sqlmap_check,
        "12": xsstrike_check,
    }

    while True:
        clear()
        print_header()
        print_menu()
        try:
            choice = input(CYAN + "  roez" + WHITE + "@" + GREEN + "tools" + CYAN + " ❯ " + WHITE).strip()
        except (EOFError, KeyboardInterrupt):
            choice = "0"
        print(RESET)
        if choice in actions:
            try:
                actions[choice]()
            except KeyboardInterrupt:
                print()
                print(YELLOW + "  ⚠ Canceled." + RESET)
                time.sleep(0.8)
            except EOFError:
                choice = "0"
            except Exception as e:                      # a bug in one feature must not kill the whole menu
                print(RED + f"  ✘ Unexpected error: {type(e).__name__}: {e}" + RESET)
                log_exception("menu choice %s" % choice, e)
                pause()
        elif choice != "0":
            print(RED + "  ✘ Invalid choice. Press Enter to try again..." + RESET)
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                choice = "0"
        if choice == "0":
            clear()
            print()
            print(CYAN + "  Thank you for using ROEZ TOOLS. Goodbye!" + RESET)
            print()
            sys.exit(0)


if __name__ == "__main__":
    main()
