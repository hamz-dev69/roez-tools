#!/usr/bin/env python3

import os
import sys
import socket
import platform
import subprocess
import json
import threading
import time
import itertools
import ssl
import re

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


def clear():
    os.system("clear")


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


def run_with_spinner(cmd, text="Scanning"):
    done = threading.Event()

    def spin():
        for ch in itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
            if done.is_set():
                break
            sys.stdout.write(f"\r{CYAN}  {ch} {text}...{RESET}")
            sys.stdout.flush()
            time.sleep(0.08)

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
    finally:
        done.set()
        t.join()
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()


def has_cmd(cmd):
    return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def run_text(cmd, timeout=15):
    """Jalankan command, balikin stdout (nggak error walau exit code != 0)."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout.decode(errors="ignore")
    except Exception:
        return ""


def pause():
    print()
    input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)


def screen(title):
    clear()
    print_header()
    width = get_terminal_width()
    print(YELLOW + BOLD + f"  {title}".center(width) + RESET)
    print()


def clean_domain(raw):
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d


def valid_domain(d):
    return bool(re.match(r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", d))


# FITUR 1-5 

def check_ip():
    clear()
    print_header()
    width = get_terminal_width()
    print(YELLOW + BOLD + "  CHECK YOUR IP".center(width) + RESET)
    print()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "Tidak tersedia"
    try:
        public_ip = subprocess.check_output(
            ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        public_ip = "Tidak tersedia (cek koneksi)"
    print(GREEN + f"  Hostname   : {WHITE}{socket.gethostname()}" + RESET)
    print(GREEN + f"  IP Lokal   : {WHITE}{local_ip}" + RESET)
    print(GREEN + f"  IP Publik  : {WHITE}{public_ip}" + RESET)
    print()
    input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)


def search_locate():
    clear()
    print_header()
    width = get_terminal_width()
    print(YELLOW + BOLD + "  SEARCH LOCATE WITH IP".center(width) + RESET)
    print()
    target = input(GREEN + "  Masukkan IP (kosongkan = IP publik sendiri): " + WHITE).strip()
    print(RESET)
    print(CYAN + "  Mengambil informasi..." + RESET)
    print()
    try:
        url = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,isp,org,as,mobile,proxy,hosting,query"
        result = subprocess.check_output(
            ["curl", "-s", "--max-time", "8", url],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        data = json.loads(result)
        if data.get("status") == "fail":
            print(RED + f"  ✘ Gagal: {data.get('message', 'Unknown error')}" + RESET)
        else:
            fields = [
                ("IP          ", data.get("query", "-")),
                ("Negara      ", data.get("country", "-")),
                ("Provinsi    ", data.get("regionName", "-")),
                ("Kota        ", data.get("city", "-")),
                ("Kode Pos    ", data.get("zip", "-")),
                ("ISP         ", data.get("isp", "-")),
                ("Organisasi  ", data.get("org", "-")),
                ("AS          ", data.get("as", "-")),
                ("Mobile/Data ", "Ya" if data.get("mobile") else "Tidak"),
                ("Proxy/VPN   ", "Ya" if data.get("proxy") else "Tidak"),
                ("Hosting     ", "Ya" if data.get("hosting") else "Tidak"),
            ]
            for label, value in fields:
                print(GREEN + f"  {label}: {WHITE}{value}" + RESET)
    except FileNotFoundError:
        print(RED + "  ✘ curl tidak ditemukan. Install: sudo apt install curl" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
    print()
    input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)


def check_system():
    clear()
    print_header()
    width = get_terminal_width()
    print(YELLOW + BOLD + "  CHECK SYSTEM".center(width) + RESET)
    print()
    for cmd in ["neofetch", "fastfetch"]:
        if subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            subprocess.call([cmd])
            print()
            input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)
            return
    print(YELLOW + "  ⚠ neofetch tidak ditemukan. Info manual:" + RESET)
    print()
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
        ("OS         ", platform.system() + " " + platform.release()),
        ("Distro     ", distro),
        ("Hostname   ", platform.node()),
        ("Arsitektur ", platform.machine()),
        ("Processor  ", platform.processor() or "N/A"),
        ("Python     ", platform.python_version()),
    ]
    for label, value in info:
        print(GREEN + f"  {label}: {WHITE}{value}" + RESET)
    print()
    print(YELLOW + "  Tip install neofetch: sudo apt install neofetch" + RESET)
    print()
    input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)


def holehe_check():
    clear()
    print_header()
    width = get_terminal_width()
    print(YELLOW + BOLD + "  HOLEHE - EMAIL OSINT".center(width) + RESET)
    print()
    if subprocess.call(["which", "holehe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print(RED + "  ✘ holehe tidak ditemukan!" + RESET)
        print(WHITE + "  Install dengan perintah:" + RESET)
        print(CYAN + "    pip3 install holehe --break-system-packages" + RESET)
        print()
        input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)
        return
    email = input(GREEN + "  Masukkan email target: " + WHITE).strip()
    if not email or "@" not in email:
        print(RED + "  ✘ Email tidak valid!" + RESET)
        print()
        input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)
        return
    print()
    print(CYAN + f"  Scanning email: {WHITE}{email}" + RESET)
    print()
    sep = "─" * width
    print(CYAN + sep + RESET)
    try:
        result = run_with_spinner(["holehe", email], "Scanning email")
        found = []
        for line in result.splitlines():
            line_strip = line.strip()
            if "[+]" in line_strip:
                platform_name = line_strip.replace("[+]", "").strip()
                if platform_name:
                    found.append(platform_name)
        if found:
            print(GREEN + BOLD + f"  ✔ Email [{email}] terdaftar di {len(found)} platform:" + RESET)
            print()
            for i, p in enumerate(found, 1):
                print(GREEN + f"  [{i:02d}] " + WHITE + p + RESET)
        else:
            print(YELLOW + f"  ⚠ Tidak ada platform yang ditemukan untuk: {email}" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
    print()
    print(CYAN + sep + RESET)
    print()
    input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)


def sherlock_check():
    clear()
    print_header()
    width = get_terminal_width()
    print(YELLOW + BOLD + "  SHERLOCK - USERNAME OSINT".center(width) + RESET)
    print()

    sherlock_cmd = None
    for cmd in ["sherlock"]:
        if subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            sherlock_cmd = cmd
            break

    if not sherlock_cmd:

        try:
            subprocess.check_output(
                ["python3", "-m", "sherlock", "--help"],
                stderr=subprocess.DEVNULL
            )
            sherlock_cmd = "module"
        except Exception:
            pass

    if not sherlock_cmd:
        print(RED + "  ✘ sherlock tidak ditemukan!" + RESET)
        print(WHITE + "  Install dengan perintah:" + RESET)
        print(CYAN + "    pip3 install sherlock-project --break-system-packages" + RESET)
        print(WHITE + "  atau:" + RESET)
        print(CYAN + "    pip install sherlock-project" + RESET)
        print()
        input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)
        return

    username = input(GREEN + "  Masukkan username target: " + WHITE).strip()
    if not username:
        print(RED + "  ✘ Username tidak boleh kosong!" + RESET)
        print()
        input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)
        return

    print()
    print(CYAN + f"  Scanning username: {WHITE}{username}" + RESET)
    print()
    sep = "─" * width
    print(CYAN + sep + RESET)

    try:
        if sherlock_cmd == "module":
            cmd_list = ["python3", "-m", "sherlock", username]
        else:
            cmd_list = ["sherlock", username]

        result = run_with_spinner(cmd_list, "Scanning username")

        found = []
        for line in result.splitlines():
            line_strip = line.strip()

            if "[+]" in line_strip:

                parts = line_strip.replace("[+]", "").strip()
                found.append(parts)

        if found:
            print(GREEN + BOLD + f"  ✔ Username [{username}] ditemukan di {len(found)} platform:" + RESET)
            print()
            for i, p in enumerate(found, 1):
                print(GREEN + f"  [{i:02d}] " + WHITE + p + RESET)
        else:
            print(YELLOW + f"  ⚠ Username [{username}] tidak ditemukan di platform manapun." + RESET)

    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)

    print()
    print(CYAN + sep + RESET)
    print()
    input(CYAN + "  Tekan Enter untuk kembali ke menu..." + RESET)


# ─────────────────────────── FITUR 6-10 (BARU) ───────────────────────────

def phone_osint():
    screen("PHONE NUMBER OSINT")
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
    except ImportError:
        print(RED + "  ✘ library phonenumbers tidak ditemukan!" + RESET)
        print(WHITE + "  Install dengan perintah:" + RESET)
        print(CYAN + "    pip3 install phonenumbers --break-system-packages" + RESET)
        pause()
        return

    raw = input(GREEN + "  Masukkan nomor (contoh: +6281234567890 / 081234567890): " + WHITE).strip()
    print(RESET)
    if not raw:
        print(RED + "  ✘ Nomor tidak boleh kosong!" + RESET)
        pause()
        return

    try:
        num = phonenumbers.parse(raw, "ID")
    except Exception as e:
        print(RED + f"  ✘ Format nomor tidak valid: {e}" + RESET)
        pause()
        return

    types = {
        phonenumbers.PhoneNumberType.MOBILE: "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line / Mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
        phonenumbers.PhoneNumberType.VOIP: "VoIP",
        phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
    }
    ntype = phonenumbers.number_type(num)
    tz = ", ".join(timezone.time_zones_for_number(num)) or "-"
    fields = [
        ("Valid        ", "Ya" if phonenumbers.is_valid_number(num) else "Tidak"),
        ("Internasional", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)),
        ("Nasional     ", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)),
        ("Kode Negara  ", f"+{num.country_code}"),
        ("Wilayah      ", geocoder.description_for_number(num, "id") or "-"),
        ("Operator     ", carrier.name_for_number(num, "id") or "-"),
        ("Tipe         ", types.get(ntype, "Lainnya")),
        ("Zona Waktu   ", tz),
    ]
    for label, value in fields:
        print(GREEN + f"  {label}: {WHITE}{value}" + RESET)
    pause()


def exif_check():
    screen("EXIFTOOL - METADATA READER")
    if not has_cmd("exiftool"):
        print(RED + "  ✘ exiftool tidak ditemukan!" + RESET)
        print(WHITE + "  Install dengan perintah:" + RESET)
        print(CYAN + "    sudo apt install libimage-exiftool-perl" + RESET)
        pause()
        return

    path = input(GREEN + "  Masukkan path file: " + WHITE).strip().strip("'\"")
    print(RESET)
    path = os.path.expanduser(path)
    if not path or not os.path.isfile(path):
        print(RED + "  ✘ File tidak ditemukan!" + RESET)
        pause()
        return

    width = get_terminal_width()
    sep = "─" * width
    print(CYAN + sep + RESET)
    try:
        result = run_with_spinner(["exiftool", path], "Membaca metadata")
        lines = [l for l in result.splitlines() if ":" in l]
        if not lines:
            print(YELLOW + "  ⚠ Tidak ada metadata yang ditemukan." + RESET)
        else:
            print(GREEN + BOLD + f"  ✔ {len(lines)} field metadata ditemukan:" + RESET)
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
                print(YELLOW + "  ⚠ File ini mengandung data lokasi GPS." + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
    print()
    print(CYAN + sep + RESET)
    pause()


def subfinder_check():
    screen("SUBFINDER - SUBDOMAIN FINDER")
    if not has_cmd("subfinder"):
        print(RED + "  ✘ subfinder tidak ditemukan!" + RESET)
        print(WHITE + "  Install dengan perintah:" + RESET)
        print(CYAN + "    sudo apt install subfinder" + RESET)
        print(WHITE + "  atau:" + RESET)
        print(CYAN + "    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" + RESET)
        pause()
        return

    domain = clean_domain(input(GREEN + "  Masukkan domain target (contoh: example.com): " + WHITE))
    print(RESET)
    if not valid_domain(domain):
        print(RED + "  ✘ Domain tidak valid!" + RESET)
        pause()
        return

    print(CYAN + f"  Scanning domain: {WHITE}{domain}" + RESET)
    print()
    width = get_terminal_width()
    sep = "─" * width
    print(CYAN + sep + RESET)
    try:
        result = run_with_spinner(["subfinder", "-d", domain, "-silent"], "Mencari subdomain")
        found = sorted(set(l.strip() for l in result.splitlines() if l.strip()))
        if found:
            print(GREEN + BOLD + f"  ✔ Ditemukan {len(found)} subdomain untuk [{domain}]:" + RESET)
            print()
            for i, s in enumerate(found, 1):
                print(GREEN + f"  [{i:02d}] " + WHITE + s + RESET)
        else:
            print(YELLOW + f"  ⚠ Tidak ada subdomain yang ditemukan untuk: {domain}" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)
    print()
    print(CYAN + sep + RESET)
    pause()


def headers_ssl_check():
    screen("SECURITY HEADERS + SSL CHECKER")
    host = clean_domain(input(GREEN + "  Masukkan domain (contoh: example.com): " + WHITE))
    print(RESET)
    if not valid_domain(host):
        print(RED + "  ✘ Domain tidak valid!" + RESET)
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
            "Mengambil headers"
        )
        blocks = [b for b in raw.replace("\r", "").split("\n\n") if b.strip()]
        if not blocks:
            raise ValueError("Tidak ada response dari server")
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
                print(RED + f"  ✘ {label}: {YELLOW}tidak ada" + RESET)
        print()
        color = GREEN if score >= 5 else (YELLOW if score >= 3 else RED)
        print(color + BOLD + f"  Skor: {score}/{len(checks)} header keamanan aktif" + RESET)
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

        print(GREEN + f"  Common Name : {WHITE}{subject.get('commonName', '-')}" + RESET)
        print(GREEN + f"  Issuer      : {WHITE}{issuer.get('organizationName', issuer.get('commonName', '-'))}" + RESET)
        print(GREEN + f"  Berlaku dari: {WHITE}{cert.get('notBefore', '-')}" + RESET)
        print(GREEN + f"  Berlaku s/d : {WHITE}{cert.get('notAfter', '-')}" + RESET)
        print(GREEN + f"  TLS Version : {WHITE}{tls_version}" + RESET)
        print(GREEN + f"  SAN         : {WHITE}{len(sans)} domain" + RESET)
        print()
        if days_left < 0:
            print(RED + BOLD + f"  ✘ Sertifikat sudah EXPIRED {abs(days_left)} hari lalu!" + RESET)
        elif days_left < 30:
            print(YELLOW + BOLD + f"  ⚠ Sertifikat akan expired dalam {days_left} hari" + RESET)
        else:
            print(GREEN + BOLD + f"  ✔ Sertifikat valid, sisa {days_left} hari" + RESET)
    except ssl.SSLCertVerificationError as e:
        print(RED + f"  ✘ Sertifikat tidak valid: {e.verify_message}" + RESET)
    except Exception as e:
        print(RED + f"  ✘ Error: {e}" + RESET)

    print()
    print(CYAN + sep + RESET)
    pause()


def whois_dns_check():
    screen("WHOIS + DNS LOOKUP")
    domain = clean_domain(input(GREEN + "  Masukkan domain (contoh: example.com): " + WHITE))
    print(RESET)
    if not valid_domain(domain):
        print(RED + "  ✘ Domain tidak valid!" + RESET)
        pause()
        return

    width = get_terminal_width()
    sep = "─" * width

    # ---- WHOIS ----
    print(CYAN + sep + RESET)
    print(YELLOW + BOLD + "  WHOIS" + RESET)
    print()
    if not has_cmd("whois"):
        print(RED + "  ✘ whois tidak ditemukan!" + RESET)
        print(CYAN + "    Install: sudo apt install whois" + RESET)
    else:
        try:
            result = run_with_spinner(["whois", domain], "Mengambil data whois")
            wanted = [
                ("domain name", "Domain      "),
                ("registrar:", "Registrar   "),
                ("creation date", "Dibuat      "),
                ("updated date", "Diupdate    "),
                ("registry expiry date", "Expired     "),
                ("expiry date", "Expired     "),
                ("registrant organization", "Organisasi  "),
                ("registrant country", "Negara      "),
                ("domain status", "Status      "),
                ("name server", "Nameserver  "),
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
                            print(GREEN + f"  {label}: {WHITE}{val}" + RESET)
                        break
            if count == 0:
                print(YELLOW + "  ⚠ Data whois tidak ditemukan / disembunyikan." + RESET)
        except Exception as e:
            print(RED + f"  ✘ Error: {e}" + RESET)

    # ---- DNS ----
    print()
    print(CYAN + sep + RESET)
    print(YELLOW + BOLD + "  DNS RECORDS" + RESET)
    print()
    if not has_cmd("dig"):
        print(RED + "  ✘ dig tidak ditemukan!" + RESET)
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
                print(YELLOW + f"  {rtype}: tidak ada record" + RESET)
            print()

    print(CYAN + sep + RESET)
    pause()


# ─────────────────────────── MAIN ───────────────────────────

def main():
    while True:
        clear()
        print_header()
        print_menu()
        choice = input(CYAN + "  roez" + WHITE + "@" + GREEN + "tools" + CYAN + " ❯ " + WHITE).strip()
        print(RESET)
        if choice == "1":
            check_ip()
        elif choice == "2":
            search_locate()
        elif choice == "3":
            check_system()
        elif choice == "4":
            holehe_check()
        elif choice == "5":
            sherlock_check()
        elif choice == "6":
            phone_osint()
        elif choice == "7":
            exif_check()
        elif choice == "8":
            subfinder_check()
        elif choice == "9":
            headers_ssl_check()
        elif choice == "10":
            whois_dns_check()
        elif choice == "11":
            clear()
            print()
            print(CYAN + "  Terima kasih telah menggunakan ROEZ TOOLS. Sampai jumpa!" + RESET)
            print()
            sys.exit(0)
        else:
            print(RED + "  ✘ Pilihan tidak valid. Tekan Enter untuk coba lagi..." + RESET)
            input()


if __name__ == "__main__":
    main()
