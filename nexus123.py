import io
import os
import re
import csv
import sys
import glob
import hmac
import json
import time
import uuid
import shutil
import random
import socket
import base64
import ctypes
import struct
import hashlib
import secrets
import statistics
import urllib.request
from ctypes import wintypes
import tempfile
import threading
import subprocess
import winreg
from collections import deque
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# =====================================================================
# ADMIN ELEVATION & CORE HELPERS
# =====================================================================

REGISTRY_ADAPTER_PATH = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
NETLIST_PROFILES_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
CRYPTO_PATH = r"SOFTWARE\Microsoft\Cryptography"
HWPROFILE_PATH = r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def ensure_admin():
    if os.name == "nt" and not is_admin():
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        sys.exit(0)

def run_cmd(cmd):
    return subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    )

def ps_quote(value):
    # Werte nur als PowerShell-Literal einbetten, damit Client-Eingaben keine Befehle einschleusen
    return "'" + str(value).replace('"', "").replace("'", "''") + "'"

HOSTNAME_RE = re.compile(r"^(?![0-9]+$)[A-Za-z0-9-]{1,15}$")
MAC_RE = re.compile(r"^[0-9A-F]{12}$")

def validate_hostname(name):
    if not HOSTNAME_RE.match(name or ""):
        raise ValueError("Ungültiger Hostname: 1–15 Zeichen, nur A–Z, 0–9 und '-'")
    return name

def resolve_mac(payload):
    raw = (payload.get("custom_mac") or "").strip()
    if not raw:
        return generate_mac(payload.get("vendor", "random"))
    clean = raw.replace(":", "").replace("-", "").upper()
    if not MAC_RE.match(clean):
        raise ValueError(f"Ungültige MAC-Adresse: {raw}")
    return clean

def resolve_hostname(payload):
    custom = (payload.get("custom_host") or "").strip()
    return validate_hostname(custom) if custom else generate_hostname(payload.get("profile", "desktop"))

# =====================================================================
# TELEMETRY & SYSTEM STATUS
# =====================================================================

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

def get_memory_info():
    try:
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        total_gb = round(stat.ullTotalPhys / (1024 ** 3), 1)
        used_gb = round((stat.ullTotalPhys - stat.ullAvailPhys) / (1024 ** 3), 1)
        return {"percent": stat.dwMemoryLoad, "total_gb": total_gb, "used_gb": used_gb}
    except Exception:
        return {"percent": 0, "total_gb": 0, "used_gb": 0}

def get_disk_info():
    try:
        total, used, free = shutil.disk_usage("C:\\")
        percent = int((used / total) * 100)
        return {
            "percent": percent,
            "free_gb": round(free / (1024 ** 3), 1),
            "total_gb": round(total / (1024 ** 3), 1)
        }
    except Exception:
        return {"percent": 0, "free_gb": 0, "total_gb": 0}

def get_uptime_str():
    try:
        GetTickCount64 = ctypes.windll.kernel32.GetTickCount64
        GetTickCount64.restype = ctypes.c_ulonglong
        ms = GetTickCount64()
        secs = int(ms // 1000)
        days, rem = divmod(secs, 86400)
        hrs, rem = divmod(rem, 3600)
        mins, _ = divmod(rem, 60)
        return f"{days}d {hrs}h {mins}m" if days else f"{hrs}h {mins}m"
    except Exception:
        return "N/A"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Disconnected"

_GATEWAY_CACHE = {"value": "N/A", "ts": 0.0}

def get_gateway_ip(max_age=30):
    # PowerShell-Start ist teuer; bei Auto-Refresh nur alle max_age Sekunden neu abfragen
    if time.time() - _GATEWAY_CACHE["ts"] < max_age:
        return _GATEWAY_CACHE["value"]
    try:
        res = run_cmd('powershell -NoProfile -Command "(Get-NetRoute -DestinationPrefix \'0.0.0.0/0\' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"')
        gw = res.stdout.strip()
        gw = gw if gw else "N/A"
    except Exception:
        gw = "N/A"
    _GATEWAY_CACHE["value"] = gw
    _GATEWAY_CACHE["ts"] = time.time()
    return gw

def get_current_hostname():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as key:
            val, _ = winreg.QueryValueEx(key, "NV Hostname")
            return val
    except Exception:
        return os.environ.get("COMPUTERNAME", "UNKNOWN")

def get_volume_serial(drive="C:"):
    try:
        vol_name_buf = ctypes.create_unicode_buffer(1024)
        fs_name_buf = ctypes.create_unicode_buffer(1024)
        serial_num = wintypes.DWORD()
        max_comp_len = wintypes.DWORD()
        fs_flags = wintypes.DWORD()
        rc = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(f"{drive}\\"),
            vol_name_buf, ctypes.sizeof(vol_name_buf),
            ctypes.byref(serial_num),
            ctypes.byref(max_comp_len),
            ctypes.byref(fs_flags),
            fs_name_buf, ctypes.sizeof(fs_name_buf)
        )
        if rc:
            val = serial_num.value
            return f"{val >> 16:04X}-{val & 0xFFFF:04X}"
    except Exception:
        pass
    return "N/A"

# ---------------------------------------------------------------------
# Live-Monitor: CPU, RAM und Netzwerkdurchsatz der letzten 60 Sekunden
# ---------------------------------------------------------------------

class MIB_IF_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", wintypes.ULONG),
        ("InterfaceGuid", ctypes.c_ubyte * 16),
        ("Alias", ctypes.c_wchar * 257),
        ("Description", ctypes.c_wchar * 257),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", wintypes.ULONG),
        ("Type", wintypes.ULONG),
        ("TunnelType", ctypes.c_int),
        ("MediaType", ctypes.c_int),
        ("PhysicalMediumType", ctypes.c_int),
        ("AccessType", ctypes.c_int),
        ("DirectionType", ctypes.c_int),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", ctypes.c_int),
        ("AdminStatus", ctypes.c_int),
        ("MediaConnectState", ctypes.c_int),
        ("NetworkGuid", ctypes.c_ubyte * 16),
        ("ConnectionType", ctypes.c_int),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("InOctets", ctypes.c_uint64),
        ("InUcastPkts", ctypes.c_uint64),
        ("InNUcastPkts", ctypes.c_uint64),
        ("InDiscards", ctypes.c_uint64),
        ("InErrors", ctypes.c_uint64),
        ("InUnknownProtos", ctypes.c_uint64),
        ("InUcastOctets", ctypes.c_uint64),
        ("InMulticastOctets", ctypes.c_uint64),
        ("InBroadcastOctets", ctypes.c_uint64),
        ("OutOctets", ctypes.c_uint64),
        ("OutUcastPkts", ctypes.c_uint64),
        ("OutNUcastPkts", ctypes.c_uint64),
        ("OutDiscards", ctypes.c_uint64),
        ("OutErrors", ctypes.c_uint64),
        ("OutUcastOctets", ctypes.c_uint64),
        ("OutMulticastOctets", ctypes.c_uint64),
        ("OutBroadcastOctets", ctypes.c_uint64),
        ("OutQLen", ctypes.c_uint64),
    ]

class MIB_IF_TABLE2(ctypes.Structure):
    _fields_ = [("NumEntries", wintypes.ULONG), ("Table", MIB_IF_ROW2 * 1)]

def get_cpu_times():
    idle, kernel, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
    ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
    as_int = lambda ft: (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    # Kernel-Zeit enthält die Idle-Zeit bereits
    return as_int(idle), as_int(kernel) + as_int(user)

def get_net_bytes():
    table = ctypes.POINTER(MIB_IF_TABLE2)()
    if ctypes.windll.iphlpapi.GetIfTable2(ctypes.byref(table)) != 0:
        return 0, 0
    try:
        rows = ctypes.cast(table.contents.Table, ctypes.POINTER(MIB_IF_ROW2))
        rx = tx = 0
        for i in range(table.contents.NumEntries):
            row = rows[i]
            flags = row.InterfaceAndOperStatusFlags
            # Nur echte Hardware-Adapter; Filter-Interfaces (QoS, WFP …) würden denselben Traffic mehrfach zählen
            if (flags & 0x01) and not (flags & 0x02) and row.OperStatus == 1:
                rx += row.InOctets
                tx += row.OutOctets
        return rx, tx
    finally:
        ctypes.windll.iphlpapi.FreeMibTable(table)

MONITOR_POINTS = 60
MONITOR = {k: deque(maxlen=MONITOR_POINTS) for k in ("cpu", "ram", "down", "up", "gpu")}
MONITOR_VIEWED = {"last": 0.0}  # letzte /api/monitor-Abfrage; GPU nur messen, solange jemand hinschaut

_SMI_DEFAULT = r"C:\Windows\System32\nvidia-smi.exe"
NVIDIA_SMI = shutil.which("nvidia-smi") or (_SMI_DEFAULT if os.path.exists(_SMI_DEFAULT) else None)
GPU_STATE = {"available": bool(NVIDIA_SMI), "name": None, "util": None, "temp": None,
             "mem_used": None, "mem_total": None, "power": None, "ts": 0.0}

def gpu_loop():
    num = lambda s: float(s) if re.fullmatch(r"\d+(\.\d+)?", s) else None
    while True:
        time.sleep(2)
        # nvidia-smi ist ein eigener Prozessstart, deshalb nicht dauerhaft im Hintergrund
        if time.time() - MONITOR_VIEWED["last"] > 6:
            continue
        try:
            res = subprocess.run(
                [NVIDIA_SMI, "--query-gpu=name,utilization.gpu,temperature.gpu,memory.used,memory.total,power.draw",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
            )
            name, util, temp, used, total, power = [x.strip() for x in res.stdout.strip().splitlines()[0].split(",")]
            GPU_STATE.update(name=name, util=num(util), temp=num(temp), mem_used=num(used),
                             mem_total=num(total), power=num(power), ts=time.time())
        except Exception:
            pass

if NVIDIA_SMI:
    threading.Thread(target=gpu_loop, daemon=True).start()

def monitor_loop():
    prev = None
    while True:
        try:
            idle, total = get_cpu_times()
            rx, tx = get_net_bytes()
            cur = {"idle": idle, "total": total, "rx": rx, "tx": tx, "ts": time.time()}
            if prev:
                dt = max(cur["ts"] - prev["ts"], 0.001)
                d_total = cur["total"] - prev["total"]
                busy = 1 - (cur["idle"] - prev["idle"]) / d_total if d_total > 0 else 0
                MONITOR["cpu"].append(round(min(max(busy * 100, 0), 100), 1))
                MONITOR["ram"].append(get_memory_info()["percent"])
                # max(..., 0): Zähler springen zurück, wenn ein Adapter neu startet (z. B. nach MAC-Wechsel)
                MONITOR["down"].append(round(max(cur["rx"] - prev["rx"], 0) / dt / 1024, 1))
                MONITOR["up"].append(round(max(cur["tx"] - prev["tx"], 0) / dt / 1024, 1))
                # None = Lücke im Graphen, solange niemand zugeschaut hat (keine veralteten Werte zeigen)
                fresh = time.time() - GPU_STATE["ts"] < 5
                MONITOR["gpu"].append(GPU_STATE["util"] if fresh else None)
            prev = cur
        except Exception:
            pass
        time.sleep(1)

threading.Thread(target=monitor_loop, daemon=True).start()

# =====================================================================
# MODULE 1: NETWORK & HARDWARE SPOOFER
# =====================================================================

ORIGINAL_IDS_BACKUP = {"machine_guid": None, "hw_guid": None, "hostname": None, "captured_at": None}
BACKUP_FILE = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "NexusOS", "original_ids.json")

def load_original_backup():
    # Originale müssen App-Neustarts überleben, sonst hält "Wiederherstellen" nach einem
    # Neustart die bereits gespooften Werte für die Originale
    try:
        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k in ORIGINAL_IDS_BACKUP:
            if data.get(k):
                ORIGINAL_IDS_BACKUP[k] = data[k]
        return
    except (OSError, ValueError):
        pass
    get_system_guids()
    ORIGINAL_IDS_BACKUP["hostname"] = get_current_hostname()
    ORIGINAL_IDS_BACKUP["captured_at"] = datetime.now().strftime("%d.%m.%Y %H:%M")
    try:
        os.makedirs(os.path.dirname(BACKUP_FILE), exist_ok=True)
        with open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(ORIGINAL_IDS_BACKUP, f, indent=2)
    except OSError:
        pass

def get_network_adapters():
    adapters = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REGISTRY_ADAPTER_PATH) as key:
            for i in range(120):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                except OSError:
                    break
                if subkey_name == "Properties":
                    continue
                # Fehler bei einzelnen Adapter-Keys (fehlende DriverDesc, Zugriff verweigert)
                # dürfen die Enumeration nicht abbrechen
                try:
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        desc, _ = winreg.QueryValueEx(subkey, "DriverDesc")
                        if any(x in desc.lower() for x in ["wan miniport", "virtual", "loopback", "bluetooth", "hyper-v", "tap-windows"]):
                            continue
                        try:
                            curr_mac, _ = winreg.QueryValueEx(subkey, "NetworkAddress")
                        except FileNotFoundError:
                            curr_mac = "HARDWARE"
                        adapters.append({"id": subkey_name, "name": desc, "mac": curr_mac})
                except OSError:
                    continue
    except Exception:
        pass
    return adapters

def get_adapter_desc(subkey_name):
    # Adapter-Beschreibung aus der Registry lesen statt dem Wert aus dem Request zu vertrauen
    if not re.fullmatch(r"\d{4}", str(subkey_name or "")):
        raise ValueError("Ungültiger Adapter-Schlüssel")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{REGISTRY_ADAPTER_PATH}\\{subkey_name}") as key:
        desc, _ = winreg.QueryValueEx(key, "DriverDesc")
    return desc

def generate_mac(vendor="random"):
    prefixes = {
        "random":  [0x02, random.randint(0x10, 0xFE), random.randint(0x00, 0xFF)],
        "apple":   [0x02, 0x1B, 0x63],
        "intel":   [0x02, 0x15, 0x17],
        "samsung": [0x02, 0x16, 0x32],
        "realtek": [0x02, 0xE0, 0x4C],
        "asus":    [0x02, 0x1A, 0x92]
    }
    head = prefixes.get(vendor, prefixes["random"])
    tail = [random.randint(0x00, 0xFF) for _ in range(3)]
    return "".join(f"{b:02X}" for b in (head + tail))

def generate_hostname(profile="desktop"):
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
    num = "".join(random.choice("0123456789") for _ in range(3))
    alphanum = "".join(random.choice(chars) for _ in range(7))
    profiles = {
        "desktop": f"DESKTOP-{alphanum}",
        "iphone":  f"iPhone-{num}",
        "galaxy":  f"Galaxy-S25-{num}",
        "macbook": f"MacBookPro-{alphanum[:4]}",
        "arch":    f"arch-{alphanum[:5].lower()}",
        "work":    f"CORP-LT-{num}"
    }
    return profiles.get(profile, f"DESKTOP-{alphanum}")

def apply_mac(subkey_name, adapter_desc, new_mac=None):
    key_path = f"{REGISTRY_ADAPTER_PATH}\\{subkey_name}"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
        if new_mac:
            clean_mac = new_mac.replace(":", "").replace("-", "").upper()[:12]
            winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, clean_mac)
        else:
            try:
                winreg.DeleteValue(key, "NetworkAddress")
            except FileNotFoundError:
                pass
    run_cmd(f'powershell -NoProfile -Command "Get-NetAdapter | Where-Object {{$_.InterfaceDescription -eq {ps_quote(adapter_desc)}}} | Restart-NetAdapter"')
    time.sleep(1.2)

def apply_hostname(new_name):
    validate_hostname(new_name)
    reg_paths = [
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    ]
    for path in reg_paths:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_ALL_ACCESS) as key:
            if "Tcpip" in path:
                winreg.SetValueEx(key, "Hostname", 0, winreg.REG_SZ, new_name)
                winreg.SetValueEx(key, "NV Hostname", 0, winreg.REG_SZ, new_name)
            else:
                winreg.SetValueEx(key, "ComputerName", 0, winreg.REG_SZ, new_name)
    run_cmd(f'powershell -NoProfile -Command "Rename-Computer -NewName {ps_quote(new_name)} -Force"')

def get_system_guids():
    m_guid, hw_guid = "N/A", "N/A"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CRYPTO_PATH) as k:
            m_guid, _ = winreg.QueryValueEx(k, "MachineGuid")
            if ORIGINAL_IDS_BACKUP["machine_guid"] is None:
                ORIGINAL_IDS_BACKUP["machine_guid"] = m_guid
    except Exception:
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, HWPROFILE_PATH) as k:
            hw_guid, _ = winreg.QueryValueEx(k, "HwProfileGuid")
            if ORIGINAL_IDS_BACKUP["hw_guid"] is None:
                ORIGINAL_IDS_BACKUP["hw_guid"] = hw_guid
    except Exception:
        pass
    return {"machine_guid": m_guid, "hw_guid": hw_guid}

def spoof_system_guids(restore=False):
    get_system_guids()
    if restore:
        # Ohne gesichertes Original wird nichts geschrieben (früher: neue Zufalls-GUID)
        new_m, new_hw = ORIGINAL_IDS_BACKUP["machine_guid"], ORIGINAL_IDS_BACKUP["hw_guid"]
    else:
        new_m, new_hw = str(uuid.uuid4()), "{" + str(uuid.uuid4()) + "}"
    if new_m:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CRYPTO_PATH, 0, winreg.KEY_ALL_ACCESS) as k:
                winreg.SetValueEx(k, "MachineGuid", 0, winreg.REG_SZ, new_m)
        except Exception:
            pass
    if new_hw:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, HWPROFILE_PATH, 0, winreg.KEY_ALL_ACCESS) as k:
                winreg.SetValueEx(k, "HwProfileGuid", 0, winreg.REG_SZ, new_hw)
        except Exception:
            pass
    return get_system_guids()

def restore_original_identity():
    restored = []
    current = get_system_guids()
    if any(ORIGINAL_IDS_BACKUP[k] and ORIGINAL_IDS_BACKUP[k] != current[k] for k in ("machine_guid", "hw_guid")):
        spoof_system_guids(restore=True)
        restored.append("System-GUIDs")
    host = ORIGINAL_IDS_BACKUP["hostname"]
    if host and host.upper() != get_current_hostname().upper():
        apply_hostname(host)
        restored.append(f"Hostname {host} (nach Neustart aktiv)")
    for a in get_network_adapters():
        if a["mac"] != "HARDWARE":
            apply_mac(a["id"], a["name"], None)
            restored.append(f"MAC {a['name']}")
    return restored

def flush_network():
    run_cmd("ipconfig /release")
    run_cmd("ipconfig /flushdns")
    run_cmd("arp -d *")
    run_cmd("nbtstat -R")
    run_cmd("nbtstat -RR")
    run_cmd("ipconfig /renew")

def clean_network_profiles():
    removed = 0
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NETLIST_PROFILES_PATH, 0, winreg.KEY_ALL_ACCESS) as key:
            subkeys = []
            for i in range(200):
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                except OSError:
                    break
            for sk in subkeys:
                try:
                    winreg.DeleteKey(key, sk)
                    removed += 1
                except OSError:
                    pass
    except Exception:
        pass
    run_cmd("netsh winsock reset")
    return removed

def apply_dns(adapter_desc, provider):
    dns_map = {
        "cloudflare": ("1.1.1.1", "1.0.0.1"),
        "quad9":      ("9.9.9.9", "149.112.112.112"),
        "mullvad":    ("194.242.2.2", "194.242.2.3"),
        "adguard":    ("94.140.14.14", "94.140.15.15"),
        "google":     ("8.8.8.8", "8.8.4.4"),
        "opendns":    ("208.67.222.222", "208.67.220.220")
    }
    if provider == "dhcp":
        cmd = f'powershell -NoProfile -Command "Get-NetAdapter | Where-Object {{$_.InterfaceDescription -eq {ps_quote(adapter_desc)}}} | Set-DnsClientServerAddress -ResetServerAddresses"'
    else:
        p1, p2 = dns_map.get(provider, ("1.1.1.1", "1.0.0.1"))
        cmd = f'powershell -NoProfile -Command "Get-NetAdapter | Where-Object {{$_.InterfaceDescription -eq {ps_quote(adapter_desc)}}} | Set-DnsClientServerAddress -ServerAddresses (\'{p1}\',\'{p2}\')"'
    run_cmd(cmd)
    run_cmd("ipconfig /flushdns")

# =====================================================================
# MODULE 2: POWER & RUHEZUSTAND MANAGER
# =====================================================================

POWER_STATE = {
    "running": False,
    "action": "Herunterfahren",
    "total_seconds": 0,
    "remaining_seconds": 0,
    "target_time_str": "—",
    "force": False,
    "test_mode": False,
    "last_message": "BEREIT – KEIN TIMER AKTIV",
    "caffeine_active": False
}

CAFFEINE_WAKE = threading.Event()

def caffeine_loop():
    # SetThreadExecutionState gilt nur, solange der aufrufende Thread lebt. Die HTTP-Handler-Threads
    # enden nach jeder Anfrage, deshalb hält dieser dauerhafte Thread den Wach-Zustand.
    while True:
        flags = 0x80000000 | (0x00000001 | 0x00000002 if POWER_STATE["caffeine_active"] else 0)
        try:
            ctypes.windll.kernel32.SetThreadExecutionState(flags)
        except Exception:
            pass
        CAFFEINE_WAKE.wait(60)
        CAFFEINE_WAKE.clear()

threading.Thread(target=caffeine_loop, daemon=True).start()

def toggle_caffeine_mode(enable: bool):
    POWER_STATE["caffeine_active"] = bool(enable)
    CAFFEINE_WAKE.set()
    return POWER_STATE["caffeine_active"]

def execute_power_action(action, force=False, test_mode=False):
    if test_mode:
        POWER_STATE["last_message"] = f"TEST ERFOLGREICH: '{action}' WÜRDE JETZT AUSGEFÜHRT"
        return
    POWER_STATE["last_message"] = f"FÜHRE AUS: {action.upper()}..."
    force_flag = "/f" if force else ""
    if action == "Herunterfahren":
        os.system(f"shutdown /s /t 0 {force_flag}")
    elif action == "Neustarten":
        os.system(f"shutdown /r /t 0 {force_flag}")
    elif action == "Ruhezustand (Hibernate)":
        os.system("shutdown /h")
    elif action == "Energie sparen (Sleep)":
        os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
    elif action == "Sperren (Lock)":
        ctypes.windll.user32.LockWorkStation()
    elif action == "Abmelden":
        os.system("shutdown /l")
    elif action == "UEFI / BIOS Reboot":
        os.system("shutdown /r /fw /t 0")

def power_timer_loop():
    while True:
        time.sleep(1)
        if POWER_STATE["running"]:
            if POWER_STATE["remaining_seconds"] > 0:
                POWER_STATE["remaining_seconds"] -= 1
            if POWER_STATE["remaining_seconds"] <= 0:
                POWER_STATE["running"] = False
                execute_power_action(
                    POWER_STATE["action"],
                    POWER_STATE["force"],
                    POWER_STATE["test_mode"]
                )

threading.Thread(target=power_timer_loop, daemon=True).start()

def set_power_plan(plan):
    plans = {
        "saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
        "balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
        "high": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    }
    if plan == "ultimate":
        res = run_cmd("powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61")
        out = res.stdout
        for token in out.split():
            if len(token) == 36 and token.count("-") == 4:
                run_cmd(f"powercfg /setactive {token}")
                return "Ultimative Leistung aktiviert"
        return "Ultimate Plan freigeschaltet"
    guid = plans.get(plan, plans["balanced"])
    run_cmd(f"powercfg /setactive {guid}")
    return f"Power-Plan ({plan.upper()}) aktiviert"

def generate_battery_report():
    report_path = os.path.join(tempfile.gettempdir(), "battery-report.html")
    run_cmd(f'powercfg /batteryreport /output "{report_path}"')
    if os.path.exists(report_path):
        os.system(f'start "" "{report_path}"')
        return "Battery Report generiert & geöffnet!"
    return "Fehler beim Erstellen des Battery Reports"

# =====================================================================
# MODULE 3: SMART FILE SORTER & AUTOMATION
# =====================================================================

FILE_CATEGORIES = {
    "Bilder": [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico", ".heic", ".raw"],
    "Dokumente": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".csv", ".rtf", ".odt"],
    "Archive": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso"],
    "Programme_Installer": [".exe", ".msi", ".bat", ".cmd", ".ps1", ".apx", ".msix"],
    "Code_Scripts": [".py", ".js", ".ts", ".html", ".css", ".json", ".xml", ".sql", ".cpp", ".c", ".cs", ".java", ".go", ".rs"],
    "Audio_Video": [".mp4", ".mkv", ".avi", ".mov", ".wmv", ".mp3", ".wav", ".flac", ".ogg", ".m4a"],
}

LAST_SORT_HISTORY = []

def resolve_preset_path(preset_or_path):
    user_dir = os.path.expanduser("~")
    presets = {
        "downloads": os.path.join(user_dir, "Downloads"),
        "desktop": os.path.join(user_dir, "Desktop"),
        "documents": os.path.join(user_dir, "Documents"),
    }
    return presets.get(preset_or_path.lower(), preset_or_path)

def get_category_for_ext(ext):
    ext = ext.lower()
    for cat, exts in FILE_CATEGORIES.items():
        if ext in exts:
            return cat
    return "Sonstiges"

PARTIAL_DOWNLOAD_EXTS = {".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp"}

def scan_or_sort_folder(target_path, dry_run=True, min_age=0):
    global LAST_SORT_HISTORY
    folder = resolve_preset_path(target_path)
    if not os.path.exists(folder) or not os.path.isdir(folder):
        return {"error": f"Ordner nicht gefunden: {folder}", "counts": {}, "total": 0}

    counts = {}
    moved_ops = []
    total = 0
    now = time.time()

    for entry in os.scandir(folder):
        if not entry.is_file():
            continue
        if entry.name.startswith(".") or entry.name.lower() == "desktop.ini":
            continue
        _, ext = os.path.splitext(entry.name)
        # Laufende Downloads nie anfassen, sonst bricht der Browser den Download ab
        if ext.lower() in PARTIAL_DOWNLOAD_EXTS:
            continue
        if min_age:
            try:
                if now - entry.stat().st_mtime < min_age:
                    continue
            except OSError:
                continue
        cat = get_category_for_ext(ext)
        counts[cat] = counts.get(cat, 0) + 1
        total += 1

        if not dry_run:
            dest_dir = os.path.join(folder, f"_{cat}")
            os.makedirs(dest_dir, exist_ok=True)
            dest_path = os.path.join(dest_dir, entry.name)
            base, extension = os.path.splitext(entry.name)
            counter = 1
            while os.path.exists(dest_path):
                dest_path = os.path.join(dest_dir, f"{base}_{counter}{extension}")
                counter += 1
            try:
                shutil.move(entry.path, dest_path)
                moved_ops.append((dest_path, entry.path))
            except Exception:
                pass

    if not dry_run and moved_ops:
        LAST_SORT_HISTORY = moved_ops

    return {"folder": folder, "counts": counts, "total": total, "moved": len(moved_ops)}

def undo_last_sort():
    global LAST_SORT_HISTORY
    restored = 0
    for src, orig in reversed(LAST_SORT_HISTORY):
        try:
            if os.path.exists(src):
                shutil.move(src, orig)
                restored += 1
        except Exception:
            pass
    LAST_SORT_HISTORY = []
    return restored

def clean_empty_folders(target_path):
    folder = resolve_preset_path(target_path)
    removed = 0
    if not os.path.isdir(folder):
        return 0
    for root, dirs, _ in os.walk(folder, topdown=False):
        for d in dirs:
            full_p = os.path.join(root, d)
            try:
                if not os.listdir(full_p):
                    os.rmdir(full_p)
                    removed += 1
            except Exception:
                pass
    return removed

def scan_large_files(target_path, min_mb=20):
    folder = resolve_preset_path(target_path)
    results = []
    min_bytes = min_mb * 1024 * 1024
    if not os.path.isdir(folder):
        return []
    try:
        for root, _, files in os.walk(folder):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    sz = os.path.getsize(fp)
                    if sz >= min_bytes:
                        results.append({
                            "name": f,
                            "path": fp,
                            "size_mb": round(sz / (1024 * 1024), 1)
                        })
                except Exception:
                    pass
    except Exception:
        pass
    results.sort(key=lambda x: x["size_mb"], reverse=True)
    return results[:15]

LAST_DUPLICATE_GROUPS = {}  # Pfad -> Liste aller Pfade derselben Duplikat-Gruppe

def _file_digest(path, limit=None):
    h = hashlib.blake2b(digest_size=20)
    remaining = limit
    with open(path, "rb") as f:
        while remaining is None or remaining > 0:
            chunk = f.read(1024 * 1024 if remaining is None else min(1024 * 1024, remaining))
            if not chunk:
                break
            h.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return h.hexdigest()

def _group_by(paths, key_fn):
    groups = {}
    for p in paths:
        try:
            groups.setdefault(key_fn(p), []).append(p)
        except OSError:
            pass
    return [g for g in groups.values() if len(g) > 1]

def _mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0

def find_duplicate_files(target_path, min_kb=10):
    global LAST_DUPLICATE_GROUPS
    folder = resolve_preset_path(target_path)
    if not os.path.isdir(folder):
        return {"error": f"Ordner nicht gefunden: {folder}", "groups": []}

    by_size = {}
    scanned = 0
    for root, _, files in os.walk(folder):
        for f in files:
            fp = os.path.join(root, f)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                continue
            if sz >= min_kb * 1024:
                by_size.setdefault(sz, []).append(fp)
                scanned += 1

    head_bytes = 64 * 1024
    groups = []
    for sz, paths in by_size.items():
        if len(paths) < 2:
            continue
        # Erst nur den Dateianfang hashen; den kompletten Inhalt nur bei echten Kandidaten lesen
        for candidates in _group_by(paths, lambda p: _file_digest(p, head_bytes)):
            same_groups = [candidates] if sz <= head_bytes else _group_by(candidates, _file_digest)
            for same in same_groups:
                same.sort(key=_mtime)  # älteste Datei zuerst = vermutlich das Original
                groups.append({"size": sz, "wasted": sz * (len(same) - 1), "files": same})

    groups.sort(key=lambda g: g["wasted"], reverse=True)
    LAST_DUPLICATE_GROUPS = {p: g["files"] for g in groups for p in g["files"]}
    return {
        "folder": folder,
        "scanned": scanned,
        "total_groups": len(groups),
        "wasted": sum(g["wasted"] for g in groups),
        "groups": groups[:25]
    }

class SHFILEOPSTRUCTW(ctypes.Structure):
    if ctypes.sizeof(ctypes.c_void_p) == 4:
        _pack_ = 1  # shellapi.h packt die Struktur nur unter 32 Bit
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", wintypes.WORD),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", wintypes.LPVOID),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]

def recycle_duplicate(path):
    # Nur Dateien aus dem letzten Scan, und nie die letzte verbleibende Kopie einer Gruppe
    group = LAST_DUPLICATE_GROUPS.get(path)
    if not group or not os.path.isfile(path):
        raise ValueError("Datei stammt nicht aus dem letzten Duplikat-Scan")
    if sum(1 for p in group if os.path.isfile(p)) < 2:
        raise ValueError("Letzte Kopie dieser Datei – wird nicht gelöscht")
    FO_DELETE, FOF_SILENT, FOF_NOCONFIRMATION, FOF_ALLOWUNDO, FOF_NOERRORUI = 3, 0x4, 0x10, 0x40, 0x400
    op = SHFILEOPSTRUCTW(
        wFunc=FO_DELETE,
        pFrom=path + "\0",  # Liste muss doppelt nullterminiert sein
        fFlags=FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
    )
    rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    return rc == 0 and not op.fAnyOperationsAborted

def reveal_in_explorer(path):
    if not path or not os.path.exists(path):
        return False
    subprocess.Popen(f'explorer /select,"{os.path.normpath(path)}"')
    return True

# =====================================================================
# MODULE 4: CLEANER & RAM OPTIMIZER
# =====================================================================

def wipe_directory_contents(path):
    freed_bytes = 0
    deleted_files = 0
    if not os.path.exists(path):
        return 0, 0
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            fp = os.path.join(root, name)
            try:
                sz = os.path.getsize(fp)
                os.remove(fp)
                freed_bytes += sz
                deleted_files += 1
            except Exception:
                pass
        for name in dirs:
            dp = os.path.join(root, name)
            try:
                os.rmdir(dp)
            except Exception:
                pass
    return freed_bytes, deleted_files

def run_system_cleaner(targets):
    total_bytes = 0
    total_files = 0
    paths = []
    if "user_temp" in targets:
        paths.append(tempfile.gettempdir())
    if "win_temp" in targets:
        paths.append(r"C:\Windows\Temp")
    if "prefetch" in targets:
        paths.append(r"C:\Windows\Prefetch")
    if "thumbcache" in targets:
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            paths.append(os.path.join(local_app, r"Microsoft\Windows\Explorer"))

    for p in paths:
        if p.endswith("Explorer"):
            if os.path.exists(p):
                for f in os.listdir(p):
                    if f.startswith("thumbcache_") and f.endswith(".db"):
                        fp = os.path.join(p, f)
                        try:
                            sz = os.path.getsize(fp)
                            os.remove(fp)
                            total_bytes += sz
                            total_files += 1
                        except Exception:
                            pass
        else:
            b, c = wipe_directory_contents(p)
            total_bytes += b
            total_files += c

    if "recycle_bin" in targets:
        try:
            ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 7)
        except Exception:
            pass

    return {
        "freed_mb": round(total_bytes / (1024 * 1024), 2),
        "deleted_files": total_files
    }

def optimize_ram_working_set():
    before = get_memory_info()
    try:
        run_cmd('powershell -NoProfile -Command "Get-Process | ForEach-Object { try { $_.MinWorkingSet = $_.MinWorkingSet } catch {} }"')
    except Exception:
        pass
    after = get_memory_info()
    return {"before": before["percent"], "after": after["percent"], "used_gb": after["used_gb"]}

def flush_standby_memory():
    try:
        run_cmd('powershell -NoProfile -Command "[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()"')
    except Exception:
        pass
    return optimize_ram_working_set()

# =====================================================================
# MODULE 5: ADVANCED TWEAKS & SERVICES
# =====================================================================

def get_tweak_states():
    states = {
        "classic_context": False,
        "disable_bing": False,
        "show_extensions": False,
        "dark_mode": True,
        "disable_telemetry": False,
        "disable_gamedvr": False,
        "nagle_algorithm": False,
        "net_throttling": False,
        "win_update_pause": False,
        "disable_sysmain": False,
        "disable_search_indexer": False,
        "ultimate_visuals": False
    }
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"):
            states["classic_context"] = True
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Explorer") as k:
            v, _ = winreg.QueryValueEx(k, "DisableSearchBoxSuggestions")
            states["disable_bing"] = (v == 1)
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") as k:
            v, _ = winreg.QueryValueEx(k, "HideFileExt")
            states["show_extensions"] = (v == 0)
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            v, _ = winreg.QueryValueEx(k, "AppsUseLightTheme")
            states["dark_mode"] = (v == 0)
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection") as k:
            v, _ = winreg.QueryValueEx(k, "AllowTelemetry")
            states["disable_telemetry"] = (v == 0)
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"System\GameConfigStore") as k:
            v, _ = winreg.QueryValueEx(k, "GameDVR_Enabled")
            states["disable_gamedvr"] = (v == 0)
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile") as k:
            v, _ = winreg.QueryValueEx(k, "NetworkThrottlingIndex")
            states["net_throttling"] = (v == 0xFFFFFFFF)
    except Exception:
        pass

    try:
        res = run_cmd('powershell -NoProfile -Command "(Get-Service SysMain).Status"')
        states["disable_sysmain"] = ("Running" not in res.stdout)
    except Exception:
        pass

    return states

def apply_tweak(tweak_id, enable):
    try:
        if tweak_id == "classic_context":
            if enable:
                run_cmd(r'reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve')
            else:
                run_cmd(r'reg.exe delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f')

        elif tweak_id == "disable_bing":
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Explorer")
            winreg.SetValueEx(key, "DisableSearchBoxSuggestions", 0, winreg.REG_DWORD, 1 if enable else 0)
            winreg.CloseKey(key)

        elif tweak_id == "show_extensions":
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")
            winreg.SetValueEx(key, "HideFileExt", 0, winreg.REG_DWORD, 0 if enable else 1)
            winreg.SetValueEx(key, "Hidden", 0, winreg.REG_DWORD, 1 if enable else 2)
            winreg.CloseKey(key)

        elif tweak_id == "dark_mode":
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            val = 0 if enable else 1
            winreg.SetValueEx(key, "AppsUseLightTheme", 0, winreg.REG_DWORD, val)
            winreg.SetValueEx(key, "SystemUsesLightTheme", 0, winreg.REG_DWORD, val)
            winreg.CloseKey(key)

        elif tweak_id == "disable_telemetry":
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection")
            winreg.SetValueEx(key, "AllowTelemetry", 0, winreg.REG_DWORD, 0 if enable else 1)
            winreg.CloseKey(key)

        elif tweak_id == "disable_gamedvr":
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"System\GameConfigStore")
            winreg.SetValueEx(key, "GameDVR_Enabled", 0, winreg.REG_DWORD, 0 if enable else 1)
            winreg.CloseKey(key)

        elif tweak_id == "net_throttling":
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")
            val = 0xFFFFFFFF if enable else 0x0000000A
            winreg.SetValueEx(key, "NetworkThrottlingIndex", 0, winreg.REG_DWORD, val)
            winreg.SetValueEx(key, "SystemResponsiveness", 0, winreg.REG_DWORD, 0 if enable else 14)
            winreg.CloseKey(key)

        elif tweak_id == "nagle_algorithm":
            val = 1 if enable else 0
            interfaces_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interfaces_path) as k:
                for i in range(100):
                    try:
                        sub = winreg.EnumKey(k, i)
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{interfaces_path}\\{sub}", 0, winreg.KEY_ALL_ACCESS) as ik:
                            winreg.SetValueEx(ik, "TcpAckFrequency", 0, winreg.REG_DWORD, val)
                            winreg.SetValueEx(ik, "TCPNoDelay", 0, winreg.REG_DWORD, val)
                    except OSError:
                        break

        elif tweak_id == "win_update_pause":
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")
            if enable:
                future = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
                winreg.SetValueEx(key, "PauseUpdatesExpiryTime", 0, winreg.REG_SZ, future)
            else:
                try:
                    winreg.DeleteValue(key, "PauseUpdatesExpiryTime")
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)

        elif tweak_id == "disable_sysmain":
            status = "Disabled" if enable else "Automatic"
            run_cmd(f'powershell -NoProfile -Command "Set-Service SysMain -StartupType {status}; { "Stop-Service SysMain -Force" if enable else "Start-Service SysMain" }"')

        elif tweak_id == "disable_search_indexer":
            status = "Disabled" if enable else "Automatic"
            run_cmd(f'powershell -NoProfile -Command "Set-Service WSearch -StartupType {status}; { "Stop-Service WSearch -Force" if enable else "Start-Service WSearch" }"')
    except Exception:
        pass
    return get_tweak_states()

def get_top_processes():
    procs = []
    try:
        cmd = 'powershell -NoProfile -Command "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 Name, Id, @{Name=\'MB\';Expression={[math]::Round($_.WorkingSet64 / 1MB, 1)}} | ConvertTo-Json"'
        res = run_cmd(cmd)
        if res.stdout.strip():
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]
            procs = data
    except Exception:
        pass
    return procs

def kill_process_by_id(pid):
    res = run_cmd(f"taskkill /PID {int(pid)} /F")
    return res.returncode == 0

PRIORITY_CLASSES = ("Idle", "BelowNormal", "Normal", "AboveNormal", "High", "Realtime")

def set_process_priority(pid, priority):
    # Nur bekannte Prioritätsklassen, der Wert landet sonst ungeprüft im PowerShell-Befehl
    if priority not in PRIORITY_CLASSES:
        return False
    res = run_cmd(f'powershell -NoProfile -Command "$p = Get-Process -Id {int(pid)}; $p.PriorityClass = \'{priority}\'"')
    return res.returncode == 0

STARTUP_SOURCES = {
    # Scope: (Root, Run-Key, StartupApproved-Key – derselbe Schalter wie im Task-Manager)
    "HKCU": (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Run",
             r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
    "HKLM": (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
    "HKLM32": (winreg.HKEY_LOCAL_MACHINE,
               r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
}

def is_startup_enabled(scope, name):
    root, _, approved_path = STARTUP_SOURCES[scope]
    try:
        with winreg.OpenKey(root, approved_path) as k:
            data, _ = winreg.QueryValueEx(k, name)
    except OSError:
        return True  # kein Eintrag = nie deaktiviert
    # Erstes Byte gerade (0x02/0x06) = aktiv, ungerade (0x03 …) = deaktiviert
    return not (data and data[0] & 1)

def get_startup_apps():
    items = []
    for scope, (root, run_path, _) in STARTUP_SOURCES.items():
        try:
            with winreg.OpenKey(root, run_path) as k:
                for i in range(100):
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    items.append({"name": name, "cmd": val, "scope": scope,
                                  "enabled": is_startup_enabled(scope, name)})
        except Exception:
            pass
    return items

def set_startup_enabled(scope, name, enable):
    if scope not in STARTUP_SOURCES:
        raise ValueError(f"Unbekannter Autostart-Bereich: {scope}")
    root, run_path, approved_path = STARTUP_SOURCES[scope]
    with winreg.OpenKey(root, run_path) as k:
        winreg.QueryValueEx(k, name)  # wirft, wenn es den Autostart-Eintrag nicht gibt
    if enable:
        data = b"\x02" + b"\x00" * 11
    else:
        # Wie der Task-Manager: 0x03 + Zeitpunkt der Deaktivierung als FILETIME
        filetime = int((time.time() + 11644473600) * 10_000_000)
        data = b"\x03\x00\x00\x00" + filetime.to_bytes(8, "little")
    with winreg.CreateKeyEx(root, approved_path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, data)
    return is_startup_enabled(scope, name)

# =====================================================================
# MODULE 6: NETWORK & PORT SECURITY SCANNER
# =====================================================================

def get_active_connections():
    conns = []
    try:
        cmd = 'powershell -NoProfile -Command "Get-NetTCPConnection | Where-Object State -eq \'Listen\' | Select-Object -First 15 LocalAddress, LocalPort, OwningProcess | ConvertTo-Json"'
        res = run_cmd(cmd)
        if res.stdout.strip():
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                data = [data]
            conns = data
    except Exception:
        pass
    return conns

def scan_target_ports(target_host="127.0.0.1", ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]
    open_ports = []

    def check_port(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            res = s.connect_ex((target_host, p))
            if res == 0:
                open_ports.append(p)
        except Exception:
            pass
        finally:
            s.close()

    threads = []
    for port in ports:
        t = threading.Thread(target=check_port, args=(port,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return sorted(open_ports)

def benchmark_dns_latencies():
    servers = {
        "Cloudflare (1.1.1.1)": "1.1.1.1",
        "Google (8.8.8.8)": "8.8.8.8",
        "Quad9 (9.9.9.9)": "9.9.9.9",
        "AdGuard (94.140.14.14)": "94.140.14.14",
        "OpenDNS (208.67.222.222)": "208.67.222.222"
    }
    results = []
    for name, ip in servers.items():
        try:
            start = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect((ip, 53))
            s.close()
            ms = round((time.time() - start) * 1000, 1)
            results.append({"name": name, "ip": ip, "ms": ms})
        except Exception:
            results.append({"name": name, "ip": ip, "ms": 999.0})
    results.sort(key=lambda x: x["ms"])
    return results

def apply_hosts_blocklist():
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    block_entries = [
        "0.0.0.0 telemetry.microsoft.com",
        "0.0.0.0 vortex.data.microsoft.com",
        "0.0.0.0 tracking.epicgames.com",
        "0.0.0.0 adservice.google.com"
    ]
    added = 0
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        with open(hosts_path, "a", encoding="utf-8") as f:
            for entry in block_entries:
                if entry.split()[1] not in content:
                    f.write(f"\n{entry}")
                    added += 1
    except Exception:
        pass
    return added

# =====================================================================
# MODULE 7: ALLTAG & AUTOMATION
# =====================================================================

DATA_FILE = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "NexusOS", "user_data.json")
USER_DATA = {
    "workspaces": [],
    "reminders": [],
    "notes": "",
    "snippets": [],
    "autosort": {"enabled": False, "path": "downloads"},
    "commands": [],
    "settings": {},
    "automations": [],
}
DATA_LOCK = threading.RLock()

def load_user_data():
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    with DATA_LOCK:
        for key, default in USER_DATA.items():
            if isinstance(data.get(key), type(default)):
                USER_DATA[key] = data[key]

def save_user_data():
    with DATA_LOCK:
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(USER_DATA, f, indent=2, ensure_ascii=False)
        os.replace(tmp, DATA_FILE)  # atomar: ein Absturz mitten im Schreiben zerstört nicht die alte Datei

def clean_text(value, max_len, field):
    text = str(value or "").strip()
    if not text or len(text) > max_len:
        raise ValueError(f"{field}: 1–{max_len} Zeichen")
    return text

def delete_entry(key, entry_id):
    with DATA_LOCK:
        USER_DATA[key] = [x for x in USER_DATA[key] if x.get("id") != entry_id]
        save_user_data()
        return USER_DATA[key]

# ---------------- Workspaces: mehrere Apps/Ordner/Seiten mit einem Klick ----------------

def save_workspace(payload):
    name = clean_text(payload.get("name"), 40, "Name")
    items = [str(i).strip().strip('"') for i in (payload.get("items") or []) if str(i).strip()]
    if not items or len(items) > 20 or any(len(i) > 500 for i in items):
        raise ValueError("Workspace braucht 1–20 Einträge mit je max. 500 Zeichen")
    with DATA_LOCK:
        existing = next((w for w in USER_DATA["workspaces"] if w["id"] == payload.get("id")), None)
        if existing:
            existing.update(name=name, items=items)
        else:
            USER_DATA["workspaces"].append({"id": uuid.uuid4().hex[:12], "name": name, "items": items})
        save_user_data()
        return USER_DATA["workspaces"]

def launch_workspace(ws_id):
    ws = next((w for w in USER_DATA["workspaces"] if w["id"] == ws_id), None)
    if not ws:
        raise ValueError("Workspace nicht gefunden")
    started, failed = [], []
    for item in ws["items"]:
        target = os.path.expandvars(item)
        # URIs wie https://, steam://, ms-settings: (min. 2 Zeichen, damit "C:" nicht als Schema gilt)
        if re.match(r"^[a-z][a-z0-9+.-]+:", target, re.I) or os.path.exists(target):
            # Über explorer.exe starten: das Programm läuft dann mit normalen Rechten statt mit unseren Admin-Rechten
            subprocess.Popen(["explorer.exe", target])
            started.append(item)
            time.sleep(0.2)
        else:
            failed.append(item)
    return {"started": started, "failed": failed}

# ---------------- Erinnerungen mit Windows-Popup ----------------

def add_reminder(payload):
    text = clean_text(payload.get("text"), 200, "Text")
    if payload.get("mode") == "at":
        m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(payload.get("time", "")).strip())
        if not m:
            raise ValueError("Uhrzeit bitte als HH:MM")
        now = datetime.now()
        due = now.replace(hour=int(m.group(1)), minute=int(m.group(2)), second=0, microsecond=0)
        if due <= now:
            due += timedelta(days=1)
    else:
        minutes = int(payload.get("minutes") or 0)
        if not 1 <= minutes <= 10080:
            raise ValueError("Erinnerung: 1 Minute bis 7 Tage")
        due = datetime.now() + timedelta(minutes=minutes)
    with DATA_LOCK:
        USER_DATA["reminders"].append({
            "id": uuid.uuid4().hex[:12],
            "text": text,
            "due": due.timestamp(),
            "repeat": "daily" if payload.get("repeat") == "daily" else "none"
        })
        USER_DATA["reminders"].sort(key=lambda r: r["due"])
        save_user_data()
        return USER_DATA["reminders"]

def show_popup(text, title="NEXUS Erinnerung"):
    MB_ICONINFORMATION, MB_SYSTEMMODAL, MB_SETFOREGROUND, MB_TOPMOST = 0x40, 0x1000, 0x10000, 0x40000
    ctypes.windll.user32.MessageBeep(MB_ICONINFORMATION)
    # MessageBoxW blockiert bis zum Klick, daher im eigenen Thread
    threading.Thread(
        target=ctypes.windll.user32.MessageBoxW,
        args=(None, text, title, MB_ICONINFORMATION | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST),
        daemon=True
    ).start()

def reminder_loop():
    while True:
        time.sleep(2)
        try:
            now = time.time()
            with DATA_LOCK:
                due = [r for r in USER_DATA["reminders"] if r["due"] <= now]
                if not due:
                    continue
                for r in due:
                    # Lief die App zum Fälligkeitszeitpunkt nicht, trotzdem melden – mit Hinweis
                    late = now - r["due"] > 120
                    when = datetime.fromtimestamp(r["due"]).strftime("%d.%m. %H:%M")
                    show_popup(r["text"] + (f"\n\n(verpasst, war fällig am {when})" if late else ""))
                    if r.get("repeat") == "daily":
                        nxt = datetime.fromtimestamp(r["due"])
                        while nxt.timestamp() <= now:
                            nxt += timedelta(days=1)
                        r["due"] = nxt.timestamp()
                USER_DATA["reminders"] = sorted(
                    (r for r in USER_DATA["reminders"] if r["due"] > now), key=lambda r: r["due"])
                save_user_data()
        except Exception:
            pass

threading.Thread(target=reminder_loop, daemon=True).start()

# ---------------- Notizen & Text-Bausteine ----------------

def save_notes(text):
    text = str(text or "")
    if len(text) > 100_000:
        raise ValueError("Notizen: maximal 100.000 Zeichen")
    with DATA_LOCK:
        USER_DATA["notes"] = text
        save_user_data()

def save_snippet(payload):
    label = clean_text(payload.get("label"), 40, "Bezeichnung")
    text = clean_text(payload.get("text"), 5000, "Text")
    with DATA_LOCK:
        USER_DATA["snippets"].append({"id": uuid.uuid4().hex[:12], "label": label, "text": text})
        save_user_data()
        return USER_DATA["snippets"]

# ---------------- Auto-Sortierung im Hintergrund ----------------

AUTOSORT_STATE = {"last_run": None, "last_moved": 0, "total_moved": 0}

def autosort_status():
    cfg = USER_DATA["autosort"]
    return dict(cfg, folder=resolve_preset_path(cfg.get("path", "downloads")), **AUTOSORT_STATE)

def set_autosort(enabled, path):
    path = (path or "downloads").strip()
    if enabled and not os.path.isdir(resolve_preset_path(path)):
        raise ValueError(f"Ordner nicht gefunden: {resolve_preset_path(path)}")
    with DATA_LOCK:
        USER_DATA["autosort"] = {"enabled": bool(enabled), "path": path}
        save_user_data()
    return autosort_status()

def autosort_loop():
    while True:
        time.sleep(60)
        cfg = USER_DATA["autosort"]
        if not cfg.get("enabled"):
            continue
        try:
            # Nur Dateien, die seit 2 Minuten unverändert sind
            res = scan_or_sort_folder(cfg.get("path", "downloads"), dry_run=False, min_age=120)
            moved = res.get("moved", 0)
            AUTOSORT_STATE["last_run"] = datetime.now().strftime("%H:%M")
            AUTOSORT_STATE["last_moved"] = moved
            AUTOSORT_STATE["total_moved"] += moved
        except Exception:
            pass

threading.Thread(target=autosort_loop, daemon=True).start()

# ---------------- App-Updates über winget ----------------

UPDATE_JOB = {"running": False, "target": None, "ok": None, "output": "", "finished_at": None}
UPDATE_LOCK = threading.Lock()

def run_winget(args, timeout):
    return subprocess.run(
        ["winget", *args, "--accept-source-agreements", "--disable-interactivity"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=timeout
    )

def clean_winget_output(output):
    # Fortschrittsbalken und Spinner (mit \r überschrieben) entfernen, nur den letzten Stand jeder Zeile behalten
    lines = [line.split("\r")[-1].rstrip() for line in output.splitlines()]
    return [l for l in lines if l.strip() and not re.search(r"[█▒]|^\s*[-\\|/]\s*$", l)]

def parse_winget_table(output):
    lines = clean_winget_output(output)
    sep = next((i for i, l in enumerate(lines) if i and re.fullmatch(r"-{20,}", l.strip())), None)
    if sep is None:
        return []
    # Spaltengrenzen aus der Kopfzeile ableiten (Name, Id, Version, Verfügbar, Quelle – auch lokalisiert)
    starts = [m.start() for m in re.finditer(r"\S+", lines[sep - 1])]
    if len(starts) < 4:
        return []
    packages = []
    for line in lines[sep + 1:]:
        cells = [line[a:b].strip() for a, b in zip(starts, starts[1:] + [None])]
        name, pkg_id, current, available = cells[:4]
        if not pkg_id or " " in pkg_id or not available:
            break  # Ende der Tabelle, z. B. "23 upgrades available."
        packages.append({"name": name, "id": pkg_id, "current": current, "available": available})
    return packages

def list_app_updates():
    try:
        res = run_winget(["upgrade"], timeout=180)
    except FileNotFoundError:
        raise ValueError("winget ist nicht installiert (App Installer aus dem Microsoft Store)")
    return parse_winget_table(res.stdout)

def start_app_update(pkg_id=None):
    if pkg_id is not None and not re.fullmatch(r"[^\s\"']{1,200}", pkg_id):
        raise ValueError("Ungültige Paket-ID")
    with UPDATE_LOCK:
        if UPDATE_JOB["running"]:
            raise ValueError("Es läuft bereits ein Update")
        UPDATE_JOB.update(running=True, target=pkg_id or "alle Apps", ok=None, output="", finished_at=None)
    args = ["upgrade", "--silent", "--accept-package-agreements"]
    args += ["--id", pkg_id, "--exact"] if pkg_id else ["--all"]

    def worker():
        try:
            res = run_winget(args, timeout=3600)
            ok, out = res.returncode == 0, res.stdout + "\n" + res.stderr
        except Exception as e:
            ok, out = False, str(e)
        UPDATE_JOB.update(
            running=False, ok=ok,
            output="\n".join(clean_winget_output(out)[-12:]),
            finished_at=datetime.now().strftime("%H:%M")
        )

    threading.Thread(target=worker, daemon=True).start()
    return dict(UPDATE_JOB)

# =====================================================================
# MODULE 8: CUSTOM COMMANDS, EINSTELLUNGEN & SYSTEM-INFOS
# =====================================================================

COMMAND_RUNS = {}  # Befehls-ID -> letzter Lauf (Status + Ausgabe)

def save_command(payload):
    name = clean_text(payload.get("name"), 40, "Name")
    command = clean_text(payload.get("command"), 2000, "Befehl")
    shell = payload.get("shell") if payload.get("shell") in ("cmd", "powershell") else "cmd"
    with DATA_LOCK:
        existing = next((c for c in USER_DATA["commands"] if c["id"] == payload.get("id")), None)
        if existing:
            existing.update(name=name, command=command, shell=shell)
        else:
            USER_DATA["commands"].append({"id": uuid.uuid4().hex[:12], "name": name, "command": command, "shell": shell})
        save_user_data()
        return USER_DATA["commands"]

def command_line(cmd, keep_open=False):
    if cmd["shell"] == "powershell":
        script = cmd["command"]
        if not keep_open:
            # Ohne Fenster: Fortschrittsbalken aus und Fehler als Text in stdout, sonst landet
            # PowerShells CLIXML-Serialisierung ("#< CLIXML ...") in der Ausgabe
            script = f"$ProgressPreference = 'SilentlyContinue'\n& {{\n{script}\n}} 2>&1 | Out-String -Width 200"
        # Base64 (UTF-16LE), damit Anführungszeichen im Befehl nicht von cmd.exe zerlegt werden
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return f'powershell -NoProfile {"-NoExit " if keep_open else ""}-EncodedCommand {encoded}'
    # Mehrere Zeilen = mehrere Befehle nacheinander
    joined = " & ".join(line.strip() for line in cmd["command"].splitlines() if line.strip())
    # /s: cmd entfernt nur die äußeren Anführungszeichen und übernimmt den Rest unverändert
    return f'cmd /d /s {"/k" if keep_open else "/c"} "{joined}"'

def run_custom_command(cmd_id, visible=False):
    cmd = next((c for c in USER_DATA["commands"] if c["id"] == cmd_id), None)
    if not cmd:
        raise ValueError("Befehl nicht gefunden")
    if visible:
        subprocess.Popen(command_line(cmd, keep_open=True), creationflags=subprocess.CREATE_NEW_CONSOLE)
        return {"visible": True}
    if COMMAND_RUNS.get(cmd_id, {}).get("running"):
        raise ValueError("Der Befehl läuft bereits")
    run = {"running": True, "output": "", "code": None, "started": datetime.now().strftime("%H:%M:%S"), "duration": None}
    COMMAND_RUNS[cmd_id] = run

    def worker():
        t0 = time.time()
        try:
            res = subprocess.run(
                command_line(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="oem", errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=300
            )
            run.update(output=res.stdout[-20000:], code=res.returncode)
        except subprocess.TimeoutExpired as e:
            partial = e.output if isinstance(e.output, str) else ""
            run.update(output=partial[-20000:] + "\n[Nach 5 Minuten abgebrochen]", code=-1)
        except Exception as e:
            run.update(output=str(e), code=-1)
        run.update(running=False, duration=round(time.time() - t0, 1))

    threading.Thread(target=worker, daemon=True).start()
    return run

DEFAULT_SETTINGS = {
    "accent": "#ffffff",
    "sound": True,
    "start_view": "view-dash",
    "monitor_interval": 1,
    "refresh_interval": 5,
    "ping_host": "google.com",
    # Design
    "theme": "midnight",
    "font": "inter",
    "font_size": 16,
    "radius": "normal",
    "density": "normal",
    "pattern": "none",
    "glow": True,
    "animations": True,
    "show_console": True,
    "nav_numbers": True,
    "brand_name": "MONOLITH // NEXUS OS",
    "brand_tag": "v10.0 QUANTUM KERNEL",
    "hidden_views": [],
    "dash_hidden": [],
    "accent2": "#a855f7",
    "accent_gradient": False,
    "card_style": "solid",
    "contrast": "normal",
    "button_shape": "normal",
    "sidebar_side": "left",
    "sidebar_width": "normal",
    "label_case": "upper",
    "mono_values": True,
    "scrollbar": "normal",
    "transition": "pop",
    "motion_speed": "normal",
    "hover_lift": False,
    # Start & Hinweise
    "welcome": True,
    "welcome_style": "stats",
    "welcome_duration": 2500,
    "welcome_name": "",
    "toasts": "all",
    "toast_pos": "bottom-right",
    "toast_duration": 5,
    "clock_format": "24",
    "clock_seconds": True,
}

SETTING_CHOICES = {
    "monitor_interval": (1, 2, 5),
    "refresh_interval": (3, 5, 10, 30),
    "theme": ("midnight", "graphite", "oled", "nord", "light"),
    "font": ("inter", "segoe", "mono", "poppins", "nunito"),
    "font_size": (14, 15, 16, 17, 18),
    "radius": ("sharp", "normal", "round"),
    "density": ("compact", "normal", "cozy"),
    "pattern": ("none", "grid", "dots", "aurora", "noise"),
    "card_style": ("solid", "glass", "outline", "elevated"),
    "contrast": ("normal", "high"),
    "button_shape": ("normal", "pill"),
    "sidebar_side": ("left", "right"),
    "sidebar_width": ("compact", "normal", "wide"),
    "label_case": ("upper", "normal"),
    "scrollbar": ("normal", "thin", "hidden"),
    "transition": ("pop", "slide", "zoom", "blur", "none"),
    "motion_speed": ("fast", "normal", "slow"),
    "welcome_style": ("minimal", "stats"),
    "welcome_duration": (0, 1500, 2500, 4000),
    "toasts": ("all", "errors", "off"),
    "toast_pos": ("top-right", "bottom-right", "bottom-center"),
    "toast_duration": (3, 5, 8),
    "clock_format": ("24", "12"),
}
SETTING_BOOLS = ("sound", "glow", "animations", "show_console", "nav_numbers", "accent_gradient",
                 "mono_values", "hover_lift", "welcome", "clock_seconds")
SETTING_TEXTS = {"brand_name": 32, "brand_tag": 24, "welcome_name": 32}
DASH_SECTIONS = ("hero", "metrics", "monitor", "bottom")

def get_settings():
    return dict(DEFAULT_SETTINGS, **USER_DATA["settings"])

def save_settings(payload):
    s = get_settings()
    for key, value in payload.items():
        if key in ("accent", "accent2"):
            if not re.fullmatch(r"#[0-9a-fA-F]{6}", str(value)):
                raise ValueError("Ungültige Farbe")
            s[key] = value.lower()
        elif key == "start_view":
            if not re.fullmatch(r"view-[a-z]+", str(value)):
                raise ValueError("Ungültige Startansicht")
            s[key] = value
        elif key in SETTING_CHOICES:
            if value not in SETTING_CHOICES[key]:
                raise ValueError(f"Ungültiger Wert für {key}: {value}")
            s[key] = value
        elif key in SETTING_BOOLS:
            s[key] = bool(value)
        elif key in SETTING_TEXTS:
            text = str(value or "").strip()
            if len(text) > SETTING_TEXTS[key]:
                raise ValueError(f"Maximal {SETTING_TEXTS[key]} Zeichen")
            s[key] = text or DEFAULT_SETTINGS[key]
        elif key == "hidden_views":
            views = [v for v in value or [] if isinstance(v, str) and re.fullmatch(r"view-[a-z]+", v)]
            # Dashboard und Einstellungen bleiben immer erreichbar, sonst sperrt man sich aus
            s[key] = sorted(set(views) - {"view-dash", "view-settings"})[:20]
        elif key == "dash_hidden":
            s[key] = sorted(set(v for v in value or [] if v in DASH_SECTIONS))
        # Unbekannte Schlüssel (z.B. aus einem Design-Code einer neueren Version) still ignorieren
    with DATA_LOCK:
        USER_DATA["settings"] = s
        save_user_data()
    return s

def get_display_name():
    # Anzeigename des Windows-Kontos (z.B. "Lukas Muster"); bei lokalen Konten oft leer → Benutzername
    try:
        size = wintypes.ULONG(256)
        buf = ctypes.create_unicode_buffer(256)
        if ctypes.windll.secur32.GetUserNameExW(3, buf, ctypes.byref(size)) and buf.value.strip():  # 3 = NameDisplay
            return buf.value.strip()
    except Exception:
        pass
    return os.environ.get("USERNAME", "")

def get_welcome_info():
    mem, disk = get_memory_info(), get_disk_info()
    with DATA_LOCK:
        upcoming = USER_DATA["reminders"][0] if USER_DATA["reminders"] else None
        active_autos = sum(1 for a in USER_DATA["automations"] if a.get("enabled"))
    return {
        "name": get_display_name(),
        "pc": os.environ.get("COMPUTERNAME") or get_current_hostname(),
        "uptime": get_uptime_str(),
        "ram": mem["percent"],
        "disk_free": disk["free_gb"],
        "reminder": {"text": upcoming["text"], "due": upcoming["due"]} if upcoming else None,
        "automations": active_autos,
    }

def import_user_data(data):
    if not isinstance(data, dict):
        raise ValueError("Keine gültige NexusOS-Sicherung")
    with DATA_LOCK:
        imported = [k for k, default in USER_DATA.items() if isinstance(data.get(k), type(default))]
        if not imported:
            raise ValueError("Keine gültige NexusOS-Sicherung")
        for k in imported:
            USER_DATA[k] = data[k]
        save_user_data()
    return imported

AUTOSTART_TASK = "NexusOS Autostart"

def autostart_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    # pythonw statt python: beim Login öffnet sich kein leeres Konsolenfenster
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    exe = pythonw if os.path.exists(pythonw) else sys.executable
    return f'"{exe}" "{os.path.abspath(sys.argv[0])}"'

def is_autostart_enabled():
    res = subprocess.run(["schtasks", "/Query", "/TN", AUTOSTART_TASK],
                         capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return res.returncode == 0

def set_autostart(enable):
    if enable:
        # Aufgabenplanung mit höchsten Rechten: startet beim Login ohne UAC-Abfrage
        args = ["schtasks", "/Create", "/TN", AUTOSTART_TASK, "/TR", autostart_command(),
                "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"]
    else:
        args = ["schtasks", "/Delete", "/TN", AUTOSTART_TASK, "/F"]
    res = subprocess.run(args, capture_output=True, text=True, encoding="oem", errors="replace",
                         creationflags=subprocess.CREATE_NO_WINDOW)
    if res.returncode != 0:
        raise ValueError((res.stderr or res.stdout).strip() or "Aufgabenplanung fehlgeschlagen")
    return is_autostart_enabled()

def open_known_place(key):
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    desktop = os.path.join(home, "Desktop")
    places = {
        "downloads": os.path.join(home, "Downloads"),
        "documents": os.path.join(home, "Documents"),
        "desktop": desktop if os.path.isdir(desktop) else os.path.join(home, "OneDrive", "Desktop"),
        "pictures": os.path.join(home, "Pictures"),
        "appdata": appdata,
        "localappdata": os.environ.get("LOCALAPPDATA", ""),
        "temp": tempfile.gettempdir(),
        "startup": os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"),
    }
    if key == "hosts":
        # Notepad erbt unsere Admin-Rechte, damit Änderungen an der hosts-Datei gespeichert werden können
        subprocess.Popen(["notepad.exe", r"C:\Windows\System32\drivers\etc\hosts"])
        return True
    path = places.get(key)
    if not path or not os.path.isdir(path):
        raise ValueError(f"Ordner nicht gefunden: {key}")
    subprocess.Popen(["explorer.exe", path])
    return True

SYSINFO_CACHE = {}

def get_system_info():
    if SYSINFO_CACHE:
        return SYSINFO_CACHE
    script = (
        "$os = Get-CimInstance Win32_OperatingSystem;"
        "$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1;"
        "$cs = Get-CimInstance Win32_ComputerSystem;"
        "[pscustomobject]@{"
        " os = $os.Caption; version = $os.Version;"
        " cpu = $cpu.Name.Trim(); cores = $cpu.NumberOfCores; threads = $cpu.NumberOfLogicalProcessors;"
        " gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object Name);"
        " ram_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1);"
        " model = \"$($cs.Manufacturer) $($cs.Model)\""
        "} | ConvertTo-Json"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    res = subprocess.run(["powershell", "-NoProfile", "-EncodedCommand", encoded],
                         capture_output=True, text=True, encoding="oem", errors="replace",
                         creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
    info = json.loads(res.stdout)
    disks = []
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if os.path.exists(root):
            try:
                total, used, free = shutil.disk_usage(root)
                disks.append(f"{letter}: {round(total / 1024 ** 3)} GB ({round(free / 1024 ** 3)} GB frei)")
            except OSError:
                pass
    rows = [
        ["Betriebssystem", f"{info.get('os')} (Build {str(info.get('version', '')).split('.')[-1]})"],
        ["Prozessor", f"{info.get('cpu')} · {info.get('cores')} Kerne / {info.get('threads')} Threads"],
        ["Grafik", ", ".join(info.get("gpus") or []) or "—"],
        ["Arbeitsspeicher", f"{info.get('ram_gb')} GB"],
        ["Gerät", info.get("model") or "—"],
        ["Laufwerke", " · ".join(disks) or "—"],
        ["Python", sys.version.split()[0]],
    ]
    SYSINFO_CACHE["rows"] = rows
    return SYSINFO_CACHE

def get_folder_sizes(target_path, time_limit=20):
    folder = resolve_preset_path(target_path)
    if not os.path.isdir(folder):
        return {"error": f"Ordner nicht gefunden: {folder}", "entries": []}
    deadline = time.time() + time_limit
    entries, loose, partial = [], 0, False
    try:
        children = list(os.scandir(folder))
    except OSError as e:
        return {"error": str(e), "entries": []}
    for child in children:
        try:
            if child.is_file(follow_symlinks=False):
                loose += child.stat(follow_symlinks=False).st_size
                continue
            if not child.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        size = files = 0
        for root, _, names in os.walk(child.path):
            for n in names:
                try:
                    size += os.lstat(os.path.join(root, n)).st_size
                    files += 1
                except OSError:
                    pass
            if time.time() > deadline:
                partial = True
                break
        entries.append({"name": child.name, "path": child.path, "size": size, "files": files})
        if partial:
            break
    if loose:
        entries.append({"name": "(Dateien direkt in diesem Ordner)", "path": folder, "size": loose, "files": None})
    entries.sort(key=lambda e: e["size"], reverse=True)
    return {
        "folder": folder,
        "total": sum(e["size"] for e in entries),
        "entries": entries[:20],
        "partial": partial
    }

# =====================================================================
# MODULE 9: AUTOMATIONEN, NETZ-DIAGNOSE, FESTPLATTEN & UMBENENNEN
# =====================================================================

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]

def get_process_names():
    # Toolhelp-Snapshot statt tasklist/PowerShell: kostet Millisekunden, kann also alle paar Sekunden laufen
    k32 = ctypes.windll.kernel32
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_void_p(-1).value:
        return set()
    names = set()
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(wintypes.HANDLE(snap), ctypes.byref(entry))
        while ok:
            names.add(entry.szExeFile.lower())
            ok = k32.Process32NextW(wintypes.HANDLE(snap), ctypes.byref(entry))
    finally:
        k32.CloseHandle(wintypes.HANDLE(snap))
    return names

# ---------------- Automationen: "Wenn X, dann Y" ----------------

TRIGGER_TYPES = ("daily", "interval", "startup", "process_start", "process_stop")
ACTION_TYPES = ("command", "workspace", "popup", "clean_temp", "sort_downloads", "caffeine_on", "caffeine_off", "power_plan")
AUTOMATION_LOG = deque(maxlen=40)

def save_automation(payload):
    name = clean_text(payload.get("name"), 40, "Name")
    trig, act = payload.get("trigger") or {}, payload.get("action") or {}
    if trig.get("type") not in TRIGGER_TYPES:
        raise ValueError("Unbekannter Auslöser")
    if act.get("type") not in ACTION_TYPES:
        raise ValueError("Unbekannte Aktion")

    trigger = {"type": trig["type"]}
    if trig["type"] == "daily":
        m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(trig.get("time", "")).strip())
        if not m:
            raise ValueError("Uhrzeit bitte als HH:MM")
        days = sorted({int(d) for d in trig.get("days") or [] if str(d).isdigit() and 0 <= int(d) <= 6})
        if not days:
            raise ValueError("Mindestens einen Wochentag auswählen")
        trigger.update(time=f"{int(m.group(1)):02d}:{m.group(2)}", days=days)
    elif trig["type"] == "interval":
        minutes = int(trig.get("minutes") or 0)
        if not 5 <= minutes <= 1440:
            raise ValueError("Intervall: 5 bis 1440 Minuten")
        trigger["minutes"] = minutes
    elif trig["type"] in ("process_start", "process_stop"):
        proc = str(trig.get("process") or "").strip().lower()
        if not proc.endswith(".exe"):
            proc += ".exe"
        if not re.fullmatch(r"[\w .()+-]{1,80}\.exe", proc):
            raise ValueError("Prozessname bitte wie z.B. valorant.exe")
        trigger["process"] = proc

    action = {"type": act["type"]}
    target = act.get("target")
    if act["type"] == "command":
        if not any(c["id"] == target for c in USER_DATA["commands"]):
            raise ValueError("Bitte einen gespeicherten Befehl auswählen")
        action["target"] = target
    elif act["type"] == "workspace":
        if not any(w["id"] == target for w in USER_DATA["workspaces"]):
            raise ValueError("Bitte einen Workspace auswählen")
        action["target"] = target
    elif act["type"] == "popup":
        action["target"] = clean_text(target, 200, "Popup-Text")
    elif act["type"] == "power_plan":
        if target not in ("saver", "balanced", "high", "ultimate"):
            raise ValueError("Unbekannter Energieplan")
        action["target"] = target

    with DATA_LOCK:
        existing = next((a for a in USER_DATA["automations"] if a["id"] == payload.get("id")), None)
        if existing:
            existing.update(name=name, trigger=trigger, action=action)
        else:
            # last_run = jetzt, damit Intervalle nicht sofort beim Anlegen feuern
            USER_DATA["automations"].append({"id": uuid.uuid4().hex[:12], "name": name, "enabled": True,
                                             "trigger": trigger, "action": action, "last_run": time.time()})
        save_user_data()
        return USER_DATA["automations"]

def set_automation_enabled(auto_id, enabled):
    with DATA_LOCK:
        auto = next((a for a in USER_DATA["automations"] if a["id"] == auto_id), None)
        if not auto:
            raise ValueError("Automation nicht gefunden")
        auto["enabled"] = bool(enabled)
        save_user_data()
        return USER_DATA["automations"]

def execute_automation(auto, reason):
    act = auto["action"]
    kind = act["type"]
    try:
        if kind == "command":
            run_custom_command(act["target"])
            result = "Befehl gestartet"
        elif kind == "workspace":
            res = launch_workspace(act["target"])
            result = f"{len(res['started'])} Einträge geöffnet"
        elif kind == "popup":
            show_popup(act["target"], title=f"NEXUS · {auto['name']}")
            result = "Popup angezeigt"
        elif kind == "clean_temp":
            res = run_system_cleaner(["user_temp"])
            result = f"{res['freed_mb']} MB Temp bereinigt"
        elif kind == "sort_downloads":
            res = scan_or_sort_folder("downloads", dry_run=False, min_age=120)
            result = f"{res.get('moved', 0)} Dateien sortiert"
        elif kind == "caffeine_on":
            toggle_caffeine_mode(True)
            result = "Caffeine an"
        elif kind == "caffeine_off":
            toggle_caffeine_mode(False)
            result = "Caffeine aus"
        else:
            result = set_power_plan(act["target"])
        ok = True
    except Exception as e:
        ok, result = False, str(e)
    with DATA_LOCK:
        auto["last_run"] = time.time()
        save_user_data()
    AUTOMATION_LOG.appendleft({"time": datetime.now().strftime("%d.%m. %H:%M:%S"), "name": auto["name"],
                               "reason": reason, "ok": ok, "result": result})
    return ok, result

def automation_loop():
    prev_procs = None
    startup_done = False
    while True:
        try:
            now = datetime.now()
            procs = get_process_names()
            with DATA_LOCK:
                autos = [a for a in USER_DATA["automations"] if a.get("enabled")]
            due = []
            for a in autos:
                t = a["trigger"]
                if t["type"] == "startup" and not startup_done:
                    due.append((a, "NEXUS gestartet"))
                elif t["type"] == "interval" and time.time() - a.get("last_run", 0) >= t["minutes"] * 60:
                    due.append((a, f"alle {t['minutes']} min"))
                elif t["type"] == "daily":
                    hh, mm = map(int, t["time"].split(":"))
                    sched = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                    # 10-Minuten-Fenster: startet NEXUS erst Stunden später, wird nichts nachgeholt
                    if (now.weekday() in t["days"] and sched <= now < sched + timedelta(minutes=10)
                            and a.get("last_run", 0) < sched.timestamp()):
                        due.append((a, f"{t['time']} Uhr"))
                elif prev_procs is not None and t["type"] == "process_start":
                    if t["process"] in procs and t["process"] not in prev_procs:
                        due.append((a, f"{t['process']} gestartet"))
                elif prev_procs is not None and t["type"] == "process_stop":
                    if t["process"] in prev_procs and t["process"] not in procs:
                        due.append((a, f"{t['process']} beendet"))
            startup_done = True
            prev_procs = procs
            for a, reason in due:
                execute_automation(a, reason)
        except Exception:
            pass
        time.sleep(5)

# ---------------- Ping-Monitor (ICMP über iphlpapi, ohne Admin/Raw-Sockets) ----------------

class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", wintypes.ULONG), ("Status", wintypes.ULONG), ("RoundTripTime", wintypes.ULONG),
                ("DataSize", wintypes.USHORT), ("Reserved", wintypes.USHORT), ("Data", ctypes.c_void_p),
                ("Options", IP_OPTION_INFORMATION)]

_iphlp = ctypes.windll.iphlpapi
_iphlp.IcmpCreateFile.restype = wintypes.HANDLE
_iphlp.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
_iphlp.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                                ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]

def icmp_ping(ip, timeout_ms=1000):
    handle = _iphlp.IcmpCreateFile()
    try:
        # IPAddr erwartet Netzwerk-Byte-Reihenfolge im Speicher, daher Little-Endian-Interpretation der Bytes
        addr = struct.unpack("<I", socket.inet_aton(ip))[0]
        data = ctypes.create_string_buffer(b"nexus-ping", 10)
        reply = ctypes.create_string_buffer(ctypes.sizeof(ICMP_ECHO_REPLY) + 10 + 8)
        if not _iphlp.IcmpSendEcho(handle, addr, data, 10, None, reply, len(reply), timeout_ms):
            return None
        echo = ICMP_ECHO_REPLY.from_buffer(reply)
        return echo.RoundTripTime if echo.Status == 0 else None
    finally:
        _iphlp.IcmpCloseHandle(handle)

PING_SLOTS = [
    {"label": "Router", "host": None, "ip": None, "samples": deque(maxlen=60)},
    {"label": "Internet · 1.1.1.1", "host": "1.1.1.1", "ip": "1.1.1.1", "samples": deque(maxlen=60)},
    {"label": "Eigenes Ziel", "host": None, "ip": None, "samples": deque(maxlen=60)},
]
PING_STATE = {"active_until": 0.0, "resolved_at": 0.0}

def resolve_ping_slots():
    gw = get_gateway_ip(max_age=0)
    PING_SLOTS[0].update(host=gw, ip=gw if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", gw or "") else None)
    host = get_settings()["ping_host"]
    if host != PING_SLOTS[2]["host"] or not PING_SLOTS[2]["ip"]:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = None
        PING_SLOTS[2].update(host=host, ip=ip, samples=deque(maxlen=60))
    PING_STATE["resolved_at"] = time.time()

def set_ping_host(host):
    host = str(host or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        raise ValueError("Bitte Hostname oder IP eingeben, z.B. google.com")
    try:
        socket.gethostbyname(host)
    except OSError:
        raise ValueError(f"{host} lässt sich nicht auflösen")
    with DATA_LOCK:
        USER_DATA["settings"] = dict(get_settings(), ping_host=host)
        save_user_data()
    resolve_ping_slots()

def ping_loop():
    while True:
        if time.time() > PING_STATE["active_until"]:
            time.sleep(1)
            continue
        t0 = time.time()
        try:
            if t0 - PING_STATE["resolved_at"] > 30:
                resolve_ping_slots()
            results = [None] * len(PING_SLOTS)

            def work(i, ip):
                results[i] = icmp_ping(ip, 1000) if ip else None

            threads = [threading.Thread(target=work, args=(i, s["ip"])) for i, s in enumerate(PING_SLOTS)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            for slot, rtt in zip(PING_SLOTS, results):
                slot["samples"].append(rtt)
        except Exception:
            pass
        time.sleep(max(0.0, 1 - (time.time() - t0)))

threading.Thread(target=ping_loop, daemon=True).start()

# ---------------- Speedtest über speed.cloudflare.com ----------------

SPEED_HOST = "speed.cloudflare.com"
SPEEDTEST = {"running": False, "phase": None, "live": None, "ping": None, "jitter": None,
             "down": None, "up": None, "error": None, "finished_at": None}
SPEED_LOCK = threading.Lock()

def _speed_request(path, data=None):
    req = urllib.request.Request(f"https://{SPEED_HOST}{path}", data=data,
                                 headers={"User-Agent": "NexusOS-Speedtest/1.0", "Content-Type": "application/octet-stream"})
    return urllib.request.urlopen(req, timeout=15)

def _measure_latency(samples=10):
    ip = socket.gethostbyname(SPEED_HOST)
    times = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((ip, 443), timeout=2):
                times.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
    if not times:
        raise RuntimeError("speed.cloudflare.com nicht erreichbar")
    jitter = statistics.mean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else 0.0
    return round(statistics.median(times), 1), round(jitter, 1)

def _measure_throughput(worker, seconds=8, streams=4, warmup=1.0):
    # Mehrere parallele Verbindungen, damit schnelle Leitungen nicht am TCP-Fenster einer Verbindung hängen
    state = {"bytes": 0, "warm_bytes": None, "lock": threading.Lock()}
    t0 = time.time()
    deadline = t0 + seconds
    threads = [threading.Thread(target=worker, args=(deadline, state), daemon=True) for _ in range(streams)]
    for t in threads:
        t.start()
    while time.time() < deadline and any(t.is_alive() for t in threads):
        time.sleep(0.25)
        elapsed = time.time() - t0
        if state["warm_bytes"] is None and elapsed >= warmup:
            state["warm_bytes"] = state["bytes"]
        if elapsed > 0:
            SPEEDTEST["live"] = round(state["bytes"] * 8 / elapsed / 1e6, 1)
    elapsed = time.time() - t0
    # Die erste Sekunde (TCP-Slow-Start) nicht mitzählen
    base = state["warm_bytes"] or 0
    span = max(elapsed - warmup, 0.5) if state["warm_bytes"] is not None else max(elapsed, 0.5)
    return round((state["bytes"] - base) * 8 / span / 1e6, 1)

def _download_worker(deadline, state):
    while time.time() < deadline:
        try:
            with _speed_request("/__down?bytes=50000000") as resp:
                while time.time() < deadline:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    with state["lock"]:
                        state["bytes"] += len(chunk)
        except Exception:
            return

def _upload_worker(deadline, state):
    size = 256 * 1024
    while time.time() < deadline:
        blob = UPLOAD_BLOB[:size]
        t0 = time.time()
        try:
            _speed_request("/__up", data=blob).read()
        except Exception:
            return
        with state["lock"]:
            state["bytes"] += len(blob)
        # Paketgröße wächst, solange ein Upload unter einer Sekunde dauert (weniger Overhead pro Anfrage)
        if time.time() - t0 < 1 and size < len(UPLOAD_BLOB):
            size *= 2

UPLOAD_BLOB = os.urandom(8 * 1024 * 1024)

def start_speedtest():
    with SPEED_LOCK:
        if SPEEDTEST["running"]:
            raise ValueError("Der Speedtest läuft bereits")
        SPEEDTEST.update(running=True, phase="ping", live=None, ping=None, jitter=None,
                         down=None, up=None, error=None, finished_at=None)

    def run():
        try:
            SPEEDTEST["ping"], SPEEDTEST["jitter"] = _measure_latency()
            SPEEDTEST["phase"] = "download"
            SPEEDTEST["down"] = _measure_throughput(_download_worker)
            SPEEDTEST.update(phase="upload", live=None)
            SPEEDTEST["up"] = _measure_throughput(_upload_worker)
        except Exception as e:
            SPEEDTEST["error"] = str(e)
        SPEEDTEST.update(running=False, phase=None, live=None, finished_at=datetime.now().strftime("%H:%M"))

    threading.Thread(target=run, daemon=True).start()
    return dict(SPEEDTEST)

# ---------------- Festplatten-Gesundheit ----------------

def get_disk_health():
    script = (
        "Get-PhysicalDisk | ForEach-Object {"
        " $r = $_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue;"
        " [pscustomobject]@{ name = $_.FriendlyName; media = [string]$_.MediaType; bus = [string]$_.BusType;"
        " health = [string]$_.HealthStatus; size_gb = [math]::Round($_.Size / 1GB);"
        " temp = $r.Temperature; wear = $r.Wear; hours = $r.PowerOnHours;"
        " read_errors = $r.ReadErrorsTotal; write_errors = $r.WriteErrorsTotal }"
        "} | ConvertTo-Json"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    res = subprocess.run(["powershell", "-NoProfile", "-EncodedCommand", encoded],
                         capture_output=True, text=True, encoding="oem", errors="replace",
                         creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
    disks = json.loads(res.stdout or "[]")
    return disks if isinstance(disks, list) else [disks]

# ---------------- Massen-Umbenennen ----------------

LAST_RENAME_HISTORY = []
INVALID_NAME_CHARS = re.compile(r'[\\/:*?"<>|]')

def plan_renames(payload):
    folder = resolve_preset_path(payload.get("path") or "")
    if not os.path.isdir(folder):
        raise ValueError(f"Ordner nicht gefunden: {folder}")
    pattern = str(payload.get("pattern") or "{name}")
    if len(pattern) > 120:
        raise ValueError("Muster: maximal 120 Zeichen")
    ext_filter = str(payload.get("ext") or "").strip().lower()
    if ext_filter and not ext_filter.startswith("."):
        ext_filter = "." + ext_filter
    find, replace = str(payload.get("find") or ""), str(payload.get("replace") or "")
    start = max(0, int(payload.get("start") or 1))

    files = [e for e in os.scandir(folder)
             if e.is_file() and not e.name.startswith(".") and e.name.lower() != "desktop.ini"
             and (not ext_filter or e.name.lower().endswith(ext_filter))]
    if payload.get("sort") == "date":
        files.sort(key=lambda e: e.stat().st_mtime)
    else:
        files.sort(key=lambda e: e.name.lower())
    pad = max(2, len(str(start + len(files) - 1)))

    plan = []
    for i, e in enumerate(files):
        base, ext = os.path.splitext(e.name)
        new_base = (pattern.replace("{name}", base)
                    .replace("{n}", str(start + i).zfill(pad))
                    .replace("{date}", datetime.fromtimestamp(e.stat().st_mtime).strftime("%Y-%m-%d")))
        if find:
            new_base = new_base.replace(find, replace)
        new_name = new_base.strip() + ext
        if not new_base.strip() or INVALID_NAME_CHARS.search(new_name):
            raise ValueError(f"Ungültiger neuer Name für {e.name}: {new_name}")
        plan.append({"old": e.name, "new": new_name})

    # Konflikte: zwei Dateien mit gleichem Ziel, oder Ziel existiert schon und wird nicht selbst umbenannt
    sources = {p["old"].lower() for p in plan}
    seen = set()
    for p in plan:
        key = p["new"].lower()
        p["conflict"] = key in seen or (key not in sources and os.path.exists(os.path.join(folder, p["new"])))
        seen.add(key)
    return folder, plan

def preview_renames(payload):
    folder, plan = plan_renames(payload)
    changed = [p for p in plan if p["old"] != p["new"]]
    return {"folder": folder, "total": len(plan), "changed": len(changed),
            "conflicts": sum(p["conflict"] for p in plan), "items": changed[:200]}

def apply_renames(payload):
    global LAST_RENAME_HISTORY
    folder, plan = plan_renames(payload)
    if any(p["conflict"] for p in plan):
        raise ValueError("Es gibt Namenskonflikte – bitte Muster anpassen")
    todo = [p for p in plan if p["old"] != p["new"]]
    path = lambda name: os.path.join(folder, name)
    # Zwei Phasen über Zwischennamen, damit Tausch-Fälle (a→b, b→a) nicht kollidieren
    temp, done = [], []
    try:
        for i, p in enumerate(todo):
            tmp_name = f".nexus_rename_{uuid.uuid4().hex[:8]}_{i}"
            os.rename(path(p["old"]), path(tmp_name))
            temp.append((tmp_name, p))
        for tmp_name, p in temp:
            os.rename(path(tmp_name), path(p["new"]))
            done.append(p)
    except OSError as e:
        # Alles zurückdrehen, damit keine .nexus_rename_-Zwischennamen liegen bleiben
        for p in done:
            try:
                os.rename(path(p["new"]), path(p["old"]))
            except OSError:
                pass
        for tmp_name, p in temp:
            if p not in done and os.path.exists(path(tmp_name)):
                try:
                    os.rename(path(tmp_name), path(p["old"]))
                except OSError:
                    pass
        raise ValueError(f"Umbenennen abgebrochen, alles zurückgesetzt: {e}")
    LAST_RENAME_HISTORY = [(path(p["new"]), path(p["old"])) for p in done]
    return {"renamed": len(done)}

def undo_renames():
    global LAST_RENAME_HISTORY
    restored = 0
    for new_path, old_path in reversed(LAST_RENAME_HISTORY):
        try:
            if os.path.exists(new_path) and not os.path.exists(old_path):
                os.rename(new_path, old_path)
                restored += 1
        except OSError:
            pass
    LAST_RENAME_HISTORY = []
    return restored

def open_url(url):
    url = str(url or "")
    if not re.fullmatch(r"https?://[^\s\"']{1,2000}", url):
        raise ValueError("Ungültige Adresse")
    # explorer.exe öffnet den Standardbrowser mit normalen Rechten
    subprocess.Popen(["explorer.exe", url])
    return True

# =====================================================================
# MODULE 10: FILE CONVERTER
# =====================================================================

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".jfif", ".bmp", ".gif", ".tif", ".tiff", ".ico", ".webp", ".heic", ".heif", ".avif"}
AUDIO_EXTS = {".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac", ".wma", ".opus"}
VIDEO_EXTS = {".mp4", ".mkv", ".mov", ".avi", ".webm", ".wmv", ".flv", ".m4v", ".ts"}

# Zielformat -> (passende Quellendungen, Endung der Ausgabedatei)
CONVERT_TARGETS = {
    "png": (IMAGE_EXTS, ".png"),
    "jpg": (IMAGE_EXTS, ".jpg"),
    "bmp": (IMAGE_EXTS, ".bmp"),
    "tiff": (IMAGE_EXTS, ".tiff"),
    "ico": (IMAGE_EXTS, ".ico"),
    "gif": (IMAGE_EXTS | VIDEO_EXTS, ".gif"),
    "pdf": (IMAGE_EXTS, ".pdf"),
    "mp3": (AUDIO_EXTS | VIDEO_EXTS, ".mp3"),
    "wav": (AUDIO_EXTS | VIDEO_EXTS, ".wav"),
    "ogg": (AUDIO_EXTS | VIDEO_EXTS, ".ogg"),
    "flac": (AUDIO_EXTS | VIDEO_EXTS, ".flac"),
    "m4a": (AUDIO_EXTS | VIDEO_EXTS, ".m4a"),
    "mp4": (VIDEO_EXTS, ".mp4"),
    "mp4_discord": (VIDEO_EXTS, ".mp4"),
    "json": ({".csv"}, ".json"),
    "csv": ({".json"}, ".csv"),
}
WPF_FORMATS = {"png", "jpg", "bmp", "tiff", "ico", "gif"}
VIDEO_QUALITY = {"high": (20, None), "medium": (24, 1080), "small": (30, 720)}
CONVERT_JOB = {"running": False, "format": None, "items": [], "message": None, "finished_at": None}
CONVERT_LOCK = threading.Lock()

# Bilder über WPF/WIC: in Windows eingebaut, liest auch WebP/HEIC, sofern die Codecs installiert sind
IMAGE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
Add-Type -AssemblyName PresentationCore, WindowsBase
$jobs = Get-Content -Raw -Encoding UTF8 -LiteralPath $JobFile | ConvertFrom-Json
foreach ($j in $jobs) {
  try {
    $fs = [IO.File]::OpenRead($j.src)
    try {
      $dec = [Windows.Media.Imaging.BitmapDecoder]::Create($fs, [Windows.Media.Imaging.BitmapCreateOptions]::PreservePixelFormat, [Windows.Media.Imaging.BitmapCacheOption]::OnLoad)
      $frame = $dec.Frames[0]
    } finally { $fs.Dispose() }

    # EXIF-Ausrichtung anwenden, sonst liegen Handyfotos nach der Konvertierung auf der Seite
    $orient = 1
    foreach ($q in '/app1/ifd/{ushort=274}', '/ifd/{ushort=274}') {
      try { $v = $frame.Metadata.GetQuery($q); if ($v) { $orient = [int]$v; break } } catch {}
    }
    $angle = @{ 3 = 180; 6 = 90; 8 = 270 }[$orient]
    $img = $frame
    if ($angle) { $img = New-Object Windows.Media.Imaging.TransformedBitmap($frame, (New-Object Windows.Media.RotateTransform($angle))) }

    $w = $img.PixelWidth; $h = $img.PixelHeight
    $scale = 1.0
    if ($j.max_side -gt 0) { $scale = [Math]::Min(1.0, $j.max_side / [Math]::Max($w, $h)) }
    $tw = [Math]::Max(1, [int][Math]::Round($w * $scale)); $th = [Math]::Max(1, [int][Math]::Round($h * $scale))
    $cw = $tw; $ch = $th
    if ($j.square) { $cw = [Math]::Max($tw, $th); $ch = $cw }

    # Neu rendern: skaliert, zentriert (Icons) und bei JPG/BMP auf Weiß statt Schwarz für Transparenz
    $dv = New-Object Windows.Media.DrawingVisual
    $dc = $dv.RenderOpen()
    if ($j.flatten) { $dc.DrawRectangle([Windows.Media.Brushes]::White, $null, (New-Object Windows.Rect(0, 0, $cw, $ch))) }
    $dc.DrawImage($img, (New-Object Windows.Rect((($cw - $tw) / 2), (($ch - $th) / 2), $tw, $th)))
    $dc.Close()
    $rtb = New-Object Windows.Media.Imaging.RenderTargetBitmap($cw, $ch, 96, 96, [Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($dv)

    switch ($j.format) {
      'jpg'  { $enc = New-Object Windows.Media.Imaging.JpegBitmapEncoder; $enc.QualityLevel = [int]$j.quality }
      'bmp'  { $enc = New-Object Windows.Media.Imaging.BmpBitmapEncoder }
      'tiff' { $enc = New-Object Windows.Media.Imaging.TiffBitmapEncoder }
      'gif'  { $enc = New-Object Windows.Media.Imaging.GifBitmapEncoder }
      default { $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder }
    }
    $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($rtb))
    $out = [IO.File]::Create($j.out)
    try { $enc.Save($out) } finally { $out.Dispose() }
    [Console]::Out.WriteLine("OK|$($j.id)|$cw|$ch")
  } catch {
    [Console]::Out.WriteLine("ERR|$($j.id)|" + ($_.Exception.Message -replace '\r?\n', ' '))
  }
  [Console]::Out.Flush()
}
"""

def unique_output(src, ext, out_dir=None, taken=None, name=None):
    folder = out_dir or os.path.dirname(src)
    base = name or os.path.splitext(os.path.basename(src))[0]
    taken = taken if taken is not None else set()
    candidate = os.path.join(folder, base + ext)
    n = 1
    # Nie die Quelle überschreiben und nie zwei Ausgaben auf denselben Namen legen
    while (os.path.exists(candidate) or os.path.normcase(candidate) == os.path.normcase(src)
           or os.path.normcase(candidate) in taken):
        candidate = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    taken.add(os.path.normcase(candidate))
    return candidate

def run_wpf_images(jobs):
    """Konvertiert alle Bilder in einem einzigen PowerShell-Prozess; liefert (OK/ERR, id, info) je Datei."""
    job_file = os.path.join(tempfile.gettempdir(), f"nexus_convert_{uuid.uuid4().hex[:8]}.json")
    with open(job_file, "w", encoding="utf-8") as f:
        json.dump(jobs, f, ensure_ascii=False)
    script = f"$JobFile = {ps_quote(job_file)}\n{IMAGE_SCRIPT}"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    proc = subprocess.Popen(["powershell", "-NoProfile", "-STA", "-EncodedCommand", encoded],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        for line in proc.stdout:
            parts = line.strip().lstrip("﻿").split("|", 2)
            if len(parts) == 3 and parts[0] in ("OK", "ERR") and parts[1].isdigit():
                yield parts[0], int(parts[1]), parts[2]
        proc.wait()
    finally:
        try:
            os.remove(job_file)
        except OSError:
            pass

def write_ico(png_path, out_path):
    data = open(png_path, "rb").read()
    width, height = struct.unpack(">II", data[16:24])  # aus dem PNG-IHDR
    # ICO mit eingebettetem PNG (ab Windows Vista); 256 px wird im Header als 0 kodiert
    entry = struct.pack("<BBBBHHII", width % 256, height % 256, 0, 0, 1, 32, len(data), 22)
    with open(out_path, "wb") as f:
        f.write(struct.pack("<HHH", 0, 1, 1) + entry + data)

def write_pdf(pages, out_path):
    """pages: Liste von (jpeg_bytes, breite, höhe); jede Seite A4, Bild eingepasst und zentriert."""
    a4_w, a4_h = 595.28, 841.89
    objects = [b"", b""]  # 1 = Catalog, 2 = Pages (werden am Ende gefüllt)
    page_ids = []
    for i, (jpeg, w, h) in enumerate(pages):
        pw, ph = (a4_h, a4_w) if w > h else (a4_w, a4_h)
        scale = min(pw / w, ph / h)
        dw, dh = w * scale, h * scale
        objects.append(b"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB "
                       b"/BitsPerComponent 8 /Filter /DCTDecode /Length %d >>\nstream\n" % (w, h, len(jpeg))
                       + jpeg + b"\nendstream")
        img_id = len(objects)
        content = f"q {dw:.2f} 0 0 {dh:.2f} {(pw - dw) / 2:.2f} {(ph - dh) / 2:.2f} cm /Im{i} Do Q".encode()
        objects.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
        content_id = len(objects)
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {pw:.2f} {ph:.2f}] "
                       f"/Resources << /XObject << /Im{i} {img_id} 0 R >> >> /Contents {content_id} 0 R >>".encode())
        page_ids.append(len(objects))
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{p} 0 R' for p in page_ids)}] /Count {len(page_ids)} >>".encode()

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for num, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % num + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    with open(out_path, "wb") as f:
        f.write(out)

def find_ffmpeg():
    path = shutil.which("ffmpeg")
    if path:
        return path
    # winget legt ffmpeg hier ab (Benutzer- bzw. Maschinen-Scope); der PATH dieses Prozesses kennt das
    # nach einer Installation zur Laufzeit noch nicht
    bases = [os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WinGet"),
             os.path.join(os.environ.get("ProgramFiles", ""), "WinGet")]
    for base in bases:
        link = os.path.join(base, "Links", "ffmpeg.exe")
        if os.path.exists(link):
            return link
        hits = glob.glob(os.path.join(base, "Packages", "*FFmpeg*", "**", "bin", "ffmpeg.exe"), recursive=True)
        if hits:
            return hits[0]
    return None

def media_duration(ffmpeg, src):
    res = subprocess.run([ffmpeg, "-hide_banner", "-i", src], capture_output=True, text=True, encoding="utf-8",
                         errors="replace", creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
    m = re.search(r"Duration: (\d+):(\d+):(\d+(?:\.\d+)?)", res.stderr)
    return int(m[1]) * 3600 + int(m[2]) * 60 + float(m[3]) if m else None

def ffmpeg_args(fmt, duration, opts):
    if fmt == "mp3":
        return ["-vn", "-c:a", "libmp3lame", "-q:a", "2"]
    if fmt == "wav":
        return ["-vn", "-c:a", "pcm_s16le"]
    if fmt == "ogg":
        return ["-vn", "-c:a", "libvorbis", "-q:a", "5"]
    if fmt == "flac":
        return ["-vn", "-c:a", "flac"]
    if fmt == "m4a":
        return ["-vn", "-c:a", "aac", "-b:a", "192k"]
    if fmt == "gif":
        width = opts["max_side"] or 480
        return ["-vf", f"fps=12,scale='min({width},iw)':-1:flags=lanczos,split[a][b];[a]palettegen[p];[b][p]paletteuse",
                "-loop", "0"]
    if fmt == "mp4":
        crf, max_h = VIDEO_QUALITY[opts["video_quality"]]
        scale = ["-vf", f"scale=-2:'min({max_h},ih)'"] if max_h else []
        return scale + ["-c:v", "libx264", "-preset", "veryfast", "-crf", str(crf), "-pix_fmt", "yuv420p",
                        "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart"]
    # mp4_discord: Bitrate so wählen, dass ~9 MB herauskommen (Discord-Limit 10 MB, etwas Puffer für ABR-Ausreißer)
    if not duration:
        raise ValueError("Videolänge unbekannt – Discord-Größe lässt sich nicht berechnen")
    video_kbps = int(max(150, 9 * 8 * 1024 * 1024 / 1000 / duration - 96))
    return ["-vf", "scale=-2:'min(720,ih)'", "-c:v", "libx264", "-preset", "veryfast", "-b:v", f"{video_kbps}k",
            "-maxrate", f"{video_kbps}k", "-bufsize", f"{video_kbps * 2}k", "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-b:a", "96k", "-movflags", "+faststart"]

def run_ffmpeg_item(ffmpeg, item, fmt, opts):
    duration = media_duration(ffmpeg, item["src"])
    args = [ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-i", item["src"],
            *ffmpeg_args(fmt, duration, opts), "-progress", "pipe:1", "-nostats", item["out"]]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
    for line in proc.stdout:
        # out_time_ms ist trotz des Namens in Mikrosekunden
        if line.startswith("out_time_ms=") and duration:
            try:
                item["progress"] = min(99, int(int(line.split("=", 1)[1]) / 1e6 / duration * 100))
            except ValueError:
                pass
    err = proc.stderr.read().strip()
    if proc.wait() != 0:
        raise RuntimeError(err.splitlines()[-1] if err else f"ffmpeg beendet mit Code {proc.returncode}")
    size_mb = os.path.getsize(item["out"]) / 1024 / 1024
    note = " – über 10 MB, Video zu lang für Discord" if fmt == "mp4_discord" and size_mb > 10 else ""
    return f"{size_mb:.1f} MB{note}"

def read_text_file(path):
    raw = open(path, "rb").read()
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            pass
    return raw.decode("latin-1")

def convert_data(src, out, fmt):
    text = read_text_file(src)
    if fmt == "json":
        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        rows = list(csv.DictReader(io.StringIO(text), dialect=dialect))
        with open(out, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        return f"{len(rows)} Zeilen"
    data = json.loads(text)
    if isinstance(data, dict):
        # {"items": [...]} → die Liste nehmen; sonst das Objekt als eine Zeile
        lists = [v for v in data.values() if isinstance(v, list)]
        data = lists[0] if len(lists) == 1 else [data]
    if not isinstance(data, list):
        raise ValueError("JSON muss eine Liste von Objekten sein")
    rows = [r if isinstance(r, dict) else {"wert": r} for r in data]
    columns = list(dict.fromkeys(k for r in rows for k in r))
    # Semikolon + BOM: so öffnet deutsches Excel die Datei per Doppelklick mit richtigen Spalten und Umlauten
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, delimiter=";")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
                             for k, v in r.items()})
    return f"{len(rows)} Zeilen"

def _convert_images(items, fmt, opts, out_dir, taken):
    tmp_dir = tempfile.mkdtemp(prefix="nexus_conv_")
    jobs = []
    for it in items:
        it["status"] = "running"
        it["out"] = unique_output(it["src"], CONVERT_TARGETS[fmt][1], out_dir, taken)
        is_ico = fmt == "ico"
        jobs.append({
            "id": it["id"], "src": it["src"],
            "out": os.path.join(tmp_dir, f"{it['id']}.png") if is_ico else it["out"],
            "format": "png" if is_ico else fmt, "quality": opts["quality"],
            "max_side": 256 if is_ico else opts["max_side"],
            "flatten": fmt in ("jpg", "bmp"), "square": is_ico,
        })
    by_id = {it["id"]: it for it in items}
    try:
        for kind, job_id, info in run_wpf_images(jobs):
            it = by_id.get(job_id)
            if not it:
                continue
            if kind == "OK":
                if fmt == "ico":
                    write_ico(os.path.join(tmp_dir, f"{job_id}.png"), it["out"])
                it.update(status="ok", progress=100, info=info.replace("|", " × ") + " px")
            else:
                it.update(status="error", info=info)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

def _convert_pdf(items, opts, out_dir, taken):
    tmp_dir = tempfile.mkdtemp(prefix="nexus_pdf_")
    jobs = [{"id": it["id"], "src": it["src"], "out": os.path.join(tmp_dir, f"{it['id']}.jpg"), "format": "jpg",
             "quality": 88, "max_side": opts["max_side"] or 2480, "flatten": True, "square": False} for it in items]
    for it in items:
        it["status"] = "running"
    by_id = {it["id"]: it for it in items}
    pages = {}
    try:
        for kind, job_id, info in run_wpf_images(jobs):
            it = by_id.get(job_id)
            if kind == "OK" and it:
                w, h = (int(x) for x in info.split("|"))
                with open(os.path.join(tmp_dir, f"{job_id}.jpg"), "rb") as f:
                    pages[job_id] = (f.read(), w, h)
                it["progress"] = 100
            elif it:
                it.update(status="error", info=info)
        ordered = [it for it in items if it["id"] in pages]
        if not ordered:
            return
        name = None if len(ordered) == 1 else f"Bilder {datetime.now():%Y-%m-%d %H-%M}"
        out = unique_output(ordered[0]["src"], ".pdf", out_dir, taken, name=name)
        write_pdf([pages[it["id"]] for it in ordered], out)
        for n, it in enumerate(ordered, 1):
            it.update(status="ok", out=out, info=f"Seite {n} von {len(ordered)}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

def _conversion_worker(fmt, items, opts, out_dir):
    todo = [it for it in items if it["status"] == "pending"]
    taken = set()
    try:
        if fmt == "pdf":
            _convert_pdf(todo, opts, out_dir, taken)
        else:
            images = [it for it in todo if fmt in WPF_FORMATS and os.path.splitext(it["src"])[1].lower() in IMAGE_EXTS]
            if images:
                _convert_images(images, fmt, opts, out_dir, taken)
            ffmpeg = find_ffmpeg()
            for it in todo:
                if it in images:
                    continue
                it["status"] = "running"
                it["out"] = unique_output(it["src"], CONVERT_TARGETS[fmt][1], out_dir, taken,
                                          name=os.path.splitext(it["name"])[0] + ("_discord" if fmt == "mp4_discord" else ""))
                try:
                    if fmt in ("json", "csv"):
                        info = convert_data(it["src"], it["out"], fmt)
                    else:
                        info = run_ffmpeg_item(ffmpeg, it, fmt, opts)
                    it.update(status="ok", progress=100, info=info)
                except Exception as e:
                    it.update(status="error", info=str(e))
    except Exception as e:
        for it in todo:
            if it["status"] in ("pending", "running"):
                it.update(status="error", info=str(e))
    for it in todo:
        if it["status"] in ("pending", "running"):
            it.update(status="error", info="Keine Antwort vom Konverter")
    ok = sum(it["status"] == "ok" for it in todo)
    CONVERT_JOB.update(running=False, finished_at=datetime.now().strftime("%H:%M"),
                       message=f"{ok} von {len(todo)} Dateien konvertiert")

def start_conversion(payload):
    fmt = payload.get("format")
    if fmt not in CONVERT_TARGETS:
        raise ValueError("Unbekanntes Zielformat")
    files = [str(p) for p in payload.get("files") or []][:300]
    if not files:
        raise ValueError("Keine Dateien ausgewählt")
    out_dir = str(payload.get("out_dir") or "").strip() or None
    if out_dir and not os.path.isdir(out_dir):
        raise ValueError(f"Ausgabeordner nicht gefunden: {out_dir}")
    opts = {
        "quality": min(100, max(1, int(payload.get("quality") or 90))),
        "max_side": min(20000, max(0, int(payload.get("max_side") or 0))),
        "video_quality": payload.get("video_quality") if payload.get("video_quality") in VIDEO_QUALITY else "medium",
    }
    allowed = CONVERT_TARGETS[fmt][0]
    items = []
    for i, src in enumerate(files):
        item = {"id": i, "src": src, "name": os.path.basename(src), "status": "pending",
                "progress": 0, "out": None, "info": None}
        if not os.path.isfile(src):
            item.update(status="skipped", info="Datei nicht gefunden")
        elif os.path.splitext(src)[1].lower() not in allowed:
            item.update(status="skipped", info="passt nicht zu diesem Zielformat")
        items.append(item)
    pending = [it for it in items if it["status"] == "pending"]
    if not pending:
        raise ValueError("Keine der Dateien passt zum gewählten Zielformat")
    needs_ffmpeg = any(fmt not in WPF_FORMATS | {"pdf", "json", "csv"}
                       or os.path.splitext(it["src"])[1].lower() in VIDEO_EXTS for it in pending)
    if needs_ffmpeg and not find_ffmpeg():
        raise ValueError("Für Audio und Video wird ffmpeg gebraucht – klick bei „ffmpeg“ auf Installieren")
    with CONVERT_LOCK:
        if CONVERT_JOB["running"]:
            raise ValueError("Es läuft bereits eine Konvertierung")
        CONVERT_JOB.update(running=True, format=fmt, items=items, message=None, finished_at=None)
    threading.Thread(target=_conversion_worker, args=(fmt, items, opts, out_dir), daemon=True).start()
    return CONVERT_JOB

def install_ffmpeg():
    with CONVERT_LOCK:
        if CONVERT_JOB["running"]:
            raise ValueError("Bitte warten, bis die laufende Aufgabe fertig ist")
        CONVERT_JOB.update(running=True, format="ffmpeg-install", items=[],
                           message="ffmpeg wird über winget installiert …", finished_at=None)

    def worker():
        try:
            res = run_winget(["install", "--id", "Gyan.FFmpeg", "--exact", "--silent",
                              "--accept-package-agreements"], timeout=900)
            path = find_ffmpeg()
            msg = f"ffmpeg installiert: {path}" if path else \
                "Installation fehlgeschlagen: " + " ".join(clean_winget_output(res.stdout)[-2:])
        except Exception as e:
            msg = f"Installation fehlgeschlagen: {e}"
        CONVERT_JOB.update(running=False, message=msg, finished_at=datetime.now().strftime("%H:%M"))

    threading.Thread(target=worker, daemon=True).start()
    return CONVERT_JOB

def pick_paths_dialog(mode):
    # Windows-Dialog statt Browser-Dateiauswahl: nur so bekommen wir echte Pfade statt Datei-Kopien
    script = (
        "Add-Type -AssemblyName System.Windows.Forms, System.Drawing\n"
        "[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false\n"
        "$owner = New-Object System.Windows.Forms.Form\n"
        "$owner.TopMost = $true; $owner.ShowInTaskbar = $false; $owner.Opacity = 0\n"
        "$owner.StartPosition = 'CenterScreen'; $owner.Size = New-Object System.Drawing.Size(1, 1)\n"
        "$owner.Show(); $owner.Activate()\n"
    )
    if mode == "folder":
        script += (
            "$d = New-Object System.Windows.Forms.FolderBrowserDialog\n"
            "$d.Description = 'Ausgabeordner für konvertierte Dateien'\n"
            "if ($d.ShowDialog($owner) -eq 'OK') { ConvertTo-Json @($d.SelectedPath) -Compress }\n"
        )
    else:
        patterns = ";".join(f"*{e}" for e in sorted(IMAGE_EXTS | AUDIO_EXTS | VIDEO_EXTS | {".csv", ".json"}))
        script += (
            "$d = New-Object System.Windows.Forms.OpenFileDialog\n"
            "$d.Multiselect = $true\n"
            "$d.Title = 'Dateien zum Konvertieren auswählen'\n"
            f"$d.Filter = 'Unterstützte Dateien|{patterns}|Alle Dateien|*.*'\n"
            "if ($d.ShowDialog($owner) -eq 'OK') { ConvertTo-Json @($d.FileNames) -Compress }\n"
        )
    script += "$owner.Dispose()\n"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    res = subprocess.run(["powershell", "-NoProfile", "-STA", "-EncodedCommand", encoded],
                         capture_output=True, text=True, encoding="utf-8", errors="replace",
                         creationflags=subprocess.CREATE_NO_WINDOW, timeout=900)
    out = res.stdout.strip().lstrip("﻿")
    return json.loads(out) if out else []


# =====================================================================
# MONOLITH // NEXUS OS FRONTEND v10.0 QUANTUM
# =====================================================================

HTML_UI = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<title>MONOLITH // NEXUS OS v10.0 QUANTUM</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

  :root {
    --bg: #050506;
    --surface: #0b0b0e;
    --surface-2: #111116;
    --border: rgba(255, 255, 255, 0.08);
    --border-strong: rgba(255, 255, 255, 0.2);
    --text-primary: #fafafa;
    --text-secondary: #a1a1aa;
    --text-muted: #52525b;
    --accent: #ffffff;
    --accent-glow: rgba(255, 255, 255, 0.14);
    --status-ok: #10b981;
    --status-warn: #f59e0b;
    --status-danger: #ef4444;
    /* Theme-Variablen: werden von applyUi() je nach Design-Einstellung überschrieben */
    --input-bg: #060608;
    --topbar-bg: rgba(5, 5, 6, 0.85);
    --sidebar-bg: rgba(9, 9, 12, 0.7);
    --tint-1: rgba(255, 255, 255, 0.018);
    --tint-2: rgba(255, 255, 255, 0.035);
    --tint-3: rgba(255, 255, 255, 0.065);
    --tint-4: rgba(255, 255, 255, 0.12);
    --tint-5: rgba(255, 255, 255, 0.25);
    --spot: rgba(255, 255, 255, 0.045);
    --pattern-line: rgba(255, 255, 255, 0.035);
    --track: #27272a;
    --knob: #ffffff;
    --on-accent: #050506;
    --danger-text: #f87171;
    --font-ui: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --rs: 1;
    --card-pad: 16px 18px;
    --gap: 14px;
    --accent-2: #a855f7;
    --accent-fill: var(--accent);
    --name-fill: linear-gradient(135deg, var(--text-primary) 15%, var(--accent));
    --sidebar-w: 240px;
    --speed: 1;
    --enter: enter-pop;
    --shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
    --noise-opacity: 0.07;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    user-select: none;
    -webkit-font-smoothing: antialiased;
  }

  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--tint-4); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--tint-5); }

  body {
    background-color: var(--bg);
    color: var(--text-primary);
    font-family: var(--font-ui);
    height: 100vh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    background-image: radial-gradient(ellipse 80% 45% at 50% -15%, var(--accent-glow), transparent);
    transition: background-image 0.4s ease;
  }

  .progress-line {
    position: fixed;
    top: 54px;
    left: 0;
    height: 2px;
    background: var(--accent-fill);
    width: 0%;
    transition: width 0.3s ease, opacity 0.3s ease;
    opacity: 0;
    z-index: 100;
    box-shadow: 0 0 12px var(--accent);
  }
  .progress-line.active { width: 100%; opacity: 1; }

  .topbar {
    height: 54px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 22px;
    background: var(--topbar-bg);
    backdrop-filter: blur(14px);
    z-index: 20;
    flex-shrink: 0;
  }

  .brand { display: flex; align-items: center; gap: 11px; }
  .brand-mark {
    width: 18px;
    height: 18px;
    background: var(--accent-fill);
    border-radius: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 0 12px var(--accent-glow);
    transition: background 0.3s ease;
  }
  .brand-mark::after {
    content: '';
    width: 6px;
    height: 6px;
    background: var(--bg);
    border-radius: 1px;
  }
  .brand-name {
    font-weight: 700;
    font-size: 0.88rem;
    letter-spacing: 0.09em;
  }
  .version-pill {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.66rem;
    color: var(--text-secondary);
    background: var(--tint-2);
    border: 1px solid var(--border);
    padding: 2px 8px;
    border-radius: 999px;
  }

  .topbar-right { display: flex; align-items: center; gap: 10px; }
  .status-indicator {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 0.72rem;
    color: var(--text-secondary);
    font-family: 'JetBrains Mono', monospace;
    margin-right: 6px;
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--status-ok);
    box-shadow: 0 0 8px var(--status-ok);
  }

  .theme-dots {
    display: flex;
    align-items: center;
    gap: 5px;
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 4px 8px;
    border-radius: 99px;
  }
  .theme-dot {
    width: 11px;
    height: 11px;
    border-radius: 50%;
    cursor: pointer;
    border: 1px solid var(--tint-5);
    transition: transform 0.15s ease;
  }
  .theme-dot:hover { transform: scale(1.25); }

  .app-shell {
    flex: 1;
    display: grid;
    grid-template-columns: var(--sidebar-w) 1fr;
    min-height: 0;
  }

  .sidebar {
    border-right: 1px solid var(--border);
    background: var(--sidebar-bg);
    padding: 18px 12px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 12px;
    min-height: 0;
  }

  /* Viele Module + breite Schriften: Navigation scrollt, die Uhr unten bleibt sichtbar */
  .nav-group { display: flex; flex-direction: column; gap: 4px; overflow-y: auto; min-height: 0; flex-shrink: 1; }
  .sidebar-footer { flex-shrink: 0; }
  .nav-btn > span:first-child { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; }
  .nav-btn .nav-badge { flex-shrink: 0; margin-left: 6px; }
  .nav-caption {
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    padding: 6px 10px 4px;
  }

  .nav-btn {
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-secondary);
    padding: 9px 12px;
    border-radius: calc(7px * var(--rs));
    font-size: 0.79rem;
    font-weight: 500;
    font-family: var(--font-ui);
    text-align: left;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: all 0.15s ease;
  }
  .nav-btn:hover {
    color: var(--text-primary);
    background: var(--tint-2);
  }
  .nav-btn.active {
    color: var(--text-primary);
    background: var(--tint-3);
    border-color: var(--border-strong);
    font-weight: 600;
  }
  .nav-badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    padding: 1px 6px;
    border-radius: 4px;
    background: var(--tint-3);
    color: var(--text-secondary);
  }

  .sidebar-footer {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: calc(8px * var(--rs));
    padding: 11px 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .live-clock {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.2rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 0.03em;
  }

  .content-col {
    display: grid;
    grid-template-rows: 1fr 125px;
    gap: var(--gap);
    padding: 18px 22px;
    min-height: 0;
  }

  .view-panel {
    display: none;
    overflow-y: auto;
    padding-right: 4px;
    flex-direction: column;
    gap: var(--gap);
  }
  .view-panel.active { display: flex; }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: calc(10px * var(--rs));
    padding: var(--card-pad);
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s ease, transform 0.25s ease, box-shadow 0.25s ease, background 0.3s ease;
    flex-shrink: 0;
  }
  .card::before {
    content: '';
    position: absolute;
    inset: 0;
    background: radial-gradient(
      480px circle at var(--mouse-x, -500px) var(--mouse-y, -500px),
      var(--spot),
      transparent 40%
    );
    pointer-events: none;
  }
  .card:hover { border-color: var(--border-strong); }

  .section-label {
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: var(--gap); }
  .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: calc(var(--gap) - 2px); }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: calc(var(--gap) - 2px); }

  .metric-box {
    background: var(--tint-1);
    border: 1px solid var(--border);
    border-radius: calc(8px * var(--rs));
    padding: 11px 13px;
  }
  .metric-title {
    font-size: 0.68rem;
    color: var(--text-secondary);
    display: flex;
    justify-content: space-between;
    margin-bottom: 4px;
  }
  .metric-val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-primary);
  }

  label {
    display: block;
    font-size: 0.72rem;
    font-weight: 500;
    color: var(--text-secondary);
    margin-bottom: 5px;
  }

  select, input[type="text"], input[type="number"] {
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 8px 11px;
    border-radius: calc(6px * var(--rs));
    font-family: var(--font-ui);
    font-size: 0.79rem;
    outline: none;
    transition: border-color 0.15s ease;
  }
  input.mono { font-family: 'JetBrains Mono', monospace; }
  select:focus, input:focus { border-color: var(--accent); }

  .btn-primary {
    background: var(--accent-fill);
    color: var(--on-accent);
    border: 1px solid transparent;
    padding: 9px 16px;
    border-radius: calc(6px * var(--rs));
    font-family: var(--font-ui);
    font-size: 0.79rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
  }
  .btn-primary:hover {
    filter: brightness(1.1);
    transform: translateY(-1px);
    box-shadow: 0 4px 18px var(--accent-glow);
  }

  .btn-secondary {
    background: var(--tint-2);
    color: var(--text-primary);
    border: 1px solid var(--border);
    padding: 8px 13px;
    border-radius: calc(6px * var(--rs));
    font-family: var(--font-ui);
    font-size: 0.76rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }
  .btn-secondary:hover {
    background: var(--tint-3);
    border-color: var(--border-strong);
  }

  .btn-danger {
    background: rgba(239, 68, 68, 0.12);
    color: var(--danger-text);
    border: 1px solid rgba(239, 68, 68, 0.3);
    padding: 8px 13px;
    border-radius: calc(6px * var(--rs));
    font-size: 0.76rem;
    font-weight: 600;
    cursor: pointer;
  }
  .btn-danger:hover { background: rgba(239, 68, 68, 0.22); }

  .tweak-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    background: var(--tint-1);
    border: 1px solid var(--border);
    border-radius: calc(8px * var(--rs));
  }
  .tweak-info h4 { font-size: 0.8rem; font-weight: 600; margin-bottom: 2px; }
  .tweak-info p { font-size: 0.7rem; color: var(--text-secondary); }

  .switch {
    position: relative;
    width: 38px;
    height: 20px;
    flex-shrink: 0;
  }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute;
    cursor: pointer;
    inset: 0;
    background-color: var(--track);
    transition: .2s;
    border-radius: 20px;
  }
  .slider:before {
    position: absolute;
    content: "";
    height: 14px;
    width: 14px;
    left: 3px;
    bottom: 3px;
    background-color: var(--knob);
    transition: .2s;
    border-radius: 50%;
  }
  input:checked + .slider { background: var(--accent-fill); }
  input:checked + .slider:before {
    transform: translateX(18px);
    background-color: var(--on-accent);
  }

  .power-hero {
    text-align: center;
    padding: 20px;
  }
  .countdown-digits {
    font-family: 'JetBrains Mono', monospace;
    font-size: 3.1rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    color: var(--accent);
    margin: 6px 0;
  }
  .bar-track {
    width: 100%;
    height: 6px;
    background: var(--tint-3);
    border-radius: 99px;
    overflow: hidden;
    margin-top: 10px;
  }
  .bar-fill {
    height: 100%;
    width: 0%;
    background: var(--accent-fill);
    transition: width 0.4s ease;
  }

  .mini-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.75rem;
  }
  .mini-table th {
    text-align: left;
    color: var(--text-muted);
    font-weight: 600;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
  }
  .mini-table td {
    padding: 7px 8px;
    border-bottom: 1px solid var(--tint-2);
    font-family: 'JetBrains Mono', monospace;
  }

  .console-card {
    display: flex;
    flex-direction: column;
    padding: 11px 16px;
    background: var(--input-bg);
  }
  #console-output {
    flex: 1;
    overflow-y: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    line-height: 1.6;
    color: var(--text-secondary);
  }
  .log-entry { display: flex; gap: 10px; }
  .log-ts { color: var(--text-muted); flex-shrink: 0; }
  .log-msg.white { color: var(--text-primary); }
  .log-msg.error { color: var(--status-danger); }

  .spark {
    display: block;
    width: 100%;
    height: 46px;
    margin-top: 8px;
    cursor: crosshair;
  }
  .spark-meta {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.64rem;
    color: var(--text-muted);
    margin-top: 5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .btn-mini { padding: 2px 8px; font-size: 0.66rem; }
  .btn-mini:disabled { opacity: 0.4; cursor: default; }
  .tag {
    font-size: 0.6rem;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 4px;
    border: 1px solid var(--border-strong);
    color: var(--text-primary);
  }
  .dup-group {
    border: 1px solid var(--border);
    border-radius: calc(8px * var(--rs));
    padding: 9px 11px;
    margin-top: 8px;
    background: var(--tint-1);
  }
  .dup-head {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    font-size: 0.74rem;
    font-weight: 600;
    margin-bottom: 6px;
  }
  .dup-file {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    color: var(--text-secondary);
    padding: 3px 0;
  }
  .dup-file .path {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .btn-primary:disabled, .btn-secondary:disabled { opacity: 0.4; cursor: default; transform: none; }

  textarea {
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 8px 11px;
    border-radius: calc(6px * var(--rs));
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.74rem;
    line-height: 1.5;
    outline: none;
    resize: vertical;
    transition: border-color 0.15s ease;
  }
  textarea:focus { border-color: var(--accent); }
  input, textarea { user-select: text; }

  .stack { display: flex; flex-direction: column; gap: 6px; }
  .list-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 10px;
    border: 1px solid var(--border);
    border-radius: calc(7px * var(--rs));
    background: var(--tint-1);
    font-size: 0.76rem;
    transition: border-color 0.15s ease;
  }
  .list-row.clickable { cursor: pointer; }
  .list-row.clickable:hover { border-color: var(--border-strong); }
  .list-row .grow { flex: 1; min-width: 0; }
  .list-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.66rem;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .palette-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    backdrop-filter: blur(3px);
    display: none;
    align-items: flex-start;
    justify-content: center;
    padding-top: 12vh;
    z-index: 200;
  }
  .palette-backdrop.open { display: flex; }
  .palette {
    width: min(560px, 92vw);
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: calc(12px * var(--rs));
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.6);
    overflow: hidden;
  }
  .palette input[type="text"] {
    border: none;
    border-bottom: 1px solid var(--border);
    border-radius: 0;
    padding: 14px 16px;
    font-size: 0.9rem;
    background: transparent;
  }
  .palette-list { max-height: 50vh; overflow-y: auto; padding: 6px; }
  .palette-item {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 9px 12px;
    border-radius: calc(7px * var(--rs));
    font-size: 0.8rem;
    cursor: pointer;
    color: var(--text-secondary);
  }
  .palette-item.sel { background: var(--tint-3); color: var(--text-primary); }
  .palette-item .hint { font-family: 'JetBrains Mono', monospace; font-size: 0.66rem; color: var(--text-muted); }
  kbd {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    padding: 1px 5px;
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    color: var(--text-secondary);
  }

  .icon-btn { padding: 7px 9px; }
  .icon-btn svg { display: block; transition: transform 0.4s ease; }
  .icon-btn:hover svg { transform: rotate(60deg); }

  .swatch {
    width: 22px;
    height: 22px;
    border-radius: 50%;
    border: 2px solid transparent;
    box-shadow: inset 0 0 0 1px var(--tint-5);
    cursor: pointer;
    padding: 0;
    transition: transform 0.15s ease;
  }
  .swatch:hover { transform: scale(1.12); }
  .swatch.active { border-color: var(--text-primary); }
  input[type="color"] {
    width: 34px;
    height: 26px;
    border: 1px solid var(--border);
    border-radius: calc(6px * var(--rs));
    background: transparent;
    padding: 0 2px;
    cursor: pointer;
  }

  .cmd-output {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: calc(8px * var(--rs));
    padding: 10px 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    line-height: 1.55;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 320px;
    overflow-y: auto;
    user-select: text;
  }

  .size-row { display: flex; align-items: center; gap: 10px; }
  .size-main { flex: 1; min-width: 0; }
  .size-head { display: flex; justify-content: space-between; gap: 10px; font-size: 0.74rem; }
  .size-head .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .size-head .val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    color: var(--text-secondary);
    flex-shrink: 0;
  }
  .size-row .bar-track { height: 4px; margin-top: 5px; }

  .shortcut-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.74rem;
    color: var(--text-secondary);
    padding: 7px 0;
    border-bottom: 1px solid var(--border);
  }
  .shortcut-row:last-child { border-bottom: none; }

  /* ---------- Design-Optionen (Klassen setzt applyUi) ---------- */
  body.no-console .console-card { display: none; }
  body.no-console .content-col { grid-template-rows: 1fr; }
  body.no-glow .card::before { display: none; }
  body.no-anim *, body.no-anim *::before, body.no-anim *::after { transition: none !important; animation: none !important; }

  .seg {
    display: flex;
    border: 1px solid var(--border);
    border-radius: calc(7px * var(--rs));
    overflow: hidden;
    background: var(--input-bg);
  }
  .seg button {
    flex: 1;
    background: transparent;
    border: none;
    border-right: 1px solid var(--border);
    color: var(--text-secondary);
    font-family: var(--font-ui);
    font-size: 0.74rem;
    padding: 7px 6px;
    cursor: pointer;
    transition: background 0.15s ease, color 0.15s ease;
  }
  .seg button:last-child { border-right: none; }
  .seg button:hover { color: var(--text-primary); background: var(--tint-2); }
  .seg button.active { background: var(--accent-fill); color: var(--on-accent); font-weight: 600; }

  .theme-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-bottom: 14px; }
  .theme-tile {
    background: transparent;
    border: 1px solid var(--border);
    border-radius: calc(8px * var(--rs));
    padding: 6px;
    cursor: pointer;
    color: var(--text-secondary);
    font-family: var(--font-ui);
    font-size: 0.68rem;
    transition: border-color 0.15s ease, transform 0.15s ease;
  }
  .theme-tile:hover { transform: translateY(-1px); border-color: var(--border-strong); }
  .theme-tile.active { border-color: var(--accent); color: var(--text-primary); font-weight: 600; }
  .theme-preview {
    height: 42px;
    border-radius: calc(5px * var(--rs));
    margin-bottom: 5px;
    padding: 6px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .theme-preview i { display: block; height: 7px; border-radius: 2px; }

  .module-list { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 12px; }
  .module-list label {
    display: flex;
    align-items: center;
    gap: 7px;
    margin: 0;
    padding: 4px 0;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 0.74rem;
  }

  .drop-hint {
    border: 1px dashed var(--border-strong);
    border-radius: calc(8px * var(--rs));
    padding: 14px;
    text-align: center;
    color: var(--text-secondary);
    font-size: 0.76rem;
  }
  .conv-row { display: flex; align-items: center; gap: 8px; }
  .conv-row .grow { flex: 1; min-width: 0; }
  .conv-status { font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; flex-shrink: 0; min-width: 70px; text-align: right; }

  /* ---------- Ebenen: Hintergrund-Effekte liegen hinter Topbar und Inhalt ---------- */
  .topbar { position: relative; }
  .app-shell { position: relative; z-index: 1; }
  #bg-fx { position: fixed; inset: -10%; pointer-events: none; z-index: 0; opacity: 0; transition: opacity 0.6s ease; }
  #bg-fx.aurora {
    opacity: 1;
    background:
      radial-gradient(36% 44% at 18% 26%, color-mix(in srgb, var(--accent) 30%, transparent), transparent 70%),
      radial-gradient(30% 40% at 84% 16%, color-mix(in srgb, var(--accent-2) 26%, transparent), transparent 70%),
      radial-gradient(40% 50% at 60% 92%, color-mix(in srgb, var(--accent) 16%, transparent), transparent 70%);
    filter: blur(28px);
    animation: aurora calc(24s * var(--speed)) ease-in-out infinite alternate;
  }
  #bg-fx.noise {
    opacity: var(--noise-opacity);
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  }
  @keyframes aurora {
    0% { transform: translate(0, 0) scale(1); }
    50% { transform: translate(-3%, 2%) scale(1.08); }
    100% { transform: translate(2%, -3%) scale(1.03); }
  }

  /* ---------- Kartenstile ---------- */
  body.card-glass .card, body.card-glass .sidebar-footer {
    background: color-mix(in srgb, var(--surface) 55%, transparent);
    backdrop-filter: blur(18px) saturate(150%);
  }
  body.card-glass .metric-box, body.card-glass .tweak-row, body.card-glass .list-row {
    background: color-mix(in srgb, var(--surface-2) 40%, transparent);
  }
  body.card-glass .sidebar { background: color-mix(in srgb, var(--surface) 35%, transparent); backdrop-filter: blur(18px); }
  body.card-outline .card { background: transparent; border-color: var(--border-strong); }
  body.card-elevated .card { border-color: transparent; box-shadow: var(--shadow); }
  body.hover-lift .card:hover { transform: translateY(-3px); box-shadow: var(--shadow); }

  /* ---------- Form & Struktur ---------- */
  body.btn-pill .btn-primary, body.btn-pill .btn-secondary, body.btn-pill .btn-danger,
  body.btn-pill .seg, body.btn-pill .settings-tabs, body.btn-pill .settings-tabs button { border-radius: 999px; }
  .btn-primary:active, .btn-secondary:active, .btn-danger:active { transform: scale(0.97); }
  body.sidebar-right .app-shell { grid-template-columns: 1fr var(--sidebar-w); }
  body.sidebar-right .sidebar { order: 2; border-right: none; border-left: 1px solid var(--border); }
  body.labels-normal .section-label, body.labels-normal .nav-caption { text-transform: none; letter-spacing: 0.01em; font-size: 0.74rem; }
  body.no-mono .metric-val, body.no-mono .countdown-digits, body.no-mono .live-clock { font-family: var(--font-ui); }
  body.scroll-thin ::-webkit-scrollbar { width: 3px; height: 3px; }
  body.scroll-hidden ::-webkit-scrollbar { width: 0; height: 0; }

  /* ---------- Übergänge beim Ansichtswechsel ---------- */
  @keyframes enter-pop { from { opacity: 0; transform: translateY(14px) scale(0.985); } }
  @keyframes enter-slide { from { opacity: 0; transform: translateX(30px); } }
  @keyframes enter-zoom { from { opacity: 0; transform: scale(0.93); } }
  @keyframes enter-blur { from { opacity: 0; filter: blur(10px); } }
  .view-panel.entering .enter-item {
    animation: var(--enter) calc(0.5s * var(--speed)) cubic-bezier(0.2, 0.8, 0.2, 1) both;
    animation-delay: calc(var(--i, 0) * 55ms * var(--speed));
  }

  /* ---------- Moderne Dialoge statt Browser-confirm() ---------- */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    z-index: 300;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.45);
    backdrop-filter: blur(6px);
    opacity: 0;
    pointer-events: none;
    transition: opacity calc(0.2s * var(--speed)) ease;
  }
  .modal-backdrop.open { opacity: 1; pointer-events: auto; }
  .modal {
    width: min(420px, 90vw);
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: calc(14px * var(--rs));
    padding: 22px;
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.5);
    transform: translateY(12px) scale(0.95);
    transition: transform calc(0.35s * var(--speed)) cubic-bezier(0.34, 1.56, 0.64, 1);
  }
  .modal-backdrop.open .modal { transform: none; }
  .modal-icon {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    margin-bottom: 14px;
    background: var(--tint-3);
    color: var(--text-primary);
  }
  .modal.danger .modal-icon { background: rgba(239, 68, 68, 0.15); color: var(--danger-text); }
  .modal h3 { font-size: 1rem; font-weight: 700; margin-bottom: 6px; }
  .modal p { font-size: 0.8rem; color: var(--text-secondary); line-height: 1.55; margin-bottom: 20px; }
  .modal-actions { display: flex; gap: 8px; justify-content: flex-end; }
  .modal.danger .btn-primary { background: var(--status-danger); color: #ffffff; }

  /* ---------- Toasts ---------- */
  .toast-stack { position: fixed; z-index: 350; display: flex; flex-direction: column; gap: 8px; pointer-events: none; width: min(360px, 90vw); }
  .toast-stack.top-right { top: 66px; right: 18px; --toast-from: -14px; }
  .toast-stack.bottom-right { bottom: 18px; right: 18px; flex-direction: column-reverse; }
  .toast-stack.bottom-center { bottom: 18px; left: 50%; transform: translateX(-50%); flex-direction: column-reverse; }
  .toast {
    pointer-events: auto;
    display: flex;
    gap: 10px;
    align-items: flex-start;
    background: var(--surface-2);
    border: 1px solid var(--border-strong);
    border-radius: calc(10px * var(--rs));
    padding: 11px 13px 13px;
    box-shadow: 0 14px 36px rgba(0, 0, 0, 0.35);
    font-size: 0.78rem;
    line-height: 1.45;
    position: relative;
    overflow: hidden;
    cursor: pointer;
    animation: toast-in calc(0.4s * var(--speed)) cubic-bezier(0.34, 1.56, 0.64, 1) both;
  }
  .toast.leaving { animation: toast-out calc(0.25s * var(--speed)) ease forwards; }
  .toast-icon {
    width: 20px;
    height: 20px;
    border-radius: 50%;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.68rem;
    font-weight: 800;
  }
  .toast.ok .toast-icon { background: rgba(16, 185, 129, 0.18); color: var(--status-ok); }
  .toast.error .toast-icon { background: rgba(239, 68, 68, 0.18); color: var(--danger-text); }
  .toast.info .toast-icon { background: var(--tint-3); color: var(--text-primary); }
  .toast-bar { position: absolute; left: 0; bottom: 0; height: 2px; background: var(--accent-fill); animation: shrink linear forwards; }
  @keyframes toast-in { from { opacity: 0; transform: translateY(var(--toast-from, 14px)) scale(0.96); } }
  @keyframes toast-out { to { opacity: 0; transform: translateX(26px) scale(0.96); } }
  @keyframes shrink { from { width: 100%; } to { width: 0; } }
  @keyframes grow { from { width: 0; } to { width: 100%; } }

  /* ---------- Welcome-Screen ---------- */
  .welcome {
    position: fixed;
    inset: 0;
    z-index: 400;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg);
    overflow: hidden;
    cursor: pointer;
    transition: opacity calc(0.6s * var(--speed)) ease, transform calc(0.6s * var(--speed)) ease, filter calc(0.6s * var(--speed)) ease;
  }
  .welcome::before {
    content: '';
    position: absolute;
    width: 980px;
    height: 980px;
    border-radius: 50%;
    top: 50%;
    left: 50%;
    background: radial-gradient(circle, var(--accent-glow), transparent 62%);
    transform: translate(-50%, -64%);
    animation: welcome-glow calc(7s * var(--speed)) ease-in-out infinite alternate;
  }
  @keyframes welcome-glow { to { transform: translate(-48%, -58%) scale(1.08); } }
  .welcome.leaving { opacity: 0; transform: scale(1.03); filter: blur(8px); pointer-events: none; }
  .welcome-inner { position: relative; text-align: center; max-width: 680px; padding: 24px; }
  .w-item { opacity: 0; animation: w-in calc(0.85s * var(--speed)) cubic-bezier(0.2, 0.8, 0.2, 1) forwards; animation-delay: calc(var(--d, 0ms) * var(--speed)); }
  body.no-anim .w-item { opacity: 1; }
  .welcome.booting .w-item { animation-play-state: paused; }
  @keyframes w-in { from { opacity: 0; transform: translateY(18px); filter: blur(10px); } to { opacity: 1; transform: none; filter: none; } }
  .welcome-mark {
    width: 56px;
    height: 56px;
    margin: 0 auto 24px;
    border-radius: calc(15px * var(--rs));
    background: var(--accent-fill);
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 0 46px var(--accent-glow);
  }
  .welcome-mark::after { content: ''; width: 18px; height: 18px; border-radius: 4px; background: var(--bg); }
  .welcome-mark i {
    position: absolute;
    inset: -9px;
    border-radius: calc(19px * var(--rs));
    border: 1px solid var(--accent);
    animation: ring calc(2.4s * var(--speed)) ease-out infinite;
  }
  @keyframes ring { from { opacity: 0.6; transform: scale(0.9); } to { opacity: 0; transform: scale(1.45); } }
  .welcome-greet { font-size: 2.6rem; font-weight: 700; letter-spacing: -0.025em; line-height: 1.15; }
  .welcome-greet .name { background: var(--name-fill); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .welcome-sub { margin-top: 12px; font-size: 1.02rem; color: var(--text-secondary); }
  .welcome-sub b { color: var(--text-primary); font-family: 'JetBrains Mono', monospace; font-weight: 600; }
  .welcome-date { margin-top: 6px; font-size: 0.84rem; color: var(--text-muted); }
  .welcome-chips { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin-top: 28px; }
  .welcome-chip {
    border: 1px solid var(--border);
    background: var(--tint-1);
    border-radius: 999px;
    padding: 6px 13px;
    font-size: 0.74rem;
    color: var(--text-secondary);
  }
  .welcome-chip b { color: var(--text-primary); font-weight: 600; margin-left: 5px; }
  .welcome-progress { width: 170px; height: 2px; margin: 30px auto 0; background: var(--tint-3); border-radius: 2px; overflow: hidden; }
  .welcome-progress i { display: block; height: 100%; width: 0; background: var(--accent-fill); animation: grow linear forwards; }
  .welcome-hint { margin-top: 14px; font-size: 0.66rem; color: var(--text-muted); letter-spacing: 0.1em; text-transform: uppercase; }

  /* ---------- Einstellungen: Tabs & Vorschau ---------- */
  .settings-tabs {
    display: flex;
    gap: 4px;
    padding: 4px;
    border: 1px solid var(--border);
    border-radius: calc(10px * var(--rs));
    background: var(--surface);
    width: fit-content;
    flex-shrink: 0;
  }
  .settings-tabs button {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    padding: 7px 15px;
    border-radius: calc(7px * var(--rs));
    font-family: var(--font-ui);
    font-size: 0.78rem;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s ease, color 0.15s ease;
  }
  .settings-tabs button:hover { color: var(--text-primary); background: var(--tint-2); }
  .settings-tabs button.active { background: var(--accent-fill); color: var(--on-accent); font-weight: 600; }
  .preview-box { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 14px; border: 1px dashed var(--border-strong); border-radius: calc(8px * var(--rs)); }
</style>
</head>
<body>

<div id="bg-fx"></div>
<div class="progress-line" id="loader-bar"></div>

<div class="palette-backdrop" id="palette" onclick="if (event.target === this) closePalette()">
  <div class="palette">
    <input type="text" id="palette-input" placeholder="Workspace, Aktion oder Ansicht suchen ..." oninput="renderPalette()" onkeydown="onPaletteKey(event)" autocomplete="off">
    <div class="palette-list" id="palette-list"></div>
  </div>
</div>

<!-- Startet sichtbar, damit beim Laden nichts aufblitzt; showWelcome() füllt oder schließt ihn -->
<div class="welcome booting" id="welcome">
  <div class="welcome-inner">
    <div class="welcome-mark w-item" style="--d:0ms"><i></i></div>
    <div class="welcome-greet w-item" id="welcome-greet" style="--d:140ms">&nbsp;</div>
    <div class="welcome-sub w-item" id="welcome-sub" style="--d:280ms">&nbsp;</div>
    <div class="welcome-date w-item" id="welcome-date" style="--d:380ms">&nbsp;</div>
    <div class="welcome-chips" id="welcome-chips"></div>
    <div class="welcome-progress w-item" id="welcome-progress" style="--d:650ms"><i></i></div>
    <div class="welcome-hint w-item" style="--d:750ms">Klicken oder Enter zum Starten</div>
  </div>
</div>

<div class="modal-backdrop" id="modal">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-icon" id="modal-icon">?</div>
    <h3 id="modal-title"></h3>
    <p id="modal-text"></p>
    <div class="modal-actions">
      <button class="btn-secondary" id="modal-cancel">Abbrechen</button>
      <button class="btn-primary" id="modal-ok">OK</button>
    </div>
  </div>
</div>

<div class="toast-stack bottom-right" id="toast-stack"></div>

<header class="topbar">
  <div class="brand">
    <div class="brand-mark"></div>
    <span class="brand-name">MONOLITH // NEXUS OS</span>
    <span class="version-pill">v10.0 QUANTUM KERNEL</span>
  </div>
  <div class="topbar-right">
    <div class="status-indicator">
      <span class="dot"></span>
      <span id="state-text">ADMIN SESSION</span>
    </div>
    <div class="theme-dots" title="Live UI Theme">
      <div class="theme-dot" style="background:#ffffff" onclick="setTheme('#ffffff','rgba(255,255,255,0.14)')"></div>
      <div class="theme-dot" style="background:#3b82f6" onclick="setTheme('#3b82f6','rgba(59,130,246,0.22)')"></div>
      <div class="theme-dot" style="background:#a855f7" onclick="setTheme('#a855f7','rgba(168,85,247,0.22)')"></div>
      <div class="theme-dot" style="background:#10b981" onclick="setTheme('#10b981','rgba(16,185,129,0.22)')"></div>
      <div class="theme-dot" style="background:#f59e0b" onclick="setTheme('#f59e0b','rgba(245,158,11,0.22)')"></div>
      <div class="theme-dot" style="background:#ef4444" onclick="setTheme('#ef4444','rgba(239,68,68,0.22)')"></div>
    </div>
    <button class="btn-secondary" onclick="openPalette()" title="Alle Aktionen, Ansichten und Workspaces durchsuchen">Suche <kbd>Strg+K</kbd></button>
    <button class="btn-secondary" id="audio-toggle" onclick="toggleSound()">Sound: On</button>
    <button class="btn-secondary" onclick="refreshAll()">Refresh</button>
    <button class="btn-secondary icon-btn" onclick="goView('view-settings')" title="Einstellungen" aria-label="Einstellungen">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="3"></circle>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
      </svg>
    </button>
  </div>
</header>

<div class="app-shell">

  <aside class="sidebar">
    <div class="nav-group">
      <div class="nav-caption">System Modules</div>
      <button class="nav-btn active" onclick="switchView('view-dash', this)">
        <span>01 // Dashboard</span>
        <span class="nav-badge">LIVE</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-spoof', this)">
        <span>02 // Identity & Spoofer</span>
        <span class="nav-badge">NET/HW</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-files', this)">
        <span>03 // Smart File Sorter</span>
        <span class="nav-badge">AUTO</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-power', this)">
        <span>04 // Power & Ruhezustand</span>
        <span class="nav-badge" id="nav-power-badge">IDLE</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-clean', this)">
        <span>05 // Cleaner & Booster</span>
        <span class="nav-badge">RAM</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-tweaks', this)">
        <span>06 // Gaming & Tweaks</span>
        <span class="nav-badge">REG</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-netscan', this)">
        <span>07 // Port & Net-Scan</span>
        <span class="nav-badge">SEC</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-tools', this)">
        <span>08 // Quantum Toolkit</span>
        <span class="nav-badge">EXT</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-daily', this)">
        <span>09 // Alltag & Automatik</span>
        <span class="nav-badge">DAILY</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-cmds', this)">
        <span>10 // Custom Commands</span>
        <span class="nav-badge">CMD</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-auto', this)">
        <span>11 // Automationen</span>
        <span class="nav-badge" id="nav-auto-badge">FLOW</span>
      </button>
      <button class="nav-btn" onclick="switchView('view-convert', this)">
        <span>12 // File Converter</span>
        <span class="nav-badge">CONV</span>
      </button>
      <div class="nav-caption" style="margin-top:10px;">System</div>
      <button class="nav-btn" onclick="switchView('view-settings', this)">
        <span>Einstellungen</span>
        <span class="nav-badge">CFG</span>
      </button>
    </div>

    <div class="sidebar-footer">
      <div style="font-size:0.65rem; color:var(--text-muted); font-weight:600; letter-spacing:0.08em;">SYSTEM UHRZEIT</div>
      <div class="live-clock" id="sidebar-clock">00:00:00</div>
      <div style="font-size:0.7rem; color:var(--text-secondary); display:flex; justify-content:space-between;">
        <span>Uptime:</span>
        <span id="val-uptime" style="font-family:'JetBrains Mono',monospace;">—</span>
      </div>
    </div>
  </aside>

  <div class="content-col">

    <!-- VIEW 1: DASHBOARD -->
    <section class="view-panel active" id="view-dash">
      <div class="card" id="dash-hero" style="display:flex; align-items:center; justify-content:space-between; gap:20px;">
        <div>
          <h2 style="font-size:1.05rem; margin-bottom:4px;">NEXUS OS v10.0 Quantum Center</h2>
          <p style="font-size:0.78rem; color:var(--text-secondary);">Maximale Kontrolle über System-Identität, Netzwerk-Sockets, Dienste-Steuerung und Gaming-Performance.</p>
        </div>
        <div style="display:flex; gap:8px; flex-shrink:0;">
          <button class="btn-primary" onclick="oneClickSpoof()">Full Identity Rotation</button>
          <button class="btn-secondary" onclick="quickBoost()">1-Click RAM & Temp Boost</button>
        </div>
      </div>

      <div class="grid-4" id="dash-metrics">
        <div class="metric-box">
          <div class="metric-title"><span>RAM Auslastung</span><span>MEMORY</span></div>
          <div class="metric-val" id="dash-ram">—</div>
        </div>
        <div class="metric-box">
          <div class="metric-title"><span>System-Laufwerk (C:)</span><span>STORAGE</span></div>
          <div class="metric-val" id="dash-disk">—</div>
        </div>
        <div class="metric-box">
          <div class="metric-title"><span>Lokale IPv4</span><span>SUBNET</span></div>
          <div class="metric-val" id="dash-ip">—</div>
        </div>
        <div class="metric-box">
          <div class="metric-title"><span>Drive Serial (C:)</span><span>VOLUME</span></div>
          <div class="metric-val" id="dash-vol" style="font-size:0.85rem;">—</div>
        </div>
      </div>

      <div class="card" id="dash-monitor">
        <div class="section-label"><span>Live-Monitor · letzte 60 Sekunden</span><span>REALTIME</span></div>
        <div class="grid-4" id="mon-grid">
          <div class="metric-box">
            <div class="metric-title"><span>CPU-Last</span><span>CPU</span></div>
            <div class="metric-val" id="mon-cpu-val">—</div>
            <canvas class="spark" id="mon-cpu"></canvas>
            <div class="spark-meta" id="mon-cpu-meta">&nbsp;</div>
          </div>
          <div class="metric-box">
            <div class="metric-title"><span>Arbeitsspeicher</span><span>RAM</span></div>
            <div class="metric-val" id="mon-ram-val">—</div>
            <canvas class="spark" id="mon-ram"></canvas>
            <div class="spark-meta" id="mon-ram-meta">&nbsp;</div>
          </div>
          <div class="metric-box">
            <div class="metric-title"><span>Download</span><span>RX</span></div>
            <div class="metric-val" id="mon-down-val">—</div>
            <canvas class="spark" id="mon-down"></canvas>
            <div class="spark-meta" id="mon-down-meta">&nbsp;</div>
          </div>
          <div class="metric-box">
            <div class="metric-title"><span>Upload</span><span>TX</span></div>
            <div class="metric-val" id="mon-up-val">—</div>
            <canvas class="spark" id="mon-up"></canvas>
            <div class="spark-meta" id="mon-up-meta">&nbsp;</div>
          </div>
          <div class="metric-box" id="gpu-tile" style="display:none;">
            <div class="metric-title"><span>Grafikkarte</span><span id="gpu-name">GPU</span></div>
            <div class="metric-val" id="mon-gpu-val">—</div>
            <canvas class="spark" id="mon-gpu"></canvas>
            <div class="spark-meta" id="mon-gpu-meta">&nbsp;</div>
          </div>
        </div>
      </div>

      <div class="grid-2" id="dash-bottom">
        <div class="card">
          <div class="section-label"><span>Aktive Netzwerk- & Hardware-Signatur</span><span>TELEMETRY</span></div>
          <div style="display:flex; flex-direction:column; gap:8px;">
            <div class="metric-box">
              <div class="metric-title"><span>Aktive Adapter MAC</span><span id="dash-mac-badge">FACTORY</span></div>
              <div class="metric-val" id="dash-mac">—</div>
            </div>
            <div class="metric-box">
              <div class="metric-title"><span>Hostname</span><span>NETBIOS</span></div>
              <div class="metric-val" id="dash-host">—</div>
            </div>
            <div class="metric-box">
              <div class="metric-title"><span>MachineGuid</span><span>REG-UUID</span></div>
              <div class="metric-val" id="dash-mguid" style="font-size:0.8rem;">—</div>
            </div>
            <div class="metric-box">
              <div class="metric-title"><span>HwProfileGuid</span><span>HWID</span></div>
              <div class="metric-val" id="dash-hwguid" style="font-size:0.8rem;">—</div>
            </div>
          </div>
        </div>

        <div class="card" style="display:flex; flex-direction:column; justify-content:space-between;">
          <div>
            <div class="section-label"><span>Quick Actions & Performance</span><span>SHORTCUTS</span></div>
            <p style="font-size:0.76rem; color:var(--text-secondary); margin-bottom:12px;">Schnellausführung für Alltag & Optimierung:</p>
          </div>
          <div class="grid-2" style="gap:8px;">
            <button class="btn-secondary" onclick="quickSortDownloads()">Downloads sortieren</button>
            <button class="btn-secondary" onclick="toggleCaffeine()">Caffeine Mode: <span id="caff-status">AUS</span></button>
            <button class="btn-secondary" onclick="flushStack()">ARP / DNS Flush</button>
            <button class="btn-secondary" onclick="unlockUltimatePower()">Ultimative Leistung</button>
            <button class="btn-secondary" onclick="triggerBatteryReport()">Akku-Bericht</button>
            <button class="btn-secondary" onclick="applyHostsBlock()">Telemetrie Hosts Block</button>
          </div>
          <div id="dash-ws" style="display:flex; flex-wrap:wrap; gap:6px; margin-top:8px;"></div>
        </div>
      </div>
    </section>

    <!-- VIEW 2: SPOOFER -->
    <section class="view-panel" id="view-spoof">
      <div class="card">
        <div class="section-label"><span>Ziel-Netzwerkadapter auswählen</span><span>NIC INTERFACE</span></div>
        <div style="display:flex; gap:10px;">
          <select id="adapter-select" onchange="onAdapterSelect()" style="flex:1;"></select>
          <button class="btn-secondary" onclick="restoreHardwareMac()">Werkseinstellung</button>
          <button class="btn-primary" onclick="oneClickSpoof()">Identität rotieren</button>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Layer-2 MAC Address Spoofer</span><span>HEX OUI</span></div>
          <label>Hersteller-Signatur (Vendor OUI)</label>
          <select id="mac-vendor" style="margin-bottom:10px;">
            <option value="random">Unicast Random (02:XX:XX)</option>
            <option value="apple">Apple Inc. (02:1B:63)</option>
            <option value="intel">Intel Corp. (02:15:17)</option>
            <option value="samsung">Samsung Elec. (02:16:32)</option>
            <option value="realtek">Realtek Semi. (02:E0:4C)</option>
            <option value="asus">ASUSTek Computer (02:1A:92)</option>
          </select>
          <label>Eigene MAC-Adresse (Optional)</label>
          <input type="text" id="custom-mac" class="mono" placeholder="02:A1:B2:C3:D4:E5" maxlength="17" style="margin-bottom:12px;">
          <button class="btn-secondary" style="width:100%;" onclick="spoofMacOnly()">MAC-Adresse anwenden</button>
        </div>

        <div class="card">
          <div class="section-label"><span>Layer-3 Hostname & DHCP Tarnung</span><span>OPTION-12</span></div>
          <label>Geräte-Tarnprofil</label>
          <select id="host-profile" style="margin-bottom:10px;">
            <option value="desktop">Windows Desktop (DESKTOP-XXXX)</option>
            <option value="iphone">Apple iPhone (iPhone-XXX)</option>
            <option value="galaxy">Samsung Galaxy (Galaxy-S25-XXX)</option>
            <option value="macbook">MacBook Pro (MacBookPro-XXXX)</option>
            <option value="arch">Arch Linux (arch-xxxxx)</option>
            <option value="work">Enterprise Laptop (CORP-LT-XXX)</option>
          </select>
          <label>Wunsch-Hostname (Optional)</label>
          <input type="text" id="custom-host" class="mono" placeholder="z.B. iPad-Air" maxlength="15" style="margin-bottom:12px;">
          <button class="btn-secondary" style="width:100%;" onclick="spoofHostOnly()">Hostname ändern</button>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Deep System GUID Spoofer</span><span>KERNEL REG</span></div>
          <p style="font-size:0.74rem; color:var(--text-secondary); margin-bottom:12px;">Generiert neue UUIDs für MachineGuid & HwProfileGuid gegen Tracking.</p>
          <div style="display:flex; gap:8px;">
            <button class="btn-primary" style="flex:1;" onclick="spoofGuids(false)">System-GUIDs spoofen</button>
            <button class="btn-secondary" onclick="spoofGuids(true)">Original wiederherstellen</button>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span>Encrypted DNS & Netzwerk-Hygiene</span><span>RESOLVER</span></div>
          <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:6px; margin-bottom:10px;">
            <button class="btn-secondary" onclick="setDns('cloudflare')">Cloudflare</button>
            <button class="btn-secondary" onclick="setDns('google')">Google</button>
            <button class="btn-secondary" onclick="setDns('quad9')">Quad9</button>
            <button class="btn-secondary" onclick="setDns('mullvad')">Mullvad</button>
            <button class="btn-secondary" onclick="setDns('adguard')">AdGuard</button>
            <button class="btn-secondary" onclick="setDns('dhcp')">DHCP</button>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="btn-secondary" style="flex:1;" onclick="flushStack()">ARP / DNS Reset</button>
            <button class="btn-secondary" style="flex:1;" onclick="wipeHistory()">Profil-Historie löschen</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="section-label"><span>Original-Backup & Komplett-Reset</span><span>SAFETY NET</span></div>
        <div style="display:flex; gap:14px; align-items:center;">
          <div class="grid-3" style="flex:1;">
            <div class="metric-box">
              <div class="metric-title"><span>Gesichert am</span></div>
              <div class="metric-val" id="bk-date" style="font-size:0.85rem;">—</div>
            </div>
            <div class="metric-box">
              <div class="metric-title"><span>Original-Hostname</span></div>
              <div class="metric-val" id="bk-host" style="font-size:0.85rem;">—</div>
            </div>
            <div class="metric-box">
              <div class="metric-title"><span>Original-MachineGuid</span></div>
              <div class="metric-val" id="bk-mguid" style="font-size:0.7rem; word-break:break-all;">—</div>
            </div>
          </div>
          <button class="btn-primary" onclick="restoreIdentity()">Alles auf Original</button>
        </div>
        <p style="font-size:0.7rem; color:var(--text-muted); margin-top:10px;" id="bk-file">—</p>
      </div>
    </section>

    <!-- VIEW 3: SMART FILE SORTER -->
    <section class="view-panel" id="view-files">
      <div class="card">
        <div class="section-label"><span>Smart Folder Organizer</span><span>AUTOMATION</span></div>
        <p style="font-size:0.76rem; color:var(--text-secondary); margin-bottom:12px;">Sortiert Dateien automatisch in Kategorie-Ordner.</p>

        <div style="display:flex; gap:8px; margin-bottom:10px;">
          <button class="btn-secondary" onclick="setSortPath('downloads')">Downloads</button>
          <button class="btn-secondary" onclick="setSortPath('desktop')">Desktop</button>
          <button class="btn-secondary" onclick="setSortPath('documents')">Dokumente</button>
          <input type="text" id="sort-path" class="mono" value="downloads" placeholder="Pfad eingeben..." style="flex:1;">
        </div>

        <div style="display:flex; gap:8px;">
          <button class="btn-secondary" onclick="runSorter(true)">Vorschau-Scan</button>
          <button class="btn-primary" onclick="runSorter(false)">Jetzt sortieren</button>
          <button class="btn-secondary" onclick="undoSort()">Rückgängig</button>
          <button class="btn-secondary" onclick="cleanEmptyDirs()">Leere Ordner löschen</button>
        </div>

        <div id="sort-preview-box" style="margin-top:12px; display:none;" class="metric-box"></div>

        <div class="tweak-row" style="margin-top:12px;">
          <div class="tweak-info">
            <h4>Auto-Sortierung im Hintergrund</h4>
            <p id="autosort-info">—</p>
          </div>
          <label class="switch"><input type="checkbox" id="autosort-toggle" onchange="toggleAutosort(this)"><span class="slider"></span></label>
        </div>
      </div>

      <div class="card">
        <div class="section-label">
          <span>Large File Radar (Dateien ab 20 MB)</span>
          <button class="btn-secondary" style="padding:4px 10px; font-size:0.7rem;" onclick="scanLargeFiles()">Scannen</button>
        </div>
        <table class="mini-table">
          <thead><tr><th>Dateiname</th><th>Größe</th><th>Pfad</th><th></th></tr></thead>
          <tbody id="large-files-body">
            <tr><td colspan="4" style="color:var(--text-muted);">Klicke auf Scannen...</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="section-label">
          <span>Duplikat-Finder (gleicher Inhalt, ab 10 KB)</span>
          <button class="btn-secondary" style="padding:4px 10px; font-size:0.7rem;" onclick="scanDuplicates()">Duplikate suchen</button>
        </div>
        <p style="font-size:0.74rem; color:var(--text-secondary);">Vergleicht alle Dateien im gewählten Ordner inkl. Unterordnern per Hash. Die älteste Datei jeder Gruppe gilt als Original und bleibt geschützt, Kopien landen nur im Papierkorb.</p>
        <div id="dup-results"></div>
      </div>

      <div class="card">
        <div class="section-label">
          <span>Speicherfresser finden (Ordner aus dem Feld oben)</span>
          <button class="btn-secondary" style="padding:4px 10px; font-size:0.7rem;" onclick="scanFolderSizes()">Analysieren</button>
        </div>
        <div class="stack" id="size-results" style="gap:10px;">
          <div class="list-sub">Zeigt, welche Unterordner am meisten Platz belegen.</div>
        </div>
      </div>

      <div class="card">
        <div class="section-label"><span>Massen-Umbenennen (Ordner aus dem Feld oben)</span><span>RENAME</span></div>
        <div style="display:grid; grid-template-columns:2fr 1fr 1fr 1fr; gap:8px; margin-bottom:8px;">
          <div><label>Muster</label><input type="text" id="ren-pattern" class="mono" value="{name}" oninput="queueRenamePreview()"></div>
          <div><label>Nur Endung</label><input type="text" id="ren-ext" class="mono" placeholder="z.B. jpg" oninput="queueRenamePreview()"></div>
          <div><label>Sortieren nach</label><select id="ren-sort" onchange="queueRenamePreview()"><option value="name">Name</option><option value="date">Datum</option></select></div>
          <div><label>Start-Nr.</label><input type="number" id="ren-start" class="mono" value="1" min="0" oninput="queueRenamePreview()"></div>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:8px;">
          <div><label>Suchen (optional)</label><input type="text" id="ren-find" class="mono" oninput="queueRenamePreview()"></div>
          <div><label>Ersetzen durch</label><input type="text" id="ren-replace" class="mono" oninput="queueRenamePreview()"></div>
        </div>
        <div class="list-sub" style="margin-bottom:10px; white-space:normal;">Platzhalter: <b>{name}</b> alter Name · <b>{n}</b> fortlaufende Nummer · <b>{date}</b> Änderungsdatum. Die Dateiendung bleibt immer erhalten.</div>
        <div style="display:flex; gap:8px; margin-bottom:10px;">
          <button class="btn-secondary" onclick="previewRenames()">Vorschau</button>
          <button class="btn-primary" id="ren-apply" onclick="applyRenames()" disabled>Umbenennen</button>
          <button class="btn-secondary" onclick="undoRenames()">Rückgängig</button>
          <span class="list-sub" id="ren-summary" style="align-self:center;"></span>
        </div>
        <div style="max-height:220px; overflow-y:auto;">
          <table class="mini-table"><tbody id="ren-body"></tbody></table>
        </div>
      </div>
    </section>

    <!-- VIEW 4: POWER & RUHEZUSTAND -->
    <section class="view-panel" id="view-power">
      <div class="card power-hero">
        <div id="power-badge" style="font-size:0.75rem; font-weight:600; color:var(--text-secondary);">● BEREIT – KEIN TIMER AKTIV</div>
        <div class="countdown-digits" id="power-countdown">00:00:00</div>
        <div id="power-target-info" style="font-size:0.75rem; color:var(--text-muted);">Countdown oder Uhrzeit wählen</div>
        <div class="bar-track"><div class="bar-fill" id="power-progress"></div></div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Countdown-Timer</span><span>TIMER MODE</span></div>
          <div class="grid-3" style="margin-bottom:10px;">
            <div><label>Stunden</label><input type="number" id="p-hrs" class="mono" value="0" min="0"></div>
            <div><label>Minuten</label><input type="number" id="p-mins" class="mono" value="30" min="0"></div>
            <div><label>Sekunden</label><input type="number" id="p-secs" class="mono" value="0" min="0"></div>
          </div>
          <div style="display:grid; grid-template-columns:repeat(5,1fr); gap:6px; margin-bottom:12px;">
            <button class="btn-secondary" onclick="setPowerPreset(0,15)">15m</button>
            <button class="btn-secondary" onclick="setPowerPreset(0,30)">30m</button>
            <button class="btn-secondary" onclick="setPowerPreset(1,0)">1h</button>
            <button class="btn-secondary" onclick="setPowerPreset(2,0)">2h</button>
            <button class="btn-secondary" onclick="setPowerPreset(4,0)">4h</button>
          </div>
          <button class="btn-primary" style="width:100%;" onclick="startPowerTimer('countdown')">▶ Timer starten</button>
        </div>

        <div class="card">
          <div class="section-label"><span>Aktions-Einstellungen</span><span>SCHEDULE</span></div>
          <div class="grid-2" style="margin-bottom:10px;">
            <div>
              <label>Aktion bei Ablauf</label>
              <select id="p-action">
                <option value="Herunterfahren">Herunterfahren</option>
                <option value="Ruhezustand (Hibernate)">Ruhezustand</option>
                <option value="Energie sparen (Sleep)">Energie sparen</option>
                <option value="Neustarten">Neustarten</option>
                <option value="Sperren (Lock)">Sperren</option>
                <option value="Abmelden">Abmelden</option>
                <option value="UEFI / BIOS Reboot">UEFI Reboot</option>
              </select>
            </div>
            <div>
              <label>Feste Uhrzeit (HH:MM)</label>
              <div style="display:flex; gap:6px;">
                <input type="text" id="p-clock-time" class="mono" value="23:30" placeholder="23:30">
                <button class="btn-secondary" onclick="startPowerTimer('clock')">Setzen</button>
              </div>
            </div>
          </div>

          <div style="display:flex; gap:14px; margin-bottom:12px;">
            <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
              <input type="checkbox" id="p-force"> Apps erzwingen (/f)
            </label>
            <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
              <input type="checkbox" id="p-test"> Test-Modus
            </label>
          </div>

          <div style="display:flex; gap:8px;">
            <button class="btn-danger" style="flex:1;" onclick="cancelPowerTimer()">✖ Timer abbrechen</button>
            <button class="btn-secondary" onclick="unlockUltimatePower()">⚡ Ultimate Power</button>
          </div>
        </div>
      </div>
    </section>

    <!-- VIEW 5: CLEANER & BOOSTER -->
    <section class="view-panel" id="view-clean">
      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Deep System Junk Cleaner</span><span>STORAGE WIPE</span></div>
          <div style="display:flex; flex-direction:column; gap:8px; margin-bottom:14px;">
            <label style="display:flex; align-items:center; gap:8px;"><input type="checkbox" class="clean-cb" value="user_temp" checked> Benutzer Temp (%TEMP%)</label>
            <label style="display:flex; align-items:center; gap:8px;"><input type="checkbox" class="clean-cb" value="win_temp" checked> Windows System Temp</label>
            <label style="display:flex; align-items:center; gap:8px;"><input type="checkbox" class="clean-cb" value="prefetch" checked> Windows Prefetch Cache</label>
            <label style="display:flex; align-items:center; gap:8px;"><input type="checkbox" class="clean-cb" value="thumbcache" checked> Thumbnail-Cache</label>
            <label style="display:flex; align-items:center; gap:8px;"><input type="checkbox" class="clean-cb" value="recycle_bin"> Papierkorb leeren</label>
          </div>
          <button class="btn-primary" style="width:100%;" onclick="runCleaner()">Bereinigung ausführen</button>
        </div>

        <div class="card" style="display:flex; flex-direction:column; justify-content:space-between;">
          <div>
            <div class="section-label"><span>RAM Working-Set & Memory Trim</span><span>KERNEL TRIM</span></div>
            <p style="font-size:0.76rem; color:var(--text-secondary); margin-bottom:14px;">Gibt ungenutzten RAM sofort frei.</p>
            <div class="metric-box" style="margin-bottom:12px;">
              <div class="metric-title"><span>RAM-Status</span><span>PHYSICAL</span></div>
              <div class="metric-val" id="clean-ram-readout">—</div>
            </div>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="btn-primary" style="flex:1;" onclick="boostRam()">Working-Set leeren</button>
            <button class="btn-secondary" style="flex:1;" onclick="flushStandbyRam()">Standby-Cache trimmen</button>
          </div>
        </div>
      </div>
    </section>

    <!-- VIEW 6: GAMING & TWEAKS -->
    <section class="view-panel" id="view-tweaks">
      <div class="card">
        <div class="section-label"><span>Gaming-, Ping- & Service-Tweaks</span><span>LIVE REGISTRY</span></div>
        <div class="grid-2">
          <div class="tweak-row">
            <div class="tweak-info"><h4>Klassisches Kontextmenü (Win 11)</h4><p>Deaktiviert das langsame Win11 Menü</p></div>
            <label class="switch"><input type="checkbox" id="tw-classic_context" onchange="toggleTweak('classic_context', this.checked)"><span class="slider"></span></label>
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>Nagle's Algorithm ausschalten</h4><p>TCP-Pakete sofort senden (Low Ping)</p></div>
            <label class="switch"><input type="checkbox" id="tw-nagle_algorithm" onchange="toggleTweak('nagle_algorithm', this.checked)"><span class="slider"></span></label>
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>Network Throttling Index aus</h4><p>Hebt Windows-Netzwerkdrosselung auf</p></div>
            <label class="switch"><input type="checkbox" id="tw-net_throttling" onchange="toggleTweak('net_throttling', this.checked)"><span class="slider"></span></label>
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>SysMain Dienst deaktivieren</h4><p>Verhindert HDD/SSD-Hintergrundauslastung</p></div>
            <label class="switch"><input type="checkbox" id="tw-disable_sysmain" onchange="toggleTweak('disable_sysmain', this.checked)"><span class="slider"></span></label>
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>Windows Search Indexer aus</h4><p>Spart CPU & I/O Leistung</p></div>
            <label class="switch"><input type="checkbox" id="tw-disable_search_indexer" onchange="toggleTweak('disable_search_indexer', this.checked)"><span class="slider"></span></label>
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>Bing-Websuche im Startmenü aus</h4><p>Macht die Suche rein lokal</p></div>
            <label class="switch"><input type="checkbox" id="tw-disable_bing" onchange="toggleTweak('disable_bing', this.checked)"><span class="slider"></span></label>
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>Dateiendungen anzeigen</h4><p>Zeigt .exe, .py, .dll im Explorer</p></div>
            <label class="switch"><input type="checkbox" id="tw-show_extensions" onchange="toggleTweak('show_extensions', this.checked)"><span class="slider"></span></label>
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>GameDVR Hintergrundaufnahme aus</h4><p>Verhindert FPS-Drops in Games</p></div>
            <label class="switch"><input type="checkbox" id="tw-disable_gamedvr" onchange="toggleTweak('disable_gamedvr', this.checked)"><span class="slider"></span></label>
          </div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="section-label">
            <span>Prozess Priority Manager & Task Killer</span>
            <button class="btn-secondary" style="padding:3px 8px; font-size:0.68rem;" onclick="loadProcesses()">Aktualisieren</button>
          </div>
          <div style="max-height:175px; overflow-y:auto;">
            <table class="mini-table">
              <thead><tr><th>Prozess</th><th>PID</th><th>RAM</th><th>Aktion</th></tr></thead>
              <tbody id="proc-body"></tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <div class="section-label">
            <span>Windows Autostart (Registry)</span>
            <button class="btn-secondary" style="padding:3px 8px; font-size:0.68rem;" onclick="loadStartup()">Aktualisieren</button>
          </div>
          <div style="max-height:175px; overflow-y:auto;">
            <table class="mini-table">
              <thead><tr><th>Name</th><th>Scope</th><th>Pfad</th><th>Aktiv</th></tr></thead>
              <tbody id="startup-body"></tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- VIEW 7: PORT & NET SCAN -->
    <section class="view-panel" id="view-netscan">
      <div class="card">
        <div class="section-label">
          <span>Speedtest · speed.cloudflare.com</span>
          <button class="btn-primary btn-mini" id="speed-btn" onclick="startSpeedtest()">Test starten</button>
        </div>
        <div class="grid-4">
          <div class="metric-box"><div class="metric-title"><span>Ping</span><span>LATENZ</span></div><div class="metric-val" id="speed-ping">—</div></div>
          <div class="metric-box"><div class="metric-title"><span>Jitter</span><span>SCHWANKUNG</span></div><div class="metric-val" id="speed-jitter">—</div></div>
          <div class="metric-box"><div class="metric-title"><span>Download</span><span>↓</span></div><div class="metric-val" id="speed-down">—</div></div>
          <div class="metric-box"><div class="metric-title"><span>Upload</span><span>↑</span></div><div class="metric-val" id="speed-up">—</div></div>
        </div>
        <div class="list-sub" id="speed-status" style="margin-top:10px;">Dauert etwa 20 Sekunden und verbraucht je nach Leitung einige hundert MB.</div>
      </div>

      <div class="card">
        <div class="section-label">
          <span>Ping-Monitor · live</span>
          <div style="display:flex; gap:6px; align-items:center;">
            <input type="text" id="ping-host" class="mono" placeholder="Eigenes Ziel, z.B. Spielserver-IP" style="width:220px; padding:4px 8px; font-size:0.7rem;">
            <button class="btn-secondary btn-mini" onclick="setPingHost()">Setzen</button>
          </div>
        </div>
        <div class="grid-3">
          <div class="metric-box">
            <div class="metric-title"><span id="ping0-label">Router</span><span id="ping0-host" class="mono">—</span></div>
            <div class="metric-val" id="mon-ping0-val">—</div>
            <canvas class="spark" id="mon-ping0"></canvas>
            <div class="spark-meta" id="mon-ping0-meta">&nbsp;</div>
          </div>
          <div class="metric-box">
            <div class="metric-title"><span id="ping1-label">Internet</span><span id="ping1-host" class="mono">—</span></div>
            <div class="metric-val" id="mon-ping1-val">—</div>
            <canvas class="spark" id="mon-ping1"></canvas>
            <div class="spark-meta" id="mon-ping1-meta">&nbsp;</div>
          </div>
          <div class="metric-box">
            <div class="metric-title"><span id="ping2-label">Eigenes Ziel</span><span id="ping2-host" class="mono">—</span></div>
            <div class="metric-val" id="mon-ping2-val">—</div>
            <canvas class="spark" id="mon-ping2"></canvas>
            <div class="spark-meta" id="mon-ping2-meta">&nbsp;</div>
          </div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="section-label">
            <span>Aktive Listening Sockets (Open Ports Local)</span>
            <button class="btn-secondary" style="padding:3px 8px; font-size:0.68rem;" onclick="loadConnections()">Neu laden</button>
          </div>
          <div style="max-height:260px; overflow-y:auto;">
            <table class="mini-table">
              <thead><tr><th>Local IP</th><th>Port</th><th>PID</th></tr></thead>
              <tbody id="net-conns-body">
                <tr><td colspan="3" style="color:var(--text-muted);">Klicke auf Neu laden...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span>Port Scanner & DNS Benchmark</span><span>SECURITY</span></div>
          <label>Ziel-IP / Hostname</label>
          <input type="text" id="scan-target" class="mono" value="127.0.0.1" style="margin-bottom:8px;">
          <div style="display:flex; gap:8px; margin-bottom:12px;">
            <button class="btn-primary" style="flex:1;" onclick="runPortScan()">Port Scan starten</button>
            <button class="btn-secondary" style="flex:1;" onclick="runDnsBenchmark()">DNS Latency Test</button>
          </div>
          <div class="metric-box">
            <div class="metric-title"><span>Ergebnis / Benchmark</span><span>ANALYTICS</span></div>
            <div class="metric-val" id="scan-results-text" style="font-size:0.8rem; font-weight:500;">Bereit für Analyse</div>
          </div>
        </div>
      </div>
    </section>

    <!-- VIEW 8: QUANTUM TOOLKIT -->
    <section class="view-panel" id="view-tools">
      <div class="card">
        <div class="section-label"><span>Windows Quantum Tool Hub (Shortcuts)</span><span>SYS TOOLS</span></div>
        <div class="grid-3">
          <button class="btn-secondary" onclick="openSysTool('godmode')">God Mode Ordner erstellen</button>
          <button class="btn-secondary" onclick="openSysTool('devmgmt')">Gerätemanager öffnen</button>
          <button class="btn-secondary" onclick="openSysTool('ncpa')">Netzwerkverbindungen</button>
          <button class="btn-secondary" onclick="openSysTool('diskmgmt')">Datenträgerverwaltung</button>
          <button class="btn-secondary" onclick="openSysTool('services')">Dienste-Verwaltung</button>
          <button class="btn-secondary" onclick="openSysTool('regedit')">Registry Editor</button>
        </div>
      </div>

      <div class="card">
        <div class="section-label">
          <span>App-Updates (winget)</span>
          <div style="display:flex; gap:6px;">
            <button class="btn-secondary btn-mini" onclick="checkAppUpdates()">Nach Updates suchen</button>
            <button class="btn-primary btn-mini" id="upd-all" onclick="startAppUpdate(null)" disabled>Alle aktualisieren</button>
          </div>
        </div>
        <div id="upd-status" class="metric-box" style="display:none; margin-bottom:10px; font-size:0.74rem;"></div>
        <div style="max-height:300px; overflow-y:auto;">
          <table class="mini-table">
            <thead><tr><th>App</th><th>Installiert</th><th>Neu</th><th></th></tr></thead>
            <tbody id="upd-body">
              <tr><td colspan="4" style="color:var(--text-muted);">Klicke auf „Nach Updates suchen“ ...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="section-label">
          <span>Systeminfo</span>
          <button class="btn-secondary btn-mini" onclick="copySystemInfo()">Als Text kopieren</button>
        </div>
        <table class="mini-table">
          <tbody id="sysinfo-body"><tr><td style="color:var(--text-muted);">Wird geladen ...</td></tr></tbody>
        </table>
      </div>

      <div class="card">
        <div class="section-label">
          <span>Festplatten-Gesundheit</span>
          <button class="btn-secondary btn-mini" onclick="loadDiskHealth()">Prüfen</button>
        </div>
        <table class="mini-table">
          <thead><tr><th>Laufwerk</th><th>Typ</th><th>Zustand</th><th>Temperatur</th><th>Verschleiß</th><th>Betriebsstunden</th></tr></thead>
          <tbody id="disk-body"><tr><td colspan="6" style="color:var(--text-muted);">Wird geladen ...</td></tr></tbody>
        </table>
      </div>
    </section>

    <!-- VIEW 9: ALLTAG & AUTOMATIK -->
    <section class="view-panel" id="view-daily">
      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Workspaces · alles mit einem Klick öffnen</span><span>LAUNCHER</span></div>
          <div class="stack" id="ws-list"></div>
          <div style="margin-top:12px; border-top:1px solid var(--border); padding-top:12px;">
            <label>Name</label>
            <input type="text" id="ws-name" placeholder="z.B. Gaming, Arbeit, Uni" maxlength="40" style="margin-bottom:8px;">
            <label>Einträge, eine Zeile pro Programm (.exe/.lnk), Ordner oder Webseite</label>
            <textarea id="ws-items" rows="4" placeholder="C:\Program Files (x86)\Steam\steam.exe&#10;%USERPROFILE%\Documents&#10;https://web.whatsapp.com&#10;ms-settings:display"></textarea>
            <div style="display:flex; gap:8px; margin-top:8px;">
              <button class="btn-primary" style="flex:1;" id="ws-save" onclick="saveWorkspace()">Workspace speichern</button>
              <button class="btn-secondary" onclick="resetWorkspaceForm()">Neu</button>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span>Erinnerungen</span><span>POPUP</span></div>
          <input type="text" id="rem-text" placeholder="Woran soll ich dich erinnern?" maxlength="200" style="margin-bottom:8px;">
          <div style="display:grid; grid-template-columns:repeat(5,1fr); gap:6px; margin-bottom:8px;">
            <button class="btn-secondary" onclick="addReminder({ minutes: 5 })">5 min</button>
            <button class="btn-secondary" onclick="addReminder({ minutes: 15 })">15 min</button>
            <button class="btn-secondary" onclick="addReminder({ minutes: 30 })">30 min</button>
            <button class="btn-secondary" onclick="addReminder({ minutes: 60 })">1 h</button>
            <button class="btn-secondary" onclick="addReminder({ minutes: 120 })">2 h</button>
          </div>
          <div style="display:flex; gap:8px; align-items:center; margin-bottom:12px;">
            <input type="text" id="rem-time" class="mono" placeholder="HH:MM" maxlength="5" style="width:90px;">
            <label style="display:flex; align-items:center; gap:6px; margin:0; cursor:pointer;">
              <input type="checkbox" id="rem-daily"> täglich
            </label>
            <button class="btn-secondary" style="margin-left:auto;" onclick="addReminder({ mode: 'at' })">Um diese Uhrzeit</button>
          </div>
          <div class="stack" id="rem-list"></div>
          <p style="font-size:0.66rem; color:var(--text-muted); margin-top:10px;">Erscheint als Windows-Popup im Vordergrund, solange NEXUS läuft. Verpasste Erinnerungen kommen beim nächsten Start.</p>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Schnellnotizen</span><span id="notes-state">GESPEICHERT</span></div>
          <textarea id="notes" rows="10" oninput="onNotesInput()" placeholder="Einkaufsliste, Ideen, Telefonnummern ... wird automatisch gespeichert."></textarea>
        </div>

        <div class="card">
          <div class="section-label"><span>Text-Bausteine · Klick kopiert</span><span>CLIPBOARD</span></div>
          <div class="stack" id="snip-list" style="margin-bottom:10px;"></div>
          <input type="text" id="snip-label" placeholder="Bezeichnung, z.B. Lieferadresse" maxlength="40" style="margin-bottom:6px;">
          <textarea id="snip-text" rows="2" placeholder="Text, der beim Klick in die Zwischenablage kommt" maxlength="5000" style="margin-bottom:6px;"></textarea>
          <button class="btn-secondary" style="width:100%;" onclick="addSnippet()">Baustein hinzufügen</button>
          <p style="font-size:0.66rem; color:var(--text-muted); margin-top:8px;">Notizen und Bausteine liegen als Klartext in %APPDATA%\NexusOS. Bitte keine Passwörter speichern.</p>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Fokus-Timer</span><span id="focus-phase">BEREIT</span></div>
          <div class="countdown-digits" id="focus-clock" style="text-align:center; font-size:2.6rem;">25:00</div>
          <div class="bar-track" style="margin:4px 0 12px;"><div class="bar-fill" id="focus-bar"></div></div>
          <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:6px; margin-bottom:8px;">
            <button class="btn-secondary" onclick="startFocus(25, 'Fokus')">25 min Fokus</button>
            <button class="btn-secondary" onclick="startFocus(50, 'Fokus')">50 min Fokus</button>
            <button class="btn-secondary" onclick="startFocus(5, 'Pause')">5 min Pause</button>
          </div>
          <button class="btn-danger" style="width:100%;" onclick="stopFocus()">Stoppen</button>
          <p style="font-size:0.66rem; color:var(--text-muted); margin-top:8px;">Am Ende kommt ein Windows-Popup, auch wenn NEXUS im Hintergrund ist.</p>
        </div>

        <div class="card">
          <div class="section-label"><span>Schnellordner</span><span>EXPLORER</span></div>
          <div class="grid-3" style="gap:6px;">
            <button class="btn-secondary" onclick="openPlace('downloads')">Downloads</button>
            <button class="btn-secondary" onclick="openPlace('documents')">Dokumente</button>
            <button class="btn-secondary" onclick="openPlace('desktop')">Desktop</button>
            <button class="btn-secondary" onclick="openPlace('pictures')">Bilder</button>
            <button class="btn-secondary" onclick="openPlace('appdata')">AppData</button>
            <button class="btn-secondary" onclick="openPlace('localappdata')">LocalAppData</button>
            <button class="btn-secondary" onclick="openPlace('temp')">Temp</button>
            <button class="btn-secondary" onclick="openPlace('startup')">Autostart-Ordner</button>
            <button class="btn-secondary" onclick="openPlace('hosts')">hosts-Datei</button>
          </div>
          <p style="font-size:0.66rem; color:var(--text-muted); margin-top:10px;">Die hosts-Datei öffnet sich im Editor mit Admin-Rechten, damit du sie speichern kannst.</p>
        </div>
      </div>
    </section>

    <!-- VIEW 10: CUSTOM COMMANDS -->
    <section class="view-panel" id="view-cmds">
      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Deine Befehle</span><span id="cmd-count">0</span></div>
          <div class="stack" id="cmd-list"></div>
          <div style="margin-top:14px; border-top:1px solid var(--border); padding-top:12px;">
            <div class="list-sub" style="margin-bottom:8px;">Vorlagen mit einem Klick übernehmen:</div>
            <div style="display:flex; flex-wrap:wrap; gap:6px;" id="cmd-presets"></div>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span id="cmd-form-title">Neuer Befehl</span><span>EDITOR</span></div>
          <div style="display:grid; grid-template-columns:1fr 140px; gap:8px; margin-bottom:8px;">
            <div><label>Name</label><input type="text" id="cmd-name" maxlength="40" placeholder="z.B. Netzwerk-Check"></div>
            <div><label>Shell</label><select id="cmd-shell"><option value="cmd">CMD</option><option value="powershell">PowerShell</option></select></div>
          </div>
          <label>Befehl (mehrere Zeilen = mehrere Befehle nacheinander)</label>
          <textarea id="cmd-command" rows="6" maxlength="2000" placeholder="ipconfig /all"></textarea>
          <div style="display:flex; gap:8px; margin-top:8px;">
            <button class="btn-primary" style="flex:1;" id="cmd-save" onclick="saveCommand()">Befehl speichern</button>
            <button class="btn-secondary" onclick="resetCommandForm()">Neu</button>
          </div>
          <p style="font-size:0.68rem; color:var(--status-warn); margin-top:10px;">⚠ Befehle laufen mit Admin-Rechten. Trag nur ein, was du verstehst, und kopier nichts ungeprüft aus dem Internet.</p>
        </div>
      </div>

      <div class="card">
        <div class="section-label">
          <span>Ausgabe <span id="cmd-out-title" style="text-transform:none; letter-spacing:0; color:var(--text-secondary);"></span></span>
          <span id="cmd-out-state">—</span>
        </div>
        <pre class="cmd-output" id="cmd-output">Führ einen Befehl mit ▶ aus, dann steht hier die Ausgabe. „Fenster“ öffnet ihn stattdessen in einer eigenen Konsole.</pre>
      </div>
    </section>

    <!-- VIEW 11: AUTOMATIONEN -->
    <section class="view-panel" id="view-auto">
      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Deine Automationen</span><span id="auto-count">0</span></div>
          <div class="stack" id="auto-list"></div>
          <div style="margin-top:14px; border-top:1px solid var(--border); padding-top:12px;">
            <div class="list-sub" style="margin-bottom:8px;">Ideen – Klick füllt den Editor:</div>
            <div style="display:flex; flex-wrap:wrap; gap:6px;" id="auto-presets"></div>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span id="auto-form-title">Neue Automation</span><span>WENN → DANN</span></div>
          <label>Name</label>
          <input type="text" id="auto-name" maxlength="40" placeholder="z.B. Gaming-Modus" style="margin-bottom:10px;">
          <label>Wenn …</label>
          <select id="auto-trigger" onchange="renderAutoFields('trigger')" style="margin-bottom:8px;">
            <option value="process_start">ein Programm startet</option>
            <option value="process_stop">ein Programm beendet wird</option>
            <option value="daily">es eine bestimmte Uhrzeit ist</option>
            <option value="interval">regelmäßig, alle X Minuten</option>
            <option value="startup">NEXUS startet</option>
          </select>
          <div id="auto-trigger-fields" style="margin-bottom:10px;"></div>
          <label>… dann</label>
          <select id="auto-action" onchange="renderAutoFields('action')" style="margin-bottom:8px;">
            <option value="power_plan">Energieplan wechseln</option>
            <option value="caffeine_on">Caffeine an (kein Standby)</option>
            <option value="caffeine_off">Caffeine aus</option>
            <option value="workspace">Workspace öffnen</option>
            <option value="command">Custom Command ausführen</option>
            <option value="popup">Popup-Nachricht zeigen</option>
            <option value="sort_downloads">Downloads sortieren</option>
            <option value="clean_temp">Temp-Ordner bereinigen</option>
          </select>
          <div id="auto-action-fields" style="margin-bottom:10px;"></div>
          <div style="display:flex; gap:8px;">
            <button class="btn-primary" style="flex:1;" id="auto-save" onclick="saveAutomation()">Automation speichern</button>
            <button class="btn-secondary" onclick="resetAutomationForm()">Neu</button>
          </div>
          <datalist id="proc-names"></datalist>
        </div>
      </div>

      <div class="card">
        <div class="section-label"><span>Verlauf</span><span>LETZTE 40</span></div>
        <div class="stack" id="auto-log"></div>
        <p style="font-size:0.66rem; color:var(--text-muted); margin-top:10px;">Automationen laufen, solange NEXUS geöffnet ist. Mit „Mit Windows starten“ in den Einstellungen laufen sie ab dem Login.</p>
      </div>
    </section>

    <!-- VIEW 12: FILE CONVERTER -->
    <section class="view-panel" id="view-convert">
      <div class="grid-2">
        <div class="card">
          <div class="section-label"><span>Dateien</span><span id="conv-count">0 DATEIEN</span></div>
          <div style="display:flex; gap:8px; margin-bottom:10px;">
            <button class="btn-primary" style="flex:1;" onclick="pickConvertFiles()">Dateien auswählen …</button>
            <button class="btn-secondary" onclick="setConvertFiles([])">Liste leeren</button>
          </div>
          <div class="stack" id="conv-files" style="max-height:280px; overflow-y:auto;"></div>
          <details style="margin-top:10px;">
            <summary class="list-sub" style="cursor:pointer;">Pfade einfügen statt auswählen</summary>
            <textarea id="conv-paste" rows="3" style="margin-top:6px;" placeholder="Ein Pfad pro Zeile – im Explorer: Datei markieren, Strg+Shift+C (Als Pfad kopieren)"></textarea>
            <button class="btn-secondary btn-mini" style="margin-top:6px;" onclick="addPastedPaths()">Hinzufügen</button>
          </details>
        </div>

        <div class="card">
          <div class="section-label"><span>Ziel</span><span>FORMAT</span></div>
          <label>Umwandeln in</label>
          <select id="conv-format" onchange="renderConvertOptions()">
            <optgroup label="Bilder">
              <option value="png">PNG – verlustfrei, mit Transparenz</option>
              <option value="jpg">JPG – klein, ideal für Fotos</option>
              <option value="pdf">PDF – alle Bilder in eine Datei</option>
              <option value="ico">ICO – Windows-Icon (256 px)</option>
              <option value="gif">GIF – aus Bild oder Video</option>
              <option value="bmp">BMP</option>
              <option value="tiff">TIFF</option>
            </optgroup>
            <optgroup label="Video (ffmpeg)">
              <option value="mp4_discord">MP4 für Discord (unter 10 MB)</option>
              <option value="mp4">MP4 (H.264)</option>
            </optgroup>
            <optgroup label="Audio (ffmpeg)">
              <option value="mp3">MP3</option>
              <option value="m4a">M4A (AAC)</option>
              <option value="wav">WAV</option>
              <option value="flac">FLAC</option>
              <option value="ogg">OGG</option>
            </optgroup>
            <optgroup label="Daten">
              <option value="csv">CSV für Excel (aus JSON)</option>
              <option value="json">JSON (aus CSV)</option>
            </optgroup>
          </select>
          <div id="conv-options" style="margin-top:10px;"></div>
          <label style="margin-top:10px;">Speichern in</label>
          <div style="display:flex; gap:6px;">
            <input type="text" id="conv-outdir" class="mono" placeholder="Neben der Originaldatei" readonly style="flex:1;">
            <button class="btn-secondary" onclick="pickOutDir()">Ordner …</button>
            <button class="btn-secondary" title="Zurück zu: neben der Originaldatei" onclick="document.getElementById('conv-outdir').value = ''">×</button>
          </div>
          <div class="tweak-row" style="margin-top:12px;">
            <div class="tweak-info"><h4>ffmpeg für Audio & Video</h4><p id="ffmpeg-info">wird geprüft …</p></div>
            <button class="btn-secondary btn-mini" id="ffmpeg-btn" style="display:none;" onclick="installFfmpeg()">Installieren</button>
          </div>
          <button class="btn-primary" id="conv-start" style="width:100%; margin-top:12px;" onclick="startConversion()">Konvertieren</button>
        </div>
      </div>

      <div class="card">
        <div class="section-label"><span>Fortschritt</span><span id="conv-state">BEREIT</span></div>
        <div class="bar-track" style="margin:0 0 12px;"><div class="bar-fill" id="conv-bar"></div></div>
        <div class="stack" id="conv-results"><div class="list-sub">Noch nichts konvertiert. Originale werden nie überschrieben.</div></div>
      </div>
    </section>

    <!-- EINSTELLUNGEN -->
    <section class="view-panel" id="view-settings">
      <div class="settings-tabs" id="settings-tabs">
        <button data-tab="look" class="active">Aussehen</button>
        <button data-tab="layout">Layout</button>
        <button data-tab="motion">Bewegung</button>
        <button data-tab="start">Start & Hinweise</button>
        <button data-tab="general">Allgemein</button>
      </div>

      <!-- Tab: Aussehen -->
      <div class="grid-2" data-stab="look">
        <div class="card">
          <div class="section-label"><span>Theme & Farbe</span><span>LOOK</span></div>
          <label>Theme</label>
          <div class="theme-grid" id="set-themes"></div>
          <label>Akzentfarbe</label>
          <div style="display:flex; align-items:center; gap:9px; margin-bottom:14px;">
            <div id="set-swatches" style="display:flex; gap:9px;"></div>
            <input type="color" id="set-accent" title="Eigene Farbe" onchange="saveSetting({ accent: this.value })">
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>Farbverlauf-Akzent</h4><p>Buttons, Balken und Schalter laufen in eine zweite Farbe über</p></div>
            <div style="display:flex; align-items:center; gap:10px;">
              <input type="color" id="set-accent2" title="Zweite Farbe" onchange="saveSetting({ accent2: this.value })">
              <label class="switch"><input type="checkbox" data-toggle="accent_gradient"><span class="slider"></span></label>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span>Oberfläche</span><span>SURFACE</span></div>
          <div class="stack" style="gap:10px;">
            <div><label>Kartenstil</label><div class="seg" data-key="card_style"></div></div>
            <div><label>Hintergrund</label><div class="seg" data-key="pattern"></div></div>
            <div><label>Kontrast</label><div class="seg" data-key="contrast"></div></div>
            <div class="tweak-row">
              <div class="tweak-info"><h4>Glow & Maus-Licht</h4><p>Leuchtender Verlauf oben und Lichtkegel über den Karten</p></div>
              <label class="switch"><input type="checkbox" data-toggle="glow"><span class="slider"></span></label>
            </div>
          </div>
          <div class="list-sub" style="white-space:normal; margin-top:10px;">Tipp: „Glas“ wirkt am besten mit dem Aurora-Hintergrund und Farbverlauf-Akzent.</div>
        </div>
      </div>

      <!-- Tab: Layout -->
      <div class="grid-2" data-stab="layout">
        <div class="card">
          <div class="section-label"><span>Schrift & Form</span><span>TYPO</span></div>
          <div class="stack" style="gap:10px;">
            <div><label>Schriftart</label><div class="seg" data-key="font"></div></div>
            <div><label>Schriftgröße</label><div class="seg" data-key="font_size"></div></div>
            <div class="grid-2" style="gap:10px;">
              <div><label>Ecken</label><div class="seg" data-key="radius"></div></div>
              <div><label>Buttons</label><div class="seg" data-key="button_shape"></div></div>
            </div>
            <div class="grid-2" style="gap:10px;">
              <div><label>Abstände</label><div class="seg" data-key="density"></div></div>
              <div><label>Überschriften</label><div class="seg" data-key="label_case"></div></div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span>Struktur</span><span>LAYOUT</span></div>
          <div class="stack" style="gap:10px;">
            <div class="grid-2" style="gap:10px;">
              <div><label>Seitenleiste</label><div class="seg" data-key="sidebar_side"></div></div>
              <div><label>Breite</label><div class="seg" data-key="sidebar_width"></div></div>
            </div>
            <div><label>Scrollbalken</label><div class="seg" data-key="scrollbar"></div></div>
            <div class="tweak-row">
              <div class="tweak-info"><h4>Zahlen in Monospace</h4><p>Werte wie „64 %“ in Terminal-Schrift statt Fließtext-Schrift</p></div>
              <label class="switch"><input type="checkbox" data-toggle="mono_values"><span class="slider"></span></label>
            </div>
            <div class="tweak-row">
              <div class="tweak-info"><h4>Kernel-Log unten anzeigen</h4><p>Aus = mehr Platz für die Ansichten</p></div>
              <label class="switch"><input type="checkbox" data-toggle="show_console"><span class="slider"></span></label>
            </div>
            <div class="tweak-row">
              <div class="tweak-info"><h4>Nummern in der Seitenleiste</h4><p>„01 //“ vor den Modulnamen</p></div>
              <label class="switch"><input type="checkbox" data-toggle="nav_numbers"><span class="slider"></span></label>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab: Bewegung -->
      <div class="grid-2" data-stab="motion">
        <div class="card">
          <div class="section-label"><span>Animationen</span><span>MOTION</span></div>
          <div class="stack" style="gap:10px;">
            <div class="tweak-row">
              <div class="tweak-info"><h4>Animationen</h4><p>Aus = alles erscheint sofort, ohne Bewegung</p></div>
              <label class="switch"><input type="checkbox" data-toggle="animations"><span class="slider"></span></label>
            </div>
            <div><label>Seitenübergang</label><div class="seg" data-key="transition"></div></div>
            <div><label>Tempo</label><div class="seg" data-key="motion_speed"></div></div>
            <div class="tweak-row">
              <div class="tweak-info"><h4>Karten heben sich an</h4><p>Leichter Schwebe-Effekt beim Drüberfahren mit der Maus</p></div>
              <label class="switch"><input type="checkbox" data-toggle="hover_lift"><span class="slider"></span></label>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span>Live-Vorschau</span><span>PREVIEW</span></div>
          <div class="preview-box" style="margin-bottom:12px;">
            <button class="btn-primary">Primär</button>
            <button class="btn-secondary">Sekundär</button>
            <label class="switch"><input type="checkbox" checked><span class="slider"></span></label>
            <div class="bar-track" style="flex:1; min-width:110px; margin:0;"><div class="bar-fill" style="width:62%;"></div></div>
          </div>
          <div class="grid-2" style="gap:8px;">
            <button class="btn-secondary" onclick="animateView(document.getElementById('view-settings'))">Übergang abspielen</button>
            <button class="btn-secondary" onclick="previewDialog()">Dialog testen</button>
            <button class="btn-secondary" onclick="toast('So sieht eine Benachrichtigung aus.', 'ok', true)">Toast testen</button>
            <button class="btn-secondary" onclick="showWelcome()">Welcome-Screen zeigen</button>
          </div>
        </div>
      </div>

      <!-- Tab: Start & Hinweise -->
      <div class="grid-2" data-stab="start">
        <div class="card">
          <div class="section-label"><span>Welcome-Screen</span><span>START</span></div>
          <div class="stack" style="gap:10px;">
            <div class="tweak-row">
              <div class="tweak-info"><h4>Begrüßung beim Start</h4><p>Begrüßt dich je nach Tageszeit mit deinem Namen und dem PC-Namen</p></div>
              <label class="switch"><input type="checkbox" data-toggle="welcome"><span class="slider"></span></label>
            </div>
            <div><label>Stil</label><div class="seg" data-key="welcome_style"></div></div>
            <div><label>Anzeigedauer</label><div class="seg" data-key="welcome_duration"></div></div>
            <div><label>Name in der Begrüßung</label><input type="text" id="set-welcome-name" maxlength="32" placeholder="leer = Name des Windows-Kontos" onchange="saveSetting({ welcome_name: this.value })"></div>
            <button class="btn-secondary" onclick="showWelcome()">Vorschau anzeigen</button>
          </div>
        </div>

        <div class="card">
          <div class="section-label"><span>Benachrichtigungen & Uhr</span><span>NOTIFY</span></div>
          <div class="stack" style="gap:10px;">
            <div><label>Toast-Benachrichtigungen</label><div class="seg" data-key="toasts"></div></div>
            <div><label>Position</label><div class="seg" data-key="toast_pos"></div></div>
            <div><label>Anzeigedauer</label><div class="seg" data-key="toast_duration"></div></div>
            <button class="btn-secondary" onclick="toast('So sieht eine Benachrichtigung aus.', 'ok', true)">Test-Benachrichtigung</button>
            <div class="grid-2" style="gap:10px; align-items:end;">
              <div><label>Uhr in der Seitenleiste</label><div class="seg" data-key="clock_format"></div></div>
              <div class="tweak-row" style="padding:6px 10px;">
                <div class="tweak-info"><h4>Sekunden</h4></div>
                <label class="switch"><input type="checkbox" data-toggle="clock_seconds"><span class="slider"></span></label>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab: Allgemein -->
      <div class="grid-2" data-stab="general">
        <div class="card">
          <div class="section-label"><span>Module & Dashboard</span><span>NAV</span></div>
          <div class="list-sub" style="white-space:normal; margin-bottom:10px;">Abgehakte Module werden angezeigt. Ausgeblendete verschwinden auch aus der Strg+K-Suche und lassen sich hier jederzeit zurückholen.</div>
          <div class="module-list" id="set-modules"></div>
          <label style="margin-top:12px;">Dashboard zeigt</label>
          <div class="module-list" id="set-dash-sections"></div>
        </div>

        <div class="card">
          <div class="section-label"><span>Personalisieren & Teilen</span><span>SHARE</span></div>
          <div class="grid-2" style="gap:8px; margin-bottom:12px;">
            <div><label>App-Name oben links</label><input type="text" id="set-brand" maxlength="32" onchange="saveSetting({ brand_name: this.value })"></div>
            <div><label>Untertitel</label><input type="text" id="set-brand-tag" maxlength="24" onchange="saveSetting({ brand_tag: this.value })"></div>
          </div>
          <label>Dein Design-Code</label>
          <div style="display:flex; gap:6px; margin-bottom:6px;">
            <input type="text" id="design-code" class="mono" readonly style="flex:1; font-size:0.68rem;" onclick="this.select()">
            <button class="btn-primary" onclick="copyDesignCode()">Kopieren</button>
          </div>
          <div class="list-sub" style="white-space:normal; margin-bottom:12px;">Schick den Code deinen Freunden: Sie fügen ihn unten ein und haben sofort deinen Look. Name, Module und deine Daten werden nicht mitgeschickt.</div>
          <label>Design-Code eines Freundes</label>
          <div style="display:flex; gap:6px; margin-bottom:12px;">
            <input type="text" id="design-code-in" class="mono" placeholder="NEXUS-…" style="flex:1; font-size:0.68rem;">
            <button class="btn-secondary" onclick="applyDesignCode()">Übernehmen</button>
          </div>
          <button class="btn-danger" style="width:100%;" onclick="resetDesign()">Design auf Standard zurücksetzen</button>
        </div>
      </div>

      <div class="grid-2" data-stab="general">
        <div class="card">
          <div class="section-label"><span>Verhalten</span><span>RUNTIME</span></div>
          <label>Startansicht beim Öffnen</label>
          <select id="set-start" onchange="saveSetting({ start_view: this.value })" style="margin-bottom:12px;"></select>
          <div class="tweak-row" style="margin-bottom:12px;">
            <div class="tweak-info"><h4>Klick-Sounds</h4><p>Kurzes Audio-Feedback bei Aktionen</p></div>
            <label class="switch"><input type="checkbox" id="set-sound" onchange="saveSetting({ sound: this.checked })"><span class="slider"></span></label>
          </div>
          <div class="grid-2" style="gap:8px; margin-bottom:14px;">
            <div>
              <label>Live-Monitor alle</label>
              <select id="set-monitor" onchange="saveSetting({ monitor_interval: +this.value })">
                <option value="1">1 Sekunde</option><option value="2">2 Sekunden</option><option value="5">5 Sekunden</option>
              </select>
            </div>
            <div>
              <label>Status-Daten alle</label>
              <select id="set-refresh" onchange="saveSetting({ refresh_interval: +this.value })">
                <option value="3">3 Sekunden</option><option value="5">5 Sekunden</option><option value="10">10 Sekunden</option><option value="30">30 Sekunden</option>
              </select>
            </div>
          </div>
          <div class="tweak-row">
            <div class="tweak-info"><h4>Mit Windows starten</h4><p id="set-autostart-info">Öffnet NEXUS beim Anmelden automatisch, ohne UAC-Abfrage. Gut für Erinnerungen und Auto-Sortierung.</p></div>
            <label class="switch"><input type="checkbox" id="set-autostart" onchange="toggleAutostart(this)"><span class="slider"></span></label>
          </div>
        </div>
      </div>

      <div class="grid-2" data-stab="general">
        <div class="card">
          <div class="section-label"><span>Deine Daten</span><span>BACKUP</span></div>
          <p style="font-size:0.74rem; color:var(--text-secondary); margin-bottom:10px;">Workspaces, Erinnerungen, Notizen, Bausteine, Befehle und Einstellungen sichern oder auf einen anderen PC mitnehmen.</p>
          <div class="grid-3" style="gap:8px;">
            <button class="btn-secondary" onclick="exportUserData()">Exportieren</button>
            <button class="btn-secondary" onclick="document.getElementById('import-file').click()">Importieren</button>
            <button class="btn-secondary" onclick="openDataFolder()">Ordner öffnen</button>
          </div>
          <input type="file" id="import-file" accept=".json,application/json" style="display:none;" onchange="importUserData(this)">
          <div class="list-sub" style="margin-top:10px;" id="set-data-path">—</div>
        </div>

        <div class="card">
          <div class="section-label"><span>Tastenkürzel & Info</span><span>v10.0</span></div>
          <div class="shortcut-row"><span>Befehlssuche öffnen</span><kbd>Strg+K</kbd></div>
          <div class="shortcut-row"><span>Suche: Auswahl bewegen / ausführen</span><span><kbd>↑</kbd> <kbd>↓</kbd> <kbd>Enter</kbd></span></div>
          <div class="shortcut-row"><span>Suche schließen</span><kbd>Esc</kbd></div>
          <div class="shortcut-row"><span>Kernel-Log leeren</span><button class="btn-secondary btn-mini" onclick="document.getElementById('console-output').innerHTML = ''">Leeren</button></div>
        </div>
      </div>
    </section>

    <!-- KERNEL LOG CONSOLE -->
    <div class="card console-card">
      <div class="section-label" style="margin-bottom:4px;">
        <span>MONOLITH // NEXUS Quantum Kernel Stream</span>
        <span id="console-status">READY</span>
      </div>
      <div id="console-output"></div>
    </div>

  </div>
</div>

<script>
// Wird beim Ausliefern vom Server ersetzt; ohne diesen Token lehnt die API jeden Request ab
const NEXUS_TOKEN = "__NEXUS_TOKEN__";

const TactileAudio = {
  ctx: null,
  enabled: true,
  init() {
    if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    if (this.ctx.state === 'suspended') this.ctx.resume();
  },
  click(freq = 160) {
    if (!this.enabled) return;
    this.init();
    const now = this.ctx.currentTime;
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(freq, now);
    osc.frequency.exponentialRampToValueAtTime(42, now + 0.035);
    gain.gain.setValueAtTime(0.08, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.04);
    osc.connect(gain);
    gain.connect(this.ctx.destination);
    osc.start(now);
    osc.stop(now + 0.045);
  },
  done() {
    if (!this.enabled) return;
    this.init();
    [320, 480].forEach((f, i) => {
      const now = this.ctx.currentTime + i * 0.07;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(f, now);
      gain.gain.setValueAtTime(0.05, now);
      gain.gain.exponentialRampToValueAtTime(0.0005, now + 0.18);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(now);
      osc.stop(now + 0.2);
    });
  }
};

function toggleSound() {
  saveSetting({ sound: !TactileAudio.enabled });
}

function setTheme(accent) {
  applyAccent(accent);
  saveSetting({ accent });
}

document.addEventListener('mousemove', (e) => {
  document.querySelectorAll('.card').forEach(card => {
    const rect = card.getBoundingClientRect();
    card.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`);
    card.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`);
  });
});

function switchView(viewId, btn) {
  document.querySelectorAll('.view-panel').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(viewId).classList.add('active');
  btn.classList.add('active');
  animateView(document.getElementById(viewId));
  TactileAudio.click(180);
  if (viewId === 'view-dash') {
    pollMonitor();
  } else if (viewId === 'view-daily' || viewId === 'view-files') {
    refreshDaily();
  } else if (viewId === 'view-tools') {
    pollAppUpdate();
    if (!sysInfoRows) loadSystemInfo();
    if (!diskLoaded) loadDiskHealth();
  } else if (viewId === 'view-auto') {
    loadAutomations();
    loadProcessNames();
  } else if (viewId === 'view-convert') {
    loadConvertInfo();
    pollConvert();
  } else if (viewId === 'view-settings') {
    loadAutostart();
  } else if (viewId === 'view-tweaks') {
    loadTweaks();
    loadProcesses();
    loadStartup();
  } else if (viewId === 'view-netscan') {
    loadConnections();
    document.getElementById('ping-host').value = settings.ping_host || '';
    pollPing();
    pollSpeedtest().catch(() => {});
  }
}

// Alles, was von Dateinamen, Prozessen oder der Registry kommt, vor innerHTML escapen.
// Ein Download namens <img onerror=…> würde sonst JS mit Zugriff auf die Admin-API ausführen.
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function log(msg, highlight = false) {
  const out = document.getElementById('console-output');
  const row = document.createElement('div');
  row.className = 'log-entry';
  const ts = document.createElement('span');
  ts.className = 'log-ts';
  ts.textContent = new Date().toLocaleTimeString('de-DE');
  const text = document.createElement('span');
  text.className = `log-msg ${highlight === 'error' ? 'error' : highlight ? 'white' : ''}`;
  text.textContent = msg;
  row.append(ts, text);
  out.appendChild(row);
  out.scrollTop = out.scrollHeight;
  if (highlight === 'error') toast(msg, 'error');
  else if (highlight === true) toast(msg, 'ok');
}

// Aktionen ohne eigenes try/catch: Fehler sichtbar loggen und den Ladebalken nicht hängen lassen
window.addEventListener('unhandledrejection', (e) => {
  setLoading(false);
  log(`Fehler: ${e.reason && e.reason.message ? e.reason.message : e.reason}`, 'error');
});

function setLoading(active, label = "ADMIN SESSION") {
  const bar = document.getElementById('loader-bar');
  document.getElementById('state-text').innerText = label;
  if (active) bar.classList.add('active');
  else bar.classList.remove('active');
}

async function api(path, body = {}) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Nexus-Token': NEXUS_TOKEN },
    body: JSON.stringify(body)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status} (${path})`);
  return data;
}

function formatMac(mac) {
  if (!mac || mac.length !== 12) return mac;
  return mac.match(/.{1,2}/g).join(':');
}

let adapters = [];

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.innerText = (value === undefined || value === null) ? '—' : value;
}

let refreshInFlight = false;

async function refreshAll() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const data = await api('/api/status');
    renderStatus(data);
  } catch (e) {
    log(`Status-Refresh fehlgeschlagen: ${e.message || e}`);
  } finally {
    refreshInFlight = false;
  }
}

function renderStatus(data) {
  adapters = data.adapters || [];
  const sel = document.getElementById('adapter-select');
  const signature = adapters.map(a => `${a.id}|${a.name}`).join(';');
  if (sel.dataset.signature !== signature) {
    const prev = sel.value;
    sel.innerHTML = '';
    adapters.forEach((a, idx) => {
      const opt = document.createElement('option');
      opt.value = idx;
      opt.innerText = a.name;
      sel.appendChild(opt);
    });
    if (prev && adapters[prev]) sel.value = prev;
    sel.dataset.signature = signature;
  }

  const active = adapters[sel.value || 0] || { mac: 'N/A', name: 'No Adapter' };
  const mem = data.memory || {};
  const disk = data.disk || {};
  const guids = data.guids || {};
  setText('dash-mac', formatMac(active.mac));
  setText('dash-mac-badge', active.mac === 'HARDWARE' ? 'FACTORY' : 'SPOOFED');
  setText('dash-host', data.hostname);
  setText('dash-ip', `${data.ip} (GW: ${data.gateway})`);
  setText('dash-ram', `${mem.percent}% (${mem.used_gb}/${mem.total_gb} GB)`);
  setText('clean-ram-readout', `${mem.percent}% (${mem.used_gb} GB belegt)`);
  setText('dash-disk', `${disk.free_gb} GB frei (${disk.percent}% belegt)`);
  setText('dash-vol', data.volume_serial);
  setText('val-uptime', data.uptime);
  setText('dash-mguid', guids.machine_guid);
  setText('dash-hwguid', guids.hw_guid);
  setText('caff-status', data.caffeine ? 'AKTIV' : 'AUS');

  const bk = data.backup || {};
  setText('bk-date', bk.captured_at);
  setText('bk-host', bk.hostname);
  setText('bk-mguid', bk.machine_guid);
  setText('bk-file', bk.file ? `Gespeichert in ${bk.file}. Wird beim ersten Start angelegt und danach nie überschrieben.` : '—');
}

// ---------------- Live-Monitor ----------------
const MONITOR_POINTS = 60;
let monitorData = { cpu: [], ram: [], down: [], up: [], gpu: [] };
let pingData = {};  // ping0..ping2 -> Laufzeiten in ms, null = keine Antwort
const sparkHoverAge = {};  // Sekunden zurück unter dem Mauszeiger, je Graph

function fmtRate(kb) {
  return kb >= 1024 ? `${(kb / 1024).toFixed(1)} MB/s` : `${kb.toFixed(kb < 10 ? 1 : 0)} KB/s`;
}

const numbers = d => d.filter(v => v != null);
const fmtMs = v => v == null ? 'Timeout' : `${v} ms`;
const pingSpark = { fmt: fmtMs, max: d => Math.max(20, ...numbers(d)) * 1.2 };

const SPARKS = {
  cpu:   { fmt: v => `${Math.round(v)} %`, max: () => 100 },
  ram:   { fmt: v => `${Math.round(v)} %`, max: () => 100 },
  // Untergrenze 64 KB/s, damit Leerlauf-Rauschen nicht wie ein Ausschlag aussieht
  down:  { fmt: fmtRate, max: d => Math.max(64, ...numbers(d)) * 1.15 },
  up:    { fmt: fmtRate, max: d => Math.max(64, ...numbers(d)) * 1.15 },
  gpu:   { fmt: v => v == null ? '—' : `${Math.round(v)} %`, max: () => 100 },
  ping0: pingSpark,
  ping1: pingSpark,
  ping2: pingSpark,
};

function sparkData(key) {
  return (key.startsWith('ping') ? pingData[key] : monitorData[key]) || [];
}

function sparkMeta(key, data, spec) {
  const vals = numbers(data);
  if (key.startsWith('ping')) {
    if (!vals.length) return data.length ? 'keine Antwort – Ziel blockiert Ping oder VPN sperrt das LAN' : 'misst …';
    const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
    const jitter = vals.length > 1 ? vals.slice(1).reduce((s, v, i) => s + Math.abs(v - vals[i]), 0) / (vals.length - 1) : 0;
    const loss = Math.round((1 - vals.length / data.length) * 100);
    return `Ø ${Math.round(avg)} ms · Jitter ${jitter.toFixed(1)} ms · Verlust ${loss} %`;
  }
  if (key === 'gpu') {
    const g = monitorData.gpu_info || {};
    if (g.temp == null) return 'wartet auf nvidia-smi …';
    const power = g.power != null ? ` · ${Math.round(g.power)} W` : '';
    return `${Math.round(g.temp)} °C · ${(g.mem_used / 1024).toFixed(1)}/${Math.round(g.mem_total / 1024)} GB VRAM${power}`;
  }
  if (!vals.length) return '';
  if (key === 'down' || key === 'up') return `Spitze ${spec.fmt(Math.max(...vals))} · 60 s`;
  return `Ø ${spec.fmt(vals.reduce((a, b) => a + b, 0) / vals.length)} · 60 s`;
}

function sparkGeometry(canvas, count) {
  const w = canvas.clientWidth;
  const step = w / (MONITOR_POINTS - 1);
  return { w, h: canvas.clientHeight, step, x0: w - (count - 1) * step };  // neuester Wert am rechten Rand
}

function renderSpark(key) {
  const canvas = document.getElementById(`mon-${key}`);
  if (!canvas) return;
  const data = sparkData(key);
  const spec = SPARKS[key];
  const { w, h, step, x0 } = sparkGeometry(canvas, data.length);
  if (!w || !h) return;  // Ansicht gerade nicht sichtbar

  const dpr = window.devicePixelRatio || 1;
  if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const css = getComputedStyle(document.documentElement);
  const accent = css.getPropertyValue('--accent').trim();
  ctx.fillStyle = css.getPropertyValue('--border').trim();
  ctx.fillRect(0, h - 1, w, 1);  // Basislinie

  const current = data[data.length - 1];
  setText(`mon-${key}-val`, current === undefined ? '—' : spec.fmt(current));
  if (!numbers(data).length) {
    setText(`mon-${key}-meta`, sparkMeta(key, data, spec));
    return;
  }

  const max = spec.max(data);
  const y = v => (h - 1) - (Math.min(v, max) / max) * (h - 4);
  // null (keine Messung / keine Antwort) trennt den Graphen in Abschnitte
  const segments = [];
  let seg = [];
  data.forEach((v, i) => {
    if (v == null) {
      if (seg.length) segments.push(seg);
      seg = [];
    } else {
      seg.push([x0 + i * step, y(v)]);
    }
  });
  if (seg.length) segments.push(seg);

  segments.forEach(s => {
    if (s.length === 1) {
      ctx.beginPath();
      ctx.arc(s[0][0], s[0][1], 1.5, 0, Math.PI * 2);
      ctx.fillStyle = accent;
      ctx.fill();
      return;
    }
    ctx.beginPath();
    s.forEach(([px, py], i) => i ? ctx.lineTo(px, py) : ctx.moveTo(px, py));
    ctx.lineTo(s[s.length - 1][0], h - 1);
    ctx.lineTo(s[0][0], h - 1);
    ctx.closePath();
    ctx.globalAlpha = 0.12;
    ctx.fillStyle = accent;
    ctx.fill();
    ctx.globalAlpha = 1;

    ctx.beginPath();
    s.forEach(([px, py], i) => i ? ctx.lineTo(px, py) : ctx.moveTo(px, py));
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.strokeStyle = accent;
    ctx.stroke();
  });

  const age = sparkHoverAge[key];
  const hi = age === undefined ? -1 : data.length - 1 - age;
  if (hi >= 0 && hi < data.length) {
    const hx = x0 + hi * step;
    ctx.fillStyle = css.getPropertyValue('--text-muted').trim();
    ctx.fillRect(Math.round(hx), 0, 1, h);
    if (data[hi] != null) {
      ctx.beginPath();
      ctx.arc(hx, y(data[hi]), 4, 0, Math.PI * 2);
      ctx.fillStyle = accent;
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.strokeStyle = css.getPropertyValue('--surface').trim();
      ctx.stroke();
    }
    setText(`mon-${key}-meta`, age === 0 ? `jetzt · ${spec.fmt(data[hi])}` : `vor ${age} s · ${spec.fmt(data[hi])}`);
  } else {
    setText(`mon-${key}-meta`, sparkMeta(key, data, spec));
  }
}

function renderSparks() {
  Object.keys(SPARKS).forEach(renderSpark);
}

function initSparks() {
  Object.keys(SPARKS).forEach(key => {
    const canvas = document.getElementById(`mon-${key}`);
    canvas.addEventListener('mousemove', (e) => {
      const data = sparkData(key);
      const { step, x0 } = sparkGeometry(canvas, data.length);
      const i = Math.round((e.clientX - canvas.getBoundingClientRect().left - x0) / step);
      if (i >= 0 && i < data.length) sparkHoverAge[key] = data.length - 1 - i;
      else delete sparkHoverAge[key];
      renderSpark(key);
    });
    canvas.addEventListener('mouseleave', () => {
      delete sparkHoverAge[key];
      renderSpark(key);
    });
  });
  window.addEventListener('resize', renderSparks);
}

let monitorInFlight = false;
let lastMonitorPoll = 0;

async function pollMonitor() {
  if (monitorInFlight || !document.getElementById('view-dash').classList.contains('active')) return;
  // Der Server misst immer jede Sekunde; die Einstellung bestimmt nur, wie oft die Graphen neu zeichnen
  if (Date.now() - lastMonitorPoll < settings.monitor_interval * 1000 - 150) return;
  lastMonitorPoll = Date.now();
  monitorInFlight = true;
  try {
    monitorData = await api('/api/monitor');
    const gpu = monitorData.gpu_info || {};
    document.getElementById('gpu-tile').style.display = gpu.available ? '' : 'none';
    document.getElementById('mon-grid').style.gridTemplateColumns = gpu.available ? 'repeat(5, 1fr)' : '';
    if (gpu.name) setText('gpu-name', gpu.name.replace(/^NVIDIA (GeForce )?/, ''));
    renderSparks();
  } catch (e) {
    // nächster Tick versucht es erneut
  } finally {
    monitorInFlight = false;
  }
}

let pingInFlight = false;

async function pollPing() {
  if (pingInFlight || !document.getElementById('view-netscan').classList.contains('active')) return;
  pingInFlight = true;
  try {
    const res = await api('/api/ping_monitor');
    res.slots.forEach((s, i) => {
      pingData[`ping${i}`] = s.samples;
      setText(`ping${i}-label`, s.label);
      setText(`ping${i}-host`, s.host || 'kein Gateway');
    });
    ['ping0', 'ping1', 'ping2'].forEach(renderSpark);
  } catch (e) {
    // nächster Tick versucht es erneut
  } finally {
    pingInFlight = false;
  }
}

async function setPingHost() {
  const host = document.getElementById('ping-host').value.trim();
  setLoading(true, "RESOLVING HOST...");
  try {
    const res = await api('/api/ping_host', { host });
    settings = res.settings;
  } finally {
    setLoading(false);
  }
  pingData.ping2 = [];
  TactileAudio.done();
  log(`Ping-Ziel geändert: ${host}`, true);
}

function onAdapterSelect() {
  const a = adapters[document.getElementById('adapter-select').value];
  if (a) {
    document.getElementById('dash-mac').innerText = formatMac(a.mac);
    log(`Adapter gewechselt zu: ${a.name}`);
  }
}

function currentAdapter() {
  return adapters[document.getElementById('adapter-select').value || 0];
}

async function oneClickSpoof() {
  const a = currentAdapter();
  if (!a) return;
  setLoading(true, "ROTATING IDENTITY...");
  log("Starte vollständige Identitäts-Rotation...", true);
  const res = await api('/api/rotate', {
    subkey: a.id,
    vendor: document.getElementById('mac-vendor').value,
    profile: document.getElementById('host-profile').value,
    custom_mac: document.getElementById('custom-mac').value.trim(),
    custom_host: document.getElementById('custom-host').value.trim()
  });
  setLoading(false);
  TactileAudio.done();
  log(`Neue Identität aktiv -> Host: ${res.hostname} | MAC: ${formatMac(res.mac)}`, true);
  await refreshAll();
}

async function spoofMacOnly() {
  const a = currentAdapter();
  if (!a) return;
  setLoading(true, "SPOOFING MAC...");
  const res = await api('/api/mac', {
    subkey: a.id,
    vendor: document.getElementById('mac-vendor').value,
    custom_mac: document.getElementById('custom-mac').value.trim()
  });
  setLoading(false);
  TactileAudio.done();
  log(`MAC geändert auf ${formatMac(res.mac)}`, true);
  await refreshAll();
}

async function spoofHostOnly() {
  setLoading(true, "UPDATING HOSTNAME...");
  const res = await api('/api/hostname', {
    profile: document.getElementById('host-profile').value,
    custom_host: document.getElementById('custom-host').value.trim()
  });
  setLoading(false);
  TactileAudio.done();
  log(`Hostname geändert auf ${res.hostname}`, true);
  await refreshAll();
}

async function restoreHardwareMac() {
  const a = currentAdapter();
  if (!a) return;
  setLoading(true, "RESTORING FACTORY MAC...");
  await api('/api/restore_mac', { subkey: a.id });
  setLoading(false);
  TactileAudio.done();
  log("Hardware-MAC wiederhergestellt.", true);
  await refreshAll();
}

async function spoofGuids(restore) {
  setLoading(true, "UPDATING SYSTEM GUIDS...");
  const res = await api('/api/spoof_guids', { restore });
  setLoading(false);
  TactileAudio.done();
  log(`${restore ? 'Original-GUIDs wiederhergestellt' : 'Neue System-GUIDs gesetzt'}: ${res.machine_guid}`, true);
  await refreshAll();
}

async function restoreIdentity() {
  if (!await nexusConfirm('Hostname, System-GUIDs und alle geänderten MAC-Adressen gehen auf die gesicherten Originalwerte zurück.',
    { title: 'Alles auf Original?', confirm: 'Zurücksetzen' })) return;
  setLoading(true, "RESTORING ORIGINAL IDENTITY...");
  const res = await api('/api/restore_identity');
  setLoading(false);
  TactileAudio.done();
  log(res.restored.length ? `Wiederhergestellt: ${res.restored.join(', ')}` : 'Alles war bereits im Originalzustand.', true);
  await refreshAll();
}

async function setDns(provider) {
  const a = currentAdapter();
  if (!a) return;
  setLoading(true, "SETTING DNS...");
  await api('/api/dns', { subkey: a.id, provider });
  setLoading(false);
  TactileAudio.done();
  log(`DNS geändert auf ${provider.toUpperCase()}.`, true);
}

async function flushStack() {
  setLoading(true, "FLUSHING STACK...");
  await api('/api/flush');
  setLoading(false);
  TactileAudio.done();
  log("ARP, DNS & DHCP Lease zurückgesetzt.", true);
  await refreshAll();
}

async function wipeHistory() {
  setLoading(true, "WIPING NETWORK HISTORY...");
  const res = await api('/api/wipe_history');
  setLoading(false);
  TactileAudio.done();
  log(`${res.removed} Netzwerkprofile gelöscht.`, true);
}

function setSortPath(val) {
  document.getElementById('sort-path').value = val;
}

async function runSorter(dryRun) {
  const path = document.getElementById('sort-path').value.trim();
  setLoading(true, dryRun ? "SCANNING FOLDER..." : "SORTING FILES...");
  const res = await api('/api/sort_files', { path, dry_run: dryRun });
  setLoading(false);
  TactileAudio.done();
  const box = document.getElementById('sort-preview-box');
  box.style.display = 'block';
  if (res.error) {
    box.innerHTML = `<span style="color:var(--status-danger)">${esc(res.error)}</span>`;
    return;
  }
  const summary = Object.entries(res.counts).map(([k, v]) => `${esc(k)}: <b>${v}</b>`).join(' &nbsp;|&nbsp; ');
  if (dryRun) {
    box.innerHTML = `<div><b>Vorschau:</b> ${res.total} Dateien gefunden (${summary || 'Keine'})</div>`;
    log(`Vorschau-Scan: ${res.total} Dateien.`);
  } else {
    box.innerHTML = `<div><b>Sortiert!</b> ${res.moved} Dateien verschoben (${summary}).</div>`;
    log(`${res.moved} Dateien sortiert!`, true);
  }
}

async function quickSortDownloads() {
  setSortPath('downloads');
  await runSorter(false);
}

async function undoSort() {
  const res = await api('/api/undo_sort');
  TactileAudio.done();
  log(`${res.restored} Dateien zurückverschoben.`, true);
}

async function cleanEmptyDirs() {
  const path = document.getElementById('sort-path').value.trim();
  const res = await api('/api/clean_empty_dirs', { path });
  TactileAudio.done();
  log(`${res.removed} leere Unterordner bereinigt.`, true);
}

async function scanLargeFiles() {
  const path = document.getElementById('sort-path').value.trim();
  setLoading(true, "SCANNING LARGE FILES...");
  const res = await api('/api/large_files', { path });
  setLoading(false);
  const tbody = document.getElementById('large-files-body');
  tbody.innerHTML = '';
  if (!res.files || res.files.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4">Keine Dateien über 20 MB gefunden.</td></tr>';
    return;
  }
  res.files.forEach(f => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(f.name)}</td><td>${esc(f.size_mb)} MB</td><td style="color:var(--text-secondary)">${esc(f.path)}</td>
      <td><button class="btn-secondary btn-mini">Zeigen</button></td>`;
    tr.querySelector('button').addEventListener('click', () => revealFile(f.path));
    tbody.appendChild(tr);
  });
  log(`${res.files.length} große Dateien gefunden.`, true);
}

function fmtBytes(b) {
  if (b >= 1024 ** 3) return `${(b / 1024 ** 3).toFixed(2)} GB`;
  if (b >= 1024 ** 2) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(b / 1024))} KB`;
}

function baseName(p) {
  return p.split(/[\\/]/).pop();
}

async function scanDuplicates() {
  const path = document.getElementById('sort-path').value.trim();
  setLoading(true, "HASHING FILES...");
  const res = await api('/api/duplicates', { path });
  setLoading(false);
  TactileAudio.done();
  const box = document.getElementById('dup-results');
  box.innerHTML = '';
  const summary = document.createElement('div');
  summary.className = 'metric-box';
  summary.style.marginTop = '10px';
  box.appendChild(summary);
  if (res.error) {
    summary.innerHTML = `<span style="color:var(--status-danger)">${esc(res.error)}</span>`;
    return;
  }
  if (!res.groups.length) {
    summary.textContent = `Keine Duplikate unter ${res.scanned} Dateien gefunden.`;
    log(`Duplikat-Scan: keine Duplikate in ${res.folder}.`);
    return;
  }
  const shown = res.total_groups > res.groups.length ? ` · Top ${res.groups.length} angezeigt` : '';
  summary.innerHTML = `<b>${res.total_groups}</b> Gruppen · <b>${fmtBytes(res.wasted)}</b> durch Kopien belegt · ${res.scanned} Dateien geprüft${shown}`;
  res.groups.forEach(g => box.appendChild(renderDupGroup(g, res.folder)));
  log(`Duplikat-Scan: ${res.total_groups} Gruppen, ${fmtBytes(res.wasted)} durch Kopien belegt.`, true);
}

function renderDupGroup(g, folder) {
  const el = document.createElement('div');
  el.className = 'dup-group';
  el.innerHTML = `<div class="dup-head"><span>${g.files.length}× ${esc(baseName(g.files[0]))}</span>
    <span style="color:var(--text-secondary); font-weight:500;">${fmtBytes(g.size)} je Datei · ${fmtBytes(g.wasted)} doppelt</span></div>`;
  const prefix = folder.replace(/[\\/]+$/, '') + '\\';
  g.files.forEach((p, i) => {
    // Relativ zum gescannten Ordner, sonst schneidet die Ellipse genau den Dateinamen ab
    const shown = p.startsWith(prefix) ? p.slice(prefix.length) : p;
    const row = document.createElement('div');
    row.className = 'dup-file';
    row.innerHTML = `<span class="path" title="${esc(p)}">${esc(shown)}</span>
      ${i === 0 ? '<span class="tag">Original</span>' : '<button class="btn-danger btn-mini">Papierkorb</button>'}
      <button class="btn-secondary btn-mini">Zeigen</button>`;
    row.querySelector('.btn-secondary').addEventListener('click', () => revealFile(p));
    const del = row.querySelector('.btn-danger');
    if (del) del.addEventListener('click', () => recycleDuplicate(p, row));
    el.appendChild(row);
  });
  return el;
}

async function recycleDuplicate(path, row) {
  const res = await api('/api/recycle_duplicate', { path });
  if (!res.ok) {
    log(`Konnte nicht in den Papierkorb verschieben: ${path}`, 'error');
    return;
  }
  TactileAudio.done();
  row.style.opacity = '0.35';
  row.querySelectorAll('button').forEach(b => b.disabled = true);
  log(`In den Papierkorb verschoben: ${path}`, true);
}

async function revealFile(path) {
  await api('/api/reveal', { path });
  TactileAudio.click();
}

function setPowerPreset(h, m) {
  document.getElementById('p-hrs').value = h;
  document.getElementById('p-mins').value = m;
  document.getElementById('p-secs').value = 0;
}

async function startPowerTimer(mode) {
  const payload = {
    mode,
    action: document.getElementById('p-action').value,
    hours: parseInt(document.getElementById('p-hrs').value || 0),
    mins: parseInt(document.getElementById('p-mins').value || 0),
    secs: parseInt(document.getElementById('p-secs').value || 0),
    clock_time: document.getElementById('p-clock-time').value.trim(),
    force: document.getElementById('p-force').checked,
    test_mode: document.getElementById('p-test').checked
  };
  const res = await api('/api/power_start', payload);
  TactileAudio.done();
  log(`Timer gestartet: ${payload.action} (Ziel: ${res.target_time_str})`, true);
  pollPowerStatus();
}

async function cancelPowerTimer() {
  await api('/api/power_cancel');
  TactileAudio.click();
  log("Timer abgebrochen.", true);
  pollPowerStatus();
}

async function pollPowerStatus() {
  const st = await api('/api/power_status');
  document.getElementById('power-badge').innerText = `● ${st.last_message}`;
  const hrs = String(Math.floor(st.remaining_seconds / 3600)).padStart(2, '0');
  const mins = String(Math.floor((st.remaining_seconds % 3600) / 60)).padStart(2, '0');
  const secs = String(st.remaining_seconds % 60).padStart(2, '0');
  document.getElementById('power-countdown').innerText = `${hrs}:${mins}:${secs}`;
  document.getElementById('nav-power-badge').innerText = st.running ? `${mins}:${secs}` : 'IDLE';
  if (st.running && st.total_seconds > 0) {
    const pct = ((st.total_seconds - st.remaining_seconds) / st.total_seconds) * 100;
    document.getElementById('power-progress').style.width = `${pct}%`;
    document.getElementById('power-target-info').innerText = `Aktion (${st.action}) um ${st.target_time_str}`;
  } else {
    document.getElementById('power-progress').style.width = '0%';
  }
}

async function toggleCaffeine() {
  const res = await api('/api/caffeine');
  TactileAudio.done();
  document.getElementById('caff-status').innerText = res.active ? 'AKTIV' : 'AUS';
  log(`Caffeine: ${res.active ? 'AKTIVIERT' : 'DEAKTIVIERT'}`, true);
}

async function unlockUltimatePower() {
  const res = await api('/api/power_plan', { plan: 'ultimate' });
  TactileAudio.done();
  log(res.msg, true);
}

async function triggerBatteryReport() {
  setLoading(true, "GENERATING BATTERY REPORT...");
  const res = await api('/api/battery_report');
  setLoading(false);
  TactileAudio.done();
  log(res.msg, true);
}

async function applyHostsBlock() {
  setLoading(true, "BLOCKING TELEMETRY...");
  const res = await api('/api/hosts_block');
  setLoading(false);
  TactileAudio.done();
  log(`${res.added} Telemetrie-Domains in Hosts blockiert.`, true);
}

async function runCleaner() {
  const targets = Array.from(document.querySelectorAll('.clean-cb:checked')).map(cb => cb.value);
  setLoading(true, "CLEANING SYSTEM...");
  const res = await api('/api/clean', { targets });
  setLoading(false);
  TactileAudio.done();
  log(`Bereinigung: ${res.deleted_files} Dateien (${res.freed_mb} MB frei).`, true);
  await refreshAll();
}

async function boostRam() {
  setLoading(true, "TRIMMING RAM...");
  const res = await api('/api/ram_boost');
  setLoading(false);
  TactileAudio.done();
  log(`RAM optimiert: ${res.before}% -> ${res.after}%`, true);
  await refreshAll();
}

async function flushStandbyRam() {
  setLoading(true, "TRIMMING STANDBY RAM...");
  const res = await api('/api/flush_standby_ram');
  setLoading(false);
  TactileAudio.done();
  log(`Standby-Cache getrimmt. Auslastung: ${res.after}%`, true);
  await refreshAll();
}

async function quickBoost() {
  await boostRam();
  const res = await api('/api/clean', { targets: ['user_temp', 'prefetch'] });
  log(`Quick-Boost: ${res.freed_mb} MB Temp bereinigt.`, true);
}

async function loadTweaks() {
  const st = await api('/api/tweaks_get');
  Object.keys(st).forEach(k => {
    const el = document.getElementById(`tw-${k}`);
    if (el) el.checked = st[k];
  });
}

async function toggleTweak(id, enable) {
  await api('/api/tweaks_set', { id, enable });
  TactileAudio.done();
  log(`Tweak [${id}] -> ${enable ? 'AKTIVIERT' : 'DEAKTIVIERT'}`, true);
}

async function loadProcesses() {
  const res = await api('/api/processes');
  const tbody = document.getElementById('proc-body');
  tbody.innerHTML = '';
  (res.processes || []).forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(p.Name)}</td><td>${esc(p.Id)}</td><td>${esc(p.MB)} MB</td>
      <td>
        <select style="padding:2px; font-size:0.65rem; width:auto; display:inline-block;">
          <option value="Normal">Normal</option>
          <option value="High">High</option>
          <option value="Realtime">Realtime</option>
        </select>
        <button class="btn-danger" style="padding:2px 6px; font-size:0.62rem;">Kill</button>
      </td>`;
    tr.querySelector('select').addEventListener('change', (e) => changePrio(p.Id, e.target.value));
    tr.querySelector('button').addEventListener('click', () => killProc(p.Id, p.Name));
    tbody.appendChild(tr);
  });
}

async function changePrio(pid, priority) {
  await api('/api/set_priority', { pid, priority });
  TactileAudio.click();
  log(`Prozess PID ${pid} Priorität auf ${priority} gesetzt.`, true);
}

async function killProc(pid, name) {
  const res = await api('/api/kill_proc', { pid });
  TactileAudio.done();
  log(res.ok ? `Prozess ${name} (PID ${pid}) beendet.` : `Fehler.`, true);
  loadProcesses();
}

async function loadStartup() {
  const res = await api('/api/startup');
  const tbody = document.getElementById('startup-body');
  tbody.innerHTML = '';
  (res.items || []).forEach(item => {
    const tr = document.createElement('tr');
    tr.style.opacity = item.enabled ? '1' : '0.5';
    tr.innerHTML = `<td title="${esc(item.name)}" style="max-width:130px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(item.name)}</td><td>${esc(item.scope)}</td>
      <td title="${esc(item.cmd)}" style="color:var(--text-secondary); max-width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(item.cmd)}</td>
      <td><label class="switch"><input type="checkbox" ${item.enabled ? 'checked' : ''}><span class="slider"></span></label></td>`;
    tr.querySelector('input').addEventListener('change', (e) => toggleStartup(item, e.target, tr));
    tbody.appendChild(tr);
  });
}

async function toggleStartup(item, input, tr) {
  try {
    const res = await api('/api/startup_toggle', { scope: item.scope, name: item.name, enable: input.checked });
    input.checked = res.enabled;
    tr.style.opacity = res.enabled ? '1' : '0.5';
    TactileAudio.done();
    log(`Autostart [${item.name}] -> ${res.enabled ? 'AKTIVIERT' : 'DEAKTIVIERT'}`, true);
  } catch (e) {
    input.checked = !input.checked;
    throw e;
  }
}

async function loadConnections() {
  const res = await api('/api/net_connections');
  const tbody = document.getElementById('net-conns-body');
  tbody.innerHTML = '';
  (res.connections || []).forEach(c => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(c.LocalAddress)}</td><td>${esc(c.LocalPort)}</td><td>${esc(c.OwningProcess)}</td>`;
    tbody.appendChild(tr);
  });
  log(`${(res.connections || []).length} Sockets geladen.`);
}

async function runPortScan() {
  const target = document.getElementById('scan-target').value.trim();
  setLoading(true, "SCANNING PORTS...");
  const res = await api('/api/port_scan', { target });
  setLoading(false);
  TactileAudio.done();
  const textEl = document.getElementById('scan-results-text');
  if (res.open_ports && res.open_ports.length > 0) {
    textEl.innerHTML = `<span style="color:var(--status-warn)">Offene Ports: ${res.open_ports.join(', ')}</span>`;
  } else {
    textEl.innerHTML = `<span style="color:var(--status-ok)">Keine offenen Standard-Ports.</span>`;
  }
  log(`Port-Scan auf ${target} fertig. Offen: ${res.open_ports.length}`, true);
}

async function runDnsBenchmark() {
  setLoading(true, "BENCHMARKING DNS...");
  const res = await api('/api/dns_benchmark');
  setLoading(false);
  TactileAudio.done();
  const textEl = document.getElementById('scan-results-text');
  if (res.benchmark && res.benchmark.length > 0) {
    const best = res.benchmark[0];
    textEl.innerHTML = `<span style="color:var(--status-ok)">Bester DNS: ${best.name} (${best.ms} ms)</span>`;
    log(`DNS Benchmark fertig. Schnellster: ${best.name} (${best.ms} ms)`, true);
  }
}

async function openSysTool(tool) {
  await api('/api/sys_tool', { tool });
  TactileAudio.click();
  log(`System-Tool geöffnet: ${tool}`, true);
}

// ---------------- App-Updates (winget) ----------------
let updatePackages = [];
let updatePoll = null;
let updateWasRunning = false;

async function checkAppUpdates() {
  setLoading(true, "CHECKING APP UPDATES...");
  const res = await api('/api/app_updates_list');
  setLoading(false);
  TactileAudio.done();
  updatePackages = res.packages;
  renderUpdates();
  log(updatePackages.length ? `${updatePackages.length} App-Updates verfügbar.` : 'Alle Apps sind aktuell.', true);
}

function renderUpdates() {
  const tbody = document.getElementById('upd-body');
  tbody.innerHTML = '';
  document.getElementById('upd-all').disabled = !updatePackages.length;
  if (!updatePackages.length) {
    tbody.innerHTML = '<tr><td colspan="4">Alles aktuell.</td></tr>';
    return;
  }
  updatePackages.forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td title="${esc(p.id)}" style="font-family:var(--font-ui);">${esc(p.name)}</td>
      <td style="color:var(--text-secondary)">${esc(p.current)}</td><td>${esc(p.available)}</td>
      <td style="text-align:right;"><button class="btn-secondary btn-mini">Update</button></td>`;
    tr.querySelector('button').addEventListener('click', () => startAppUpdate(p.id, p.name));
    tbody.appendChild(tr);
  });
}

async function startAppUpdate(id, name) {
  if (!id && !await nexusConfirm(`${updatePackages.length} Apps werden still im Hintergrund aktualisiert. Laufende Apps werden dabei ggf. kurz geschlossen.`,
    { title: 'Alle Apps aktualisieren?', confirm: 'Aktualisieren' })) return;
  await api('/api/app_update_start', id ? { id } : {});
  log(`Update gestartet: ${name || 'alle Apps'}`, true);
  pollAppUpdate();
}

async function pollAppUpdate() {
  clearTimeout(updatePoll);
  const st = await api('/api/app_update_status');
  const box = document.getElementById('upd-status');
  document.querySelectorAll('#upd-body button').forEach(b => b.disabled = st.running);
  document.getElementById('upd-all').disabled = st.running || !updatePackages.length;
  if (st.running) {
    updateWasRunning = true;
    box.style.display = 'block';
    box.innerHTML = `<b>Läuft:</b> ${esc(st.target)} wird aktualisiert ... das kann ein paar Minuten dauern.`;
    updatePoll = setTimeout(() => pollAppUpdate().catch(() => {}), 2000);
  } else if (st.finished_at) {
    box.style.display = 'block';
    box.innerHTML = `<span style="color:${st.ok ? 'var(--status-ok)' : 'var(--status-warn)'}; font-weight:600;">${st.ok ? '✓ Fertig' : '⚠ Mit Fehlern beendet'}</span>
      (${esc(st.finished_at)}): ${esc(st.target)}
      <pre style="margin-top:6px; font-family:'JetBrains Mono',monospace; font-size:0.66rem; color:var(--text-secondary); white-space:pre-wrap; max-height:120px; overflow-y:auto;">${esc(st.output)}</pre>`;
    if (updateWasRunning) {
      updateWasRunning = false;
      TactileAudio.done();
      log(`Update ${st.ok ? 'abgeschlossen' : 'mit Fehlern beendet'}: ${st.target}`, st.ok ? true : 'error');
      checkAppUpdates();
    }
  }
}

// ---------------- Alltag: Workspaces, Erinnerungen, Notizen, Bausteine ----------------
let userData = { workspaces: [], reminders: [], notes: '', snippets: [], autosort: {}, commands: [] };
let editingWorkspaceId = null;

async function loadUserData(withNotes = false) {
  userData = await api('/api/user_data');
  renderWorkspaces();
  renderReminders();
  renderSnippets();
  renderAutosort();
  renderCommands();
  settings = userData.settings;
  applySettings();
  setText('set-data-path', `Gespeichert in ${userData.data_file}`);
  if (withNotes) document.getElementById('notes').value = userData.notes;
}

// Nur die Teile neu zeichnen, die sich im Hintergrund ändern (fällige Erinnerungen, Auto-Sort-Status)
async function refreshDaily() {
  const data = await api('/api/user_data');
  userData.reminders = data.reminders;
  userData.autosort = data.autosort;
  renderReminders();
  renderAutosort();
}

function shortItem(item) {
  try {
    const u = new URL(item);
    if (u.host) return u.host;
  } catch (e) {}
  return baseName(item.replace(/[\\/]+$/, '')) || item;
}

function renderWorkspaces() {
  const list = document.getElementById('ws-list');
  const dash = document.getElementById('dash-ws');
  list.innerHTML = '';
  dash.innerHTML = '';
  if (!userData.workspaces.length) {
    list.innerHTML = '<div class="list-sub">Noch keine Workspaces. Leg unten deinen ersten an.</div>';
    return;
  }
  dash.innerHTML = '<span class="list-sub" style="align-self:center; margin-right:4px;">Workspaces</span>';
  userData.workspaces.forEach(w => {
    const row = document.createElement('div');
    row.className = 'list-row';
    row.innerHTML = `<div class="grow"><b>${esc(w.name)}</b><div class="list-sub">${esc(w.items.map(shortItem).join(' · '))}</div></div>
      <button class="btn-primary btn-mini">Starten</button>
      <button class="btn-secondary btn-mini">Bearbeiten</button>
      <button class="btn-danger btn-mini" title="Löschen">×</button>`;
    const [start, edit, del] = row.querySelectorAll('button');
    start.addEventListener('click', () => launchWorkspace(w.id));
    edit.addEventListener('click', () => editWorkspace(w));
    del.addEventListener('click', () => deleteWorkspace(w));
    list.appendChild(row);

    const quick = document.createElement('button');
    quick.className = 'btn-secondary btn-mini';
    quick.textContent = `▶ ${w.name}`;
    quick.addEventListener('click', () => launchWorkspace(w.id));
    dash.appendChild(quick);
  });
}

async function launchWorkspace(id) {
  const w = userData.workspaces.find(x => x.id === id);
  const res = await api('/api/workspace_launch', { id });
  TactileAudio.done();
  log(`Workspace „${w ? w.name : id}“: ${res.started.length} geöffnet.`, true);
  if (res.failed.length) log(`Nicht gefunden: ${res.failed.join(', ')}`, 'error');
}

function editWorkspace(w) {
  editingWorkspaceId = w.id;
  document.getElementById('ws-name').value = w.name;
  document.getElementById('ws-items').value = w.items.join('\n');
  document.getElementById('ws-save').innerText = 'Änderungen speichern';
  document.getElementById('ws-name').focus();
}

function resetWorkspaceForm() {
  editingWorkspaceId = null;
  document.getElementById('ws-name').value = '';
  document.getElementById('ws-items').value = '';
  document.getElementById('ws-save').innerText = 'Workspace speichern';
}

async function saveWorkspace() {
  const name = document.getElementById('ws-name').value.trim();
  const items = document.getElementById('ws-items').value.split('\n').map(s => s.trim()).filter(Boolean);
  const res = await api('/api/workspace_save', { id: editingWorkspaceId, name, items });
  userData.workspaces = res.workspaces;
  renderWorkspaces();
  resetWorkspaceForm();
  TactileAudio.done();
  log(`Workspace „${name}“ gespeichert.`, true);
}

async function deleteWorkspace(w) {
  const entries = w.items.length === 1 ? '1 Eintrag' : `${w.items.length} Einträge`;
  if (!await nexusConfirm(`„${w.name}“ (${entries}) wird entfernt. Die Programme selbst bleiben natürlich installiert.`,
    { title: 'Workspace löschen?', confirm: 'Löschen', danger: true })) return;
  const res = await api('/api/workspace_delete', { id: w.id });
  userData.workspaces = res.workspaces;
  renderWorkspaces();
  log(`Workspace „${w.name}“ gelöscht.`);
}

function fmtDue(ts) {
  const d = new Date(ts * 1000);
  const now = new Date();
  const time = d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
  const days = Math.round((new Date(d.toDateString()) - new Date(now.toDateString())) / 86400000);
  const day = days === 0 ? 'heute' : days === 1 ? 'morgen'
    : d.toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit' });
  const mins = Math.max(0, Math.round((d - now) / 60000));
  const rel = mins < 60 ? `in ${mins} min` : `in ${Math.floor(mins / 60)} h ${mins % 60} min`;
  return `${day} ${time} · ${rel}`;
}

function renderReminders() {
  const list = document.getElementById('rem-list');
  list.innerHTML = '';
  if (!userData.reminders.length) {
    list.innerHTML = '<div class="list-sub">Keine anstehenden Erinnerungen.</div>';
    return;
  }
  userData.reminders.forEach(r => {
    const row = document.createElement('div');
    row.className = 'list-row';
    row.innerHTML = `<div class="grow">${esc(r.text)}<div class="list-sub">${fmtDue(r.due)}${r.repeat === 'daily' ? ' · täglich' : ''}</div></div>
      <button class="btn-danger btn-mini" title="Löschen">×</button>`;
    row.querySelector('button').addEventListener('click', () => deleteReminder(r));
    list.appendChild(row);
  });
}

async function addReminder(opts) {
  const input = document.getElementById('rem-text');
  const text = input.value.trim();
  if (!text) {
    input.focus();
    log('Bitte erst eintippen, woran du erinnert werden willst.', 'error');
    return;
  }
  const body = { text, ...opts };
  if (opts.mode === 'at') {
    body.time = document.getElementById('rem-time').value.trim();
    body.repeat = document.getElementById('rem-daily').checked ? 'daily' : 'none';
  }
  // Sofort leeren, damit direkt die nächste Erinnerung getippt werden kann; bei Fehler zurückholen
  input.value = '';
  let res;
  try {
    res = await api('/api/reminder_add', body);
  } catch (e) {
    input.value = text;
    throw e;
  }
  userData.reminders = res.reminders;
  renderReminders();
  TactileAudio.done();
  log(`Erinnerung gesetzt: ${text}`, true);
}

async function deleteReminder(r) {
  const res = await api('/api/reminder_delete', { id: r.id });
  userData.reminders = res.reminders;
  renderReminders();
  log(`Erinnerung entfernt: ${r.text}`);
}

let notesTimer = null;

function onNotesInput() {
  setText('notes-state', 'SPEICHERT ...');
  clearTimeout(notesTimer);
  notesTimer = setTimeout(async () => {
    await api('/api/notes_save', { text: document.getElementById('notes').value });
    setText('notes-state', 'GESPEICHERT');
  }, 800);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

function renderSnippets() {
  const list = document.getElementById('snip-list');
  list.innerHTML = '';
  if (!userData.snippets.length) {
    list.innerHTML = '<div class="list-sub">Noch keine Bausteine, z.B. Adresse, Standard-Antworten, Discord-Name.</div>';
    return;
  }
  userData.snippets.forEach(s => {
    const row = document.createElement('div');
    row.className = 'list-row clickable';
    row.title = 'Klicken zum Kopieren';
    row.innerHTML = `<div class="grow"><b>${esc(s.label)}</b><div class="list-sub">${esc(s.text)}</div></div>
      <button class="btn-danger btn-mini" title="Löschen">×</button>`;
    row.addEventListener('click', () => copySnippet(s));
    row.querySelector('button').addEventListener('click', (e) => {
      e.stopPropagation();
      deleteSnippet(s);
    });
    list.appendChild(row);
  });
}

async function copySnippet(s) {
  await copyText(s.text);
  TactileAudio.done();
  log(`„${s.label}“ in die Zwischenablage kopiert.`, true);
}

async function addSnippet() {
  const label = document.getElementById('snip-label').value.trim();
  const text = document.getElementById('snip-text').value;
  const res = await api('/api/snippet_save', { label, text });
  userData.snippets = res.snippets;
  renderSnippets();
  document.getElementById('snip-label').value = '';
  document.getElementById('snip-text').value = '';
  TactileAudio.done();
  log(`Baustein „${label}“ gespeichert.`, true);
}

async function deleteSnippet(s) {
  const res = await api('/api/snippet_delete', { id: s.id });
  userData.snippets = res.snippets;
  renderSnippets();
  log(`Baustein „${s.label}“ gelöscht.`);
}

function renderAutosort() {
  const st = userData.autosort || {};
  document.getElementById('autosort-toggle').checked = !!st.enabled;
  const last = st.last_run
    ? `zuletzt ${st.last_run} (${st.last_moved} Dateien), seit Start ${st.total_moved}`
    : 'erster Lauf in spätestens einer Minute';
  setText('autosort-info', st.enabled
    ? `Aktiv für ${st.folder} · ${last}`
    : 'Sortiert den Ordner aus dem Feld oben jede Minute automatisch. Laufende Downloads und Dateien jünger als 2 Minuten bleiben liegen.');
}

async function toggleAutosort(input) {
  const path = document.getElementById('sort-path').value.trim() || 'downloads';
  try {
    userData.autosort = await api('/api/autosort_set', { enabled: input.checked, path });
    renderAutosort();
    TactileAudio.done();
    log(userData.autosort.enabled ? `Auto-Sortierung aktiv für ${userData.autosort.folder}` : 'Auto-Sortierung aus.', true);
  } catch (e) {
    input.checked = !input.checked;
    throw e;
  }
}

// ---------------- Befehlssuche (Strg+K) ----------------
let paletteItems = [];
let paletteSel = 0;

function goView(id) {
  const btn = [...document.querySelectorAll('.nav-btn')].find(b => b.getAttribute('onclick').includes(`'${id}'`));
  if (btn) switchView(id, btn);
}

function paletteCommands() {
  const focusLater = (id) => setTimeout(() => document.getElementById(id).focus(), 50);
  const workspaces = userData.workspaces.map(w => ({ label: `Starten: ${w.name}`, hint: 'Workspace', run: () => launchWorkspace(w.id) }));
  const snippets = userData.snippets.map(s => ({ label: `Kopieren: ${s.label}`, hint: 'Baustein', run: () => copySnippet(s) }));
  const actions = [
    { label: 'Downloads jetzt sortieren', hint: 'Aktion', run: quickSortDownloads },
    { label: 'App-Updates suchen', hint: 'Aktion', run: () => { goView('view-tools'); return checkAppUpdates(); } },
    { label: 'Neue Erinnerung', hint: 'Alltag', run: () => { goView('view-daily'); focusLater('rem-text'); } },
    { label: 'Notiz schreiben', hint: 'Alltag', run: () => { goView('view-daily'); focusLater('notes'); } },
    { label: 'Neuer Workspace', hint: 'Alltag', run: () => { goView('view-daily'); resetWorkspaceForm(); focusLater('ws-name'); } },
    { label: 'Caffeine Mode umschalten', hint: 'Aktion', run: toggleCaffeine },
    { label: 'RAM & Temp Boost', hint: 'Aktion', run: quickBoost },
    { label: 'ARP / DNS Flush', hint: 'Aktion', run: flushStack },
    { label: 'Sound an/aus', hint: 'Einstellung', run: toggleSound },
  ];
  const views = [...document.querySelectorAll('.nav-btn')].filter(btn => btn.style.display !== 'none').map(btn => ({
    label: btn.querySelector('span').textContent.replace(/^\d+ \/\/ /, ''),
    hint: 'Ansicht',
    run: () => switchView(btn.getAttribute('onclick').match(/'([^']+)'/)[1], btn)
  }));
  const commands = userData.commands.map(c => ({
    label: `Ausführen: ${c.name}`, hint: 'Befehl', run: () => { goView('view-cmds'); return runCommand(c); }
  }));
  const places = [['downloads', 'Downloads'], ['documents', 'Dokumente'], ['desktop', 'Desktop'], ['appdata', 'AppData'],
    ['temp', 'Temp'], ['startup', 'Autostart-Ordner'], ['hosts', 'hosts-Datei']]
    .map(([key, name]) => ({ label: `Öffnen: ${name}`, hint: 'Ordner', run: () => openPlace(key) }));
  const autoCmds = automations.map(a => ({
    label: `Automation testen: ${a.name}`, hint: 'Automation', run: () => runAutomationNow(a)
  }));
  const focusCmds = [
    ...autoCmds,
    { label: 'Dateien konvertieren …', hint: 'Converter', run: () => { goView('view-convert'); return pickConvertFiles(); } },
    { label: 'Design-Code kopieren', hint: 'Design', run: copyDesignCode },
    { label: 'Speedtest starten', hint: 'Netz', run: () => { goView('view-netscan'); return startSpeedtest(); } },
    { label: 'Ping-Monitor', hint: 'Netz', run: () => goView('view-netscan') },
    { label: 'Festplatten-Gesundheit', hint: 'System', run: () => { goView('view-tools'); return loadDiskHealth(); } },
    { label: 'Neue Automation', hint: 'Automation', run: () => { goView('view-auto'); resetAutomationForm(); } },
    { label: 'Fokus-Timer 25 min starten', hint: 'Alltag', run: () => startFocus(25, 'Fokus') },
    { label: 'Pause 5 min starten', hint: 'Alltag', run: () => startFocus(5, 'Pause') },
    { label: 'Einstellungen', hint: 'System', run: () => goView('view-settings') },
  ];
  return [...workspaces, ...commands, ...snippets, ...actions, ...focusCmds, ...places, ...views];
}

function openPalette() {
  document.getElementById('palette').classList.add('open');
  const input = document.getElementById('palette-input');
  input.value = '';
  renderPalette();
  input.focus();
}

function closePalette() {
  document.getElementById('palette').classList.remove('open');
}

function setPaletteSel(i) {
  const items = document.getElementById('palette-list').children;
  if (!paletteItems.length) return;
  paletteSel = (i + paletteItems.length) % paletteItems.length;
  [...items].forEach((el, idx) => el.classList.toggle('sel', idx === paletteSel));
  items[paletteSel].scrollIntoView({ block: 'nearest' });
}

// Rechner: nur Ziffern, Klammern und Grundrechenarten erreichen Function(), sonst nichts
function paletteCalc(query) {
  const expr = query.trim().replace(/^=/, '').replace(/,/g, '.').replace(/×/g, '*').replace(/÷/g, '/').replace(/\^/g, '**');
  if (!/^[\d\s+\-*/().%]+$/.test(expr) || !/\d\s*(\*\*|[+\-*/%])\s*[\d(.]/.test(expr)) return [];
  try {
    const value = Function(`"use strict"; return (${expr});`)();
    if (!Number.isFinite(value)) return [];
    const result = +value.toFixed(10);
    return [{
      label: `= ${result.toLocaleString('de-DE', { maximumFractionDigits: 10 })}`,
      hint: 'Rechner · Enter kopiert',
      run: async () => { await copyText(String(result).replace('.', ',')); log(`Ergebnis ${result} kopiert.`, true); }
    }];
  } catch (e) {
    return [];
  }
}

function paletteSearch(query) {
  const q = query.trim();
  if (!q) return [];
  const open = (url) => api('/api/open_url', { url });
  return [
    { label: `Google: ${q}`, hint: 'Websuche', run: () => open(`https://www.google.com/search?q=${encodeURIComponent(q)}`) },
    { label: `YouTube: ${q}`, hint: 'Websuche', run: () => open(`https://www.youtube.com/results?search_query=${encodeURIComponent(q)}`) },
  ];
}

function renderPalette() {
  const query = document.getElementById('palette-input').value;
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const matches = paletteCommands().filter(c => words.every(w => `${c.label} ${c.hint}`.toLowerCase().includes(w)));
  const calc = paletteCalc(query);
  paletteItems = [...calc, ...matches, ...(calc.length ? [] : paletteSearch(query))];
  const list = document.getElementById('palette-list');
  list.innerHTML = paletteItems.length ? '' : '<div class="palette-item">Nichts gefunden</div>';
  paletteItems.forEach((c, i) => {
    const el = document.createElement('div');
    el.className = 'palette-item';
    el.innerHTML = `<span>${esc(c.label)}</span><span class="hint">${esc(c.hint)}</span>`;
    el.addEventListener('mousemove', () => { if (paletteSel !== i) setPaletteSel(i); });
    el.addEventListener('click', () => runPalette(i));
    list.appendChild(el);
  });
  setPaletteSel(0);
}

function runPalette(i) {
  const cmd = paletteItems[i];
  if (!cmd) return;
  closePalette();
  TactileAudio.click(200);
  cmd.run();
}

function onPaletteKey(e) {
  if (e.key === 'ArrowDown') { e.preventDefault(); setPaletteSel(paletteSel + 1); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); setPaletteSel(paletteSel - 1); }
  else if (e.key === 'Enter') { e.preventDefault(); runPalette(paletteSel); }
  else if (e.key === 'Escape') { closePalette(); }
}

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    document.getElementById('palette').classList.contains('open') ? closePalette() : openPalette();
  }
});

// ---------------- Custom Commands ----------------
const CMD_PRESETS = [
  { name: 'Netzwerk-Info', shell: 'cmd', command: 'ipconfig /all' },
  { name: 'Ping-Test', shell: 'cmd', command: 'ping 1.1.1.1 -n 4' },
  { name: 'DNS-Cache leeren', shell: 'cmd', command: 'ipconfig /flushdns' },
  { name: 'Top-RAM-Prozesse', shell: 'powershell', command: "Get-Process | Sort-Object WS -Descending | Select-Object -First 10 Name, @{n='MB';e={[math]::Round($_.WS/1MB)}} | Format-Table -AutoSize" },
  { name: 'Treiberliste', shell: 'cmd', command: 'driverquery /fo table' },
  { name: 'Letzter Neustart', shell: 'powershell', command: '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime' },
];
let editingCommandId = null;
let commandPoll = null;

function renderCommands() {
  const list = document.getElementById('cmd-list');
  list.innerHTML = '';
  setText('cmd-count', `${userData.commands.length} GESPEICHERT`);
  if (!userData.commands.length) {
    list.innerHTML = '<div class="list-sub">Noch keine Befehle. Schreib rechts einen oder nimm unten eine Vorlage.</div>';
  }
  userData.commands.forEach(c => {
    const row = document.createElement('div');
    row.className = 'list-row';
    row.innerHTML = `<div class="grow"><b>${esc(c.name)}</b><div class="list-sub">${c.shell === 'powershell' ? 'PS' : 'CMD'} · ${esc(c.command)}</div></div>
      <button class="btn-primary btn-mini" title="Ausführen, Ausgabe unten anzeigen">▶</button>
      <button class="btn-secondary btn-mini" title="In eigenem Konsolenfenster öffnen">Fenster</button>
      <button class="btn-secondary btn-mini">Bearbeiten</button>
      <button class="btn-danger btn-mini" title="Löschen">×</button>`;
    const [run, win, edit, del] = row.querySelectorAll('button');
    run.addEventListener('click', () => runCommand(c));
    win.addEventListener('click', () => runCommand(c, true));
    edit.addEventListener('click', () => editCommand(c));
    del.addEventListener('click', () => deleteCommand(c));
    list.appendChild(row);
  });

  const presets = document.getElementById('cmd-presets');
  presets.innerHTML = '';
  CMD_PRESETS.filter(p => !userData.commands.some(c => c.command === p.command)).forEach(p => {
    const btn = document.createElement('button');
    btn.className = 'btn-secondary btn-mini';
    btn.textContent = `+ ${p.name}`;
    btn.title = p.command;
    btn.addEventListener('click', () => saveCommand(p));
    presets.appendChild(btn);
  });
  if (!presets.children.length) presets.innerHTML = '<span class="list-sub">Alle Vorlagen übernommen.</span>';
}

function editCommand(c) {
  editingCommandId = c.id;
  document.getElementById('cmd-name').value = c.name;
  document.getElementById('cmd-shell').value = c.shell;
  document.getElementById('cmd-command').value = c.command;
  setText('cmd-form-title', 'Befehl bearbeiten');
  document.getElementById('cmd-save').innerText = 'Änderungen speichern';
  document.getElementById('cmd-name').focus();
}

function resetCommandForm() {
  editingCommandId = null;
  document.getElementById('cmd-name').value = '';
  document.getElementById('cmd-shell').value = 'cmd';
  document.getElementById('cmd-command').value = '';
  setText('cmd-form-title', 'Neuer Befehl');
  document.getElementById('cmd-save').innerText = 'Befehl speichern';
}

async function saveCommand(preset) {
  const body = preset ? { ...preset } : {
    id: editingCommandId,
    name: document.getElementById('cmd-name').value.trim(),
    shell: document.getElementById('cmd-shell').value,
    command: document.getElementById('cmd-command').value
  };
  const res = await api('/api/command_save', body);
  userData.commands = res.commands;
  renderCommands();
  if (!preset) resetCommandForm();
  TactileAudio.done();
  log(`Befehl „${body.name}“ gespeichert.`, true);
}

async function deleteCommand(c) {
  if (!await nexusConfirm(`Der gespeicherte Befehl „${c.name}“ wird entfernt.`,
    { title: 'Befehl löschen?', confirm: 'Löschen', danger: true })) return;
  const res = await api('/api/command_delete', { id: c.id });
  userData.commands = res.commands;
  renderCommands();
  log(`Befehl „${c.name}“ gelöscht.`);
}

async function runCommand(c, visible = false) {
  await api('/api/command_run', { id: c.id, visible });
  TactileAudio.click(200);
  if (visible) {
    log(`Befehl „${c.name}“ in eigenem Fenster gestartet.`, true);
    return;
  }
  setText('cmd-out-title', `· ${c.name}`);
  log(`Befehl „${c.name}“ läuft ...`);
  pollCommand(c);
}

async function pollCommand(c) {
  clearTimeout(commandPoll);
  const st = await api('/api/command_status', { id: c.id });
  const out = document.getElementById('cmd-output');
  const state = document.getElementById('cmd-out-state');
  if (st.running) {
    state.innerHTML = '<span style="color:var(--text-secondary)">● LÄUFT ...</span>';
    out.textContent = st.output || '…';
    commandPoll = setTimeout(() => pollCommand(c).catch(() => {}), 700);
    return;
  }
  const ok = st.code === 0;
  state.innerHTML = `<span style="color:${ok ? 'var(--status-ok)' : 'var(--status-warn)'}">${ok ? '✓' : '⚠'} EXIT ${esc(st.code)} · ${esc(st.duration)} s</span>`;
  out.textContent = st.output.trim() || '(keine Ausgabe)';
  out.scrollTop = out.scrollHeight;
  TactileAudio.done();
  log(`Befehl „${c.name}“ fertig (Exit ${st.code}).`, ok ? true : 'error');
}

// ---------------- Einstellungen ----------------
const DEFAULT_DESIGN = {
  theme: 'midnight', accent: '#ffffff', accent2: '#a855f7', accent_gradient: false, font: 'inter', font_size: 16,
  radius: 'normal', density: 'normal', pattern: 'none', glow: true, animations: true, show_console: true,
  nav_numbers: true, card_style: 'solid', contrast: 'normal', button_shape: 'normal', sidebar_side: 'left',
  sidebar_width: 'normal', label_case: 'upper', mono_values: true, scrollbar: 'normal', transition: 'pop',
  motion_speed: 'normal', hover_lift: false
};
const DESIGN_KEYS = Object.keys(DEFAULT_DESIGN);
let settings = {
  ...DEFAULT_DESIGN, sound: true, start_view: 'view-dash', monitor_interval: 1, refresh_interval: 5,
  brand_name: 'MONOLITH // NEXUS OS', brand_tag: 'v10.0 QUANTUM KERNEL', hidden_views: [], dash_hidden: [],
  welcome: true, welcome_style: 'stats', welcome_duration: 2500, welcome_name: '',
  toasts: 'all', toast_pos: 'bottom-right', toast_duration: 5, clock_format: '24', clock_seconds: true
};
const ACCENTS = ['#ffffff', '#3b82f6', '#a855f7', '#10b981', '#f59e0b', '#ef4444'];

// tint = RGB der Überlagerungsfarbe (hell auf dunklen Themes, dunkel auf Light)
const THEMES = {
  midnight: { name: 'Midnight', bg: '#050506', surface: '#0b0b0e', surface2: '#111116', input: '#060608', text: ['#fafafa', '#a1a1aa', '#52525b'], tint: '255,255,255', track: '#27272a', topbar: 'rgba(5,5,6,0.85)', sidebar: 'rgba(9,9,12,0.7)' },
  graphite: { name: 'Graphite', bg: '#17171a', surface: '#1f1f23', surface2: '#26262b', input: '#131316', text: ['#f4f4f5', '#a1a1aa', '#63636c'], tint: '255,255,255', track: '#3f3f46', topbar: 'rgba(23,23,26,0.85)', sidebar: 'rgba(27,27,31,0.72)' },
  oled:     { name: 'OLED', bg: '#000000', surface: '#050505', surface2: '#0b0b0b', input: '#000000', text: ['#ffffff', '#9ca3af', '#4b5563'], tint: '255,255,255', track: '#262626', topbar: 'rgba(0,0,0,0.88)', sidebar: 'rgba(0,0,0,0.8)' },
  nord:     { name: 'Nord', bg: '#242933', surface: '#2e3440', surface2: '#353c4a', input: '#262b35', text: ['#eceff4', '#aeb6c5', '#6f7a8f'], tint: '236,239,244', track: '#4c566a', topbar: 'rgba(36,41,51,0.86)', sidebar: 'rgba(41,46,57,0.72)' },
  light:    { name: 'Light', bg: '#f4f4f5', surface: '#ffffff', surface2: '#ffffff', input: '#f7f7f9', text: ['#18181b', '#52525b', '#8e8e98'], tint: '24,24,27', track: '#d4d4d8', topbar: 'rgba(244,244,245,0.86)', sidebar: 'rgba(250,250,251,0.82)', light: true },
};
const FONTS = {
  inter:   { label: 'Inter', css: "'Inter', -apple-system, 'Segoe UI', sans-serif" },
  segoe:   { label: 'Segoe', css: "'Segoe UI Variable Text', 'Segoe UI', system-ui, sans-serif" },
  mono:    { label: 'Mono', css: "'JetBrains Mono', Consolas, monospace" },
  poppins: { label: 'Poppins', css: "'Poppins', 'Segoe UI', sans-serif", url: 'https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap' },
  nunito:  { label: 'Nunito', css: "'Nunito', 'Segoe UI', sans-serif", url: 'https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap' },
};
const SEGMENTS = {
  font: Object.entries(FONTS).map(([k, f]) => [k, f.label]),
  font_size: [[14, 'XS'], [15, 'S'], [16, 'M'], [17, 'L'], [18, 'XL']],
  radius: [['sharp', 'Eckig'], ['normal', 'Normal'], ['round', 'Rund']],
  density: [['compact', 'Kompakt'], ['normal', 'Normal'], ['cozy', 'Luftig']],
  pattern: [['none', 'Schlicht'], ['grid', 'Raster'], ['dots', 'Punkte'], ['aurora', 'Aurora'], ['noise', 'Körnung']],
  card_style: [['solid', 'Solid'], ['glass', 'Glas'], ['outline', 'Outline'], ['elevated', 'Schwebend']],
  contrast: [['normal', 'Normal'], ['high', 'Hoch']],
  button_shape: [['normal', 'Normal'], ['pill', 'Pill']],
  label_case: [['upper', 'GROSS'], ['normal', 'Normal']],
  sidebar_side: [['left', 'Links'], ['right', 'Rechts']],
  sidebar_width: [['compact', 'Schmal'], ['normal', 'Normal'], ['wide', 'Breit']],
  scrollbar: [['normal', 'Normal'], ['thin', 'Dünn'], ['hidden', 'Versteckt']],
  transition: [['pop', 'Pop'], ['slide', 'Slide'], ['zoom', 'Zoom'], ['blur', 'Blur'], ['none', 'Aus']],
  motion_speed: [['fast', 'Schnell'], ['normal', 'Normal'], ['slow', 'Langsam']],
  welcome_style: [['minimal', 'Minimal'], ['stats', 'Mit Infos']],
  welcome_duration: [[1500, '1,5 s'], [2500, '2,5 s'], [4000, '4 s'], [0, 'Bis Klick']],
  toasts: [['all', 'Alle'], ['errors', 'Nur Fehler'], ['off', 'Aus']],
  toast_pos: [['top-right', 'Oben rechts'], ['bottom-right', 'Unten rechts'], ['bottom-center', 'Unten Mitte']],
  toast_duration: [[3, '3 s'], [5, '5 s'], [8, '8 s']],
  clock_format: [['24', '24 h'], ['12', '12 h']],
};
const DASH_SECTIONS = [['hero', 'Kopfbereich'], ['metrics', 'Kennzahlen'], ['monitor', 'Live-Monitor'], ['bottom', 'Signatur & Schnellaktionen']];

const viewIdOf = btn => btn.getAttribute('onclick').match(/'([^']+)'/)[1];

function initSettingsUI() {
  document.querySelectorAll('#settings-tabs button').forEach(b => b.addEventListener('click', () => {
    TactileAudio.click(190);
    switchSettingsTab(b.dataset.tab);
  }));
  switchSettingsTab('look');

  const themes = document.getElementById('set-themes');
  Object.entries(THEMES).forEach(([key, t]) => {
    const tile = document.createElement('button');
    tile.className = 'theme-tile';
    tile.dataset.theme = key;
    tile.innerHTML = `<div class="theme-preview" style="background:${t.bg}; border:1px solid rgba(${t.tint},0.12);">
        <i style="background:${t.surface2}; width:70%;"></i><i style="background:rgba(${t.tint},0.35); width:45%;"></i><i style="background:${t.surface}; width:85%;"></i>
      </div>${t.name}`;
    tile.addEventListener('click', () => saveSetting({ theme: key }));
    themes.appendChild(tile);
  });

  document.querySelectorAll('.seg[data-key]').forEach(seg => {
    SEGMENTS[seg.dataset.key].forEach(([value, label]) => {
      const b = document.createElement('button');
      b.textContent = label;
      b.dataset.value = value;
      b.addEventListener('click', () => saveSetting({ [seg.dataset.key]: value }));
      seg.appendChild(b);
    });
  });

  document.querySelectorAll('[data-toggle]').forEach(input => {
    input.addEventListener('change', () => saveSetting({ [input.dataset.toggle]: input.checked }));
  });

  const modules = document.getElementById('set-modules');
  document.querySelectorAll('.nav-btn').forEach(btn => {
    const id = viewIdOf(btn);
    if (id === 'view-dash' || id === 'view-settings') return;
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" value="${id}"> ${esc(btn.querySelector('span').textContent.replace(/^\d+ \/\/ /, ''))}`;
    label.querySelector('input').addEventListener('change', () => {
      const hidden = [...modules.querySelectorAll('input:not(:checked)')].map(i => i.value);
      saveSetting({ hidden_views: hidden });
    });
    modules.appendChild(label);
  });

  const dash = document.getElementById('set-dash-sections');
  DASH_SECTIONS.forEach(([key, name]) => {
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" value="${key}"> ${name}`;
    label.querySelector('input').addEventListener('change', () => {
      saveSetting({ dash_hidden: [...dash.querySelectorAll('input:not(:checked)')].map(i => i.value) });
    });
    dash.appendChild(label);
  });

  const swatches = document.getElementById('set-swatches');
  ACCENTS.forEach(color => {
    const s = document.createElement('button');
    s.className = 'swatch';
    s.dataset.color = color;
    s.style.background = color;
    s.title = color;
    s.addEventListener('click', () => setTheme(color));
    swatches.appendChild(s);
  });
  const start = document.getElementById('set-start');
  document.querySelectorAll('.nav-btn').forEach(btn => {
    const opt = document.createElement('option');
    opt.value = btn.getAttribute('onclick').match(/'([^']+)'/)[1];
    opt.textContent = btn.querySelector('span').textContent;
    start.appendChild(opt);
  });
}

function hexRgb(hex) {
  const n = parseInt(hex.slice(1), 16);
  return [n >> 16, (n >> 8) & 255, n & 255];
}

function glowFor(hex, light) {
  const alpha = light ? 0.1 : (hex === '#ffffff' ? 0.14 : 0.22);
  return `rgba(${hexRgb(hex).join(', ')}, ${alpha})`;
}

// Textfarbe auf Akzent-Flächen: Schwarz oder Weiß, je nachdem was mehr WCAG-Kontrast ergibt
function onAccentFor(hex) {
  const lin = c => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
  const [r, g, b] = hexRgb(hex);
  const L = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  return 1.05 / (L + 0.05) > (L + 0.05) / 0.05 ? '#ffffff' : '#050506';
}

function mixHex(a, b) {
  const [x, y] = [hexRgb(a), hexRgb(b)];
  return '#' + x.map((v, i) => Math.round((v + y[i]) / 2).toString(16).padStart(2, '0')).join('');
}

function applyAccent(hex) {
  const theme = THEMES[settings.theme] || THEMES.midnight;
  // Weiß als Akzent wäre auf dem Light-Theme unsichtbar, dort wird daraus Fast-Schwarz
  const effective = theme.light && hex === '#ffffff' ? '#18181b' : hex;
  const gradient = settings.accent_gradient;
  const fill = gradient ? `linear-gradient(135deg, ${effective}, ${settings.accent2})` : effective;
  const root = document.documentElement.style;
  root.setProperty('--accent', effective);
  root.setProperty('--accent-2', settings.accent2);
  root.setProperty('--accent-fill', fill);
  root.setProperty('--name-fill', gradient ? fill : `linear-gradient(135deg, var(--text-primary) 15%, ${effective})`);
  root.setProperty('--accent-glow', glowFor(effective, theme.light));
  // Bei Verlauf die Textfarbe an der Mischfarbe beider Enden ausrichten
  root.setProperty('--on-accent', onAccentFor(gradient ? mixHex(effective, settings.accent2) : effective));
  document.getElementById('set-accent').value = hex;
  document.getElementById('set-accent2').value = settings.accent2;
  document.querySelectorAll('.swatch').forEach(s => s.classList.toggle('active', s.dataset.color === hex));
  renderSparks();
}

function loadFont(font) {
  if (!font.url || document.querySelector(`link[href="${font.url}"]`)) return;
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = font.url;
  document.head.appendChild(link);
}

function applyUi() {
  const t = THEMES[settings.theme] || THEMES.midnight;
  const root = document.documentElement.style;
  const k = t.light
    ? { b: 0.1, s: 0.22, t1: 0.025, t2: 0.045, t3: 0.075, t4: 0.16, t5: 0.3, spot: 0.03, pat: 0.07 }
    : { b: 0.08, s: 0.2, t1: 0.018, t2: 0.035, t3: 0.065, t4: 0.12, t5: 0.25, spot: 0.045, pat: 0.035 };
  const high = settings.contrast === 'high';
  if (high) ['b', 's', 't1', 't2', 't3'].forEach(key => k[key] *= 1.7);
  const tint = a => `rgba(${t.tint}, ${Math.min(a, 0.6)})`;
  // Hoher Kontrast: Sekundärtext näher an die Hauptfarbe, gedämpfter Text bekommt die alte Sekundärfarbe
  const text2 = high ? `color-mix(in srgb, ${t.text[0]} 75%, ${t.text[1]})` : t.text[1];
  const text3 = high ? t.text[1] : t.text[2];
  Object.entries({
    '--bg': t.bg, '--surface': t.surface, '--surface-2': t.surface2, '--input-bg': t.input,
    '--text-primary': t.text[0], '--text-secondary': text2, '--text-muted': text3,
    '--shadow': t.light ? '0 8px 28px rgba(24, 24, 27, 0.09)' : '0 12px 34px rgba(0, 0, 0, 0.5)',
    '--noise-opacity': t.light ? 0.05 : 0.07,
    '--border': tint(k.b), '--border-strong': tint(k.s),
    '--tint-1': tint(k.t1), '--tint-2': tint(k.t2), '--tint-3': tint(k.t3), '--tint-4': tint(k.t4), '--tint-5': tint(k.t5),
    '--spot': tint(k.spot), '--pattern-line': tint(k.pat), '--track': t.track,
    '--topbar-bg': t.topbar, '--sidebar-bg': t.sidebar, '--danger-text': t.light ? '#dc2626' : '#f87171',
  }).forEach(([name, value]) => root.setProperty(name, value));
  root.colorScheme = t.light ? 'light' : 'dark';  // native Dropdowns und Scrollbalken passend einfärben

  const font = FONTS[settings.font] || FONTS.inter;
  loadFont(font);
  root.setProperty('--font-ui', font.css);
  root.fontSize = `${settings.font_size}px`;
  root.setProperty('--rs', { sharp: 0.3, normal: 1, round: 1.7 }[settings.radius]);
  const density = { compact: ['11px 13px', '9px'], normal: ['16px 18px', '14px'], cozy: ['22px 24px', '18px'] }[settings.density];
  root.setProperty('--card-pad', density[0]);
  root.setProperty('--gap', density[1]);

  root.setProperty('--sidebar-w', { compact: '196px', normal: '240px', wide: '290px' }[settings.sidebar_width]);
  root.setProperty('--speed', { fast: 0.6, normal: 1, slow: 1.6 }[settings.motion_speed]);
  root.setProperty('--enter', `enter-${settings.transition}`);

  const body = document.body;
  body.classList.toggle('no-glow', !settings.glow);
  body.classList.toggle('no-anim', !settings.animations);
  body.classList.toggle('no-console', !settings.show_console);
  ['glass', 'outline', 'elevated'].forEach(s => body.classList.toggle(`card-${s}`, settings.card_style === s));
  body.classList.toggle('btn-pill', settings.button_shape === 'pill');
  body.classList.toggle('sidebar-right', settings.sidebar_side === 'right');
  body.classList.toggle('labels-normal', settings.label_case === 'normal');
  body.classList.toggle('no-mono', !settings.mono_values);
  body.classList.toggle('scroll-thin', settings.scrollbar === 'thin');
  body.classList.toggle('scroll-hidden', settings.scrollbar === 'hidden');
  body.classList.toggle('hover-lift', settings.hover_lift);
  document.getElementById('bg-fx').className = ['aurora', 'noise'].includes(settings.pattern) ? settings.pattern : '';
  document.getElementById('toast-stack').className = `toast-stack ${settings.toast_pos}`;
  const layers = [];
  if (settings.glow) layers.push(['radial-gradient(ellipse 80% 45% at 50% -15%, var(--accent-glow), transparent)', 'auto']);
  if (settings.pattern === 'grid') {
    layers.push(['linear-gradient(var(--pattern-line) 1px, transparent 1px)', '32px 32px']);
    layers.push(['linear-gradient(90deg, var(--pattern-line) 1px, transparent 1px)', '32px 32px']);
  } else if (settings.pattern === 'dots') {
    layers.push(['radial-gradient(var(--tint-4) 1px, transparent 1.6px)', '20px 20px']);
  }
  body.style.backgroundImage = layers.map(l => l[0]).join(', ') || 'none';
  body.style.backgroundSize = layers.map(l => l[1]).join(', ') || 'auto';

  document.querySelector('.brand-name').textContent = settings.brand_name;
  document.querySelector('.version-pill').textContent = settings.brand_tag;
  document.title = settings.brand_name;

  document.querySelectorAll('.nav-btn').forEach(btn => {
    const span = btn.querySelector('span');
    if (!span.dataset.full) span.dataset.full = span.textContent;
    span.textContent = settings.nav_numbers ? span.dataset.full : span.dataset.full.replace(/^\d+ \/\/ /, '');
    btn.style.display = settings.hidden_views.includes(viewIdOf(btn)) ? 'none' : '';
  });
  const active = document.querySelector('.view-panel.active');
  if (active && settings.hidden_views.includes(active.id)) goView('view-dash');
  DASH_SECTIONS.forEach(([key]) => {
    document.getElementById(`dash-${key}`).style.display = settings.dash_hidden.includes(key) ? 'none' : '';
  });
}

function syncSettingsControls() {
  document.querySelectorAll('.theme-tile').forEach(tile => tile.classList.toggle('active', tile.dataset.theme === settings.theme));
  document.querySelectorAll('.seg[data-key]').forEach(seg => {
    seg.querySelectorAll('button').forEach(b => b.classList.toggle('active', b.dataset.value === String(settings[seg.dataset.key])));
  });
  document.querySelectorAll('[data-toggle]').forEach(input => input.checked = !!settings[input.dataset.toggle]);
  document.querySelectorAll('#set-modules input').forEach(i => i.checked = !settings.hidden_views.includes(i.value));
  document.querySelectorAll('#set-dash-sections input').forEach(i => i.checked = !settings.dash_hidden.includes(i.value));
  const brand = document.getElementById('set-brand');
  const tag = document.getElementById('set-brand-tag');
  const welcomeName = document.getElementById('set-welcome-name');
  if (document.activeElement !== brand) brand.value = settings.brand_name;
  if (document.activeElement !== tag) tag.value = settings.brand_tag;
  if (document.activeElement !== welcomeName) welcomeName.value = settings.welcome_name;
  document.getElementById('design-code').value = designCode();
  document.getElementById('set-sound').checked = settings.sound;
  document.getElementById('set-start').value = settings.start_view;
  document.getElementById('set-monitor').value = settings.monitor_interval;
  document.getElementById('set-refresh').value = settings.refresh_interval;
}

function applySettings() {
  applyUi();
  applyAccent(settings.accent);
  TactileAudio.enabled = settings.sound;
  document.getElementById('audio-toggle').innerText = `Sound: ${settings.sound ? 'On' : 'Off'}`;
  syncSettingsControls();
  restartRefreshTimer();
}

function designCode() {
  const design = Object.fromEntries(DESIGN_KEYS.map(k => [k, settings[k]]));
  return `NEXUS-${btoa(JSON.stringify(design))}`;
}

async function copyDesignCode() {
  await copyText(designCode());
  TactileAudio.done();
  log('Design-Code kopiert – schick ihn deinen Freunden.', true);
}

async function applyDesignCode() {
  const input = document.getElementById('design-code-in');
  let design;
  try {
    design = JSON.parse(atob(input.value.trim().replace(/^NEXUS-/, '')));
  } catch (e) {
    log('Das ist kein gültiger Design-Code.', 'error');
    return;
  }
  const patch = Object.fromEntries(Object.entries(design || {}).filter(([k]) => DESIGN_KEYS.includes(k)));
  if (!Object.keys(patch).length) {
    log('Der Design-Code enthält keine Design-Einstellungen.', 'error');
    return;
  }
  await saveSetting(patch);
  input.value = '';
  TactileAudio.done();
  log('Design übernommen.', true);
}

async function resetDesign() {
  if (!await nexusConfirm('Theme, Farben, Schrift, Layout und Animationen gehen auf den Standard zurück. Name, Module und Daten bleiben.',
    { title: 'Design zurücksetzen?', confirm: 'Zurücksetzen', danger: true })) return;
  await saveSetting(DEFAULT_DESIGN);
  log('Design zurückgesetzt.', true);
}

const speedFactor = () => settings.animations ? ({ fast: 0.6, normal: 1, slow: 1.6 }[settings.motion_speed] || 1) : 0;

function fmtClock(date, withSeconds = settings.clock_seconds) {
  const h12 = settings.clock_format === '12';
  return date.toLocaleTimeString(h12 ? 'en-US' : 'de-DE',
    { hour: '2-digit', minute: '2-digit', second: withSeconds ? '2-digit' : undefined, hour12: h12 });
}

// ---------------- Einstellungs-Tabs & Übergänge ----------------
function switchSettingsTab(tab) {
  document.querySelectorAll('#settings-tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('#view-settings [data-stab]').forEach(el => el.style.display = el.dataset.stab === tab ? '' : 'none');
  animateView(document.getElementById('view-settings'));
}

// Karten einer Ansicht nacheinander einblenden (Stil und Tempo aus den Einstellungen)
function animateView(panel) {
  if (!panel || !panel.classList.contains('active') || !settings.animations || settings.transition === 'none') return;
  panel.classList.remove('entering');
  const items = [];
  [...panel.children].filter(el => el.style.display !== 'none').forEach(el => {
    if (/\bgrid-[234]\b/.test(el.className)) items.push(...el.children);
    else items.push(el);
  });
  items.forEach((el, i) => {
    el.classList.add('enter-item');
    el.style.setProperty('--i', Math.min(i, 10));
  });
  void panel.offsetWidth;  // Reflow erzwingen, sonst startet die Animation nicht neu
  panel.classList.add('entering');
  clearTimeout(panel._enterTimer);
  panel._enterTimer = setTimeout(() => panel.classList.remove('entering'), (600 + Math.min(items.length, 10) * 55) * speedFactor() + 100);
}

// ---------------- Dialoge (Ersatz für confirm) ----------------
function nexusConfirm(text, { title = 'Bist du sicher?', confirm = 'Fortfahren', danger = false } = {}) {
  const back = document.getElementById('modal');
  const ok = document.getElementById('modal-ok');
  const cancel = document.getElementById('modal-cancel');
  back.querySelector('.modal').classList.toggle('danger', danger);
  setText('modal-icon', danger ? '!' : '?');
  setText('modal-title', title);
  setText('modal-text', text);
  ok.textContent = confirm;
  back.classList.add('open');
  setTimeout(() => ok.focus(), 60);
  return new Promise(resolve => {
    const finish = (value) => {
      back.classList.remove('open');
      document.removeEventListener('keydown', onKey, true);
      ok.onclick = cancel.onclick = back.onclick = null;
      TactileAudio.click(value ? 210 : 130);
      resolve(value);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        finish(false);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        finish(document.activeElement !== cancel);
      }
    };
    ok.onclick = () => finish(true);
    cancel.onclick = () => finish(false);
    back.onclick = (e) => { if (e.target === back) finish(false); };
    document.addEventListener('keydown', onKey, true);
  });
}

function previewDialog() {
  nexusConfirm('So sehen Rückfragen im Tool aus. Enter bestätigt, Esc oder ein Klick daneben bricht ab.',
    { title: 'Dialog-Vorschau', confirm: 'Verstanden' });
}

// ---------------- Toasts ----------------
let toastsReady = false;  // erst nach dem Welcome-Screen, sonst stapeln sich Start-Meldungen

function toast(message, type = 'info', force = false) {
  if (!force && (!toastsReady || settings.toasts === 'off' || (settings.toasts === 'errors' && type !== 'error'))) return;
  const stack = document.getElementById('toast-stack');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon">${{ ok: '✓', error: '!', info: 'i' }[type]}</span><div style="flex:1;"></div><div class="toast-bar"></div>`;
  el.children[1].textContent = message;
  const ms = settings.toast_duration * 1000;
  const bar = el.querySelector('.toast-bar');
  bar.style.animationDuration = `${ms}ms`;
  let timer;
  const close = () => {
    if (el.classList.contains('leaving')) return;
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 260 * speedFactor() + 20);
  };
  el.addEventListener('click', close);
  el.addEventListener('mouseenter', () => { clearTimeout(timer); bar.style.animationPlayState = 'paused'; });
  el.addEventListener('mouseleave', () => { timer = setTimeout(close, 1500); bar.style.animationPlayState = 'running'; });
  stack.appendChild(el);
  timer = setTimeout(close, ms);
  while (stack.children.length > 4) stack.firstElementChild.remove();
}

// ---------------- Welcome-Screen ----------------
let welcomeTimer = null;

function greetingFor(hour) {
  if (hour < 5) return 'Noch wach';
  if (hour < 11) return 'Guten Morgen';
  if (hour < 17) return 'Hallo';
  if (hour < 22) return 'Guten Abend';
  return 'Gute Nacht';
}

async function showWelcome() {
  const el = document.getElementById('welcome');
  clearTimeout(welcomeTimer);
  let info = null;
  try {
    info = await api('/api/welcome');
  } catch (e) {
    // ohne Infos trotzdem begrüßen
  }
  const name = settings.welcome_name || ((info && info.name) || '').split(/\s+/)[0];
  const now = new Date();
  document.getElementById('welcome-greet').innerHTML = `${greetingFor(now.getHours())}${name ? `, <span class="name">${esc(name)}</span>` : ''}`;
  document.getElementById('welcome-sub').innerHTML = info ? `Willkommen zurück an <b>${esc(info.pc)}</b>` : 'Willkommen zurück';
  setText('welcome-date', `${now.toLocaleDateString('de-DE', { weekday: 'long', day: 'numeric', month: 'long' })} · ${fmtClock(now, false)}`);

  const chips = document.getElementById('welcome-chips');
  chips.innerHTML = '';
  if (info && settings.welcome_style === 'stats') {
    const items = [['Online seit', info.uptime], ['RAM', `${info.ram} %`], ['C: frei', `${info.disk_free} GB`]];
    if (info.reminder) items.push(['Erinnerung', `${fmtClock(new Date(info.reminder.due * 1000), false)} · ${info.reminder.text}`]);
    if (info.automations) items.push(['Automationen', `${info.automations} aktiv`]);
    items.forEach(([label, value], i) => {
      const chip = document.createElement('span');
      chip.className = 'welcome-chip w-item';
      chip.style.setProperty('--d', `${480 + i * 70}ms`);
      chip.innerHTML = `${esc(label)}<b>${esc(value)}</b>`;
      chips.appendChild(chip);
    });
  }

  // Animationen neu starten (wichtig für die Vorschau aus den Einstellungen)
  el.querySelectorAll('.w-item, .welcome-progress i').forEach(item => {
    item.style.animation = 'none';
    void item.offsetWidth;
    item.style.animation = '';
  });
  const duration = settings.welcome_duration;
  const progress = document.getElementById('welcome-progress');
  progress.style.visibility = duration ? 'visible' : 'hidden';
  progress.querySelector('i').style.animationDuration = `${duration + 900}ms`;
  el.classList.remove('booting', 'leaving');
  el.style.display = 'flex';

  const close = () => {
    clearTimeout(welcomeTimer);
    document.removeEventListener('keydown', onKey, true);
    el.onclick = null;
    el.classList.add('leaving');
    setTimeout(() => {
      el.style.display = 'none';
      toastsReady = true;
      animateView(document.querySelector('.view-panel.active'));
    }, 600 * speedFactor());
  };
  const onKey = (e) => {
    if (['Enter', 'Escape', ' '].includes(e.key)) {
      e.preventDefault();
      e.stopPropagation();
      close();
    }
  };
  el.onclick = close;
  document.addEventListener('keydown', onKey, true);
  if (duration) welcomeTimer = setTimeout(close, duration + 900);
}

function hideWelcomeNow() {
  const el = document.getElementById('welcome');
  el.classList.remove('booting');
  el.classList.add('leaving');
  setTimeout(() => { el.style.display = 'none'; }, 300);
  toastsReady = true;
}

async function saveSetting(patch) {
  settings = await api('/api/settings_save', patch);
  applySettings();
  TactileAudio.click(220);
}

async function loadAutostart() {
  const st = await api('/api/autostart_get');
  document.getElementById('set-autostart').checked = st.enabled;
}

async function toggleAutostart(input) {
  try {
    const res = await api('/api/autostart_set', { enable: input.checked });
    input.checked = res.enabled;
    TactileAudio.done();
    log(res.enabled ? 'NEXUS startet ab jetzt mit Windows.' : 'Autostart mit Windows entfernt.', true);
  } catch (e) {
    input.checked = !input.checked;
    throw e;
  }
}

async function exportUserData() {
  const data = await api('/api/user_data_export');
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `nexusos-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  TactileAudio.done();
  log(`Sicherung „${a.download}“ in den Downloads gespeichert.`, true);
}

async function importUserData(input) {
  const file = input.files[0];
  input.value = '';
  if (!file) return;
  let data;
  try {
    data = JSON.parse(await file.text());
  } catch (e) {
    log('Die Datei ist kein gültiges JSON.', 'error');
    return;
  }
  if (!await nexusConfirm('Vorhandene Workspaces, Notizen, Befehle usw. werden durch den Inhalt der Datei ersetzt.',
    { title: 'Sicherung importieren?', confirm: 'Importieren', danger: true })) return;
  const res = await api('/api/user_data_import', { data });
  await loadUserData(true);
  TactileAudio.done();
  log(`Importiert: ${res.imported.join(', ')}`, true);
}

async function openDataFolder() {
  await api('/api/open_data_folder');
  TactileAudio.click();
}

// ---------------- Fokus-Timer (nutzt die Erinnerungen für das Popup) ----------------
let focus = null;  // { end, total, label, reminderId }

function storeFocus() {
  try {
    if (focus) localStorage.setItem('nexus-focus', JSON.stringify(focus));
    else localStorage.removeItem('nexus-focus');
  } catch (e) {}
}

function restoreFocus() {
  try {
    const saved = JSON.parse(localStorage.getItem('nexus-focus') || 'null');
    if (saved && saved.end > Date.now()) focus = saved;
  } catch (e) {}
}

async function startFocus(minutes, label) {
  if (focus) await stopFocus(true);
  const text = label === 'Fokus' ? `Fokus-Zeit (${minutes} min) vorbei – Zeit für eine Pause!` : 'Pause vorbei – weiter geht’s!';
  const res = await api('/api/reminder_add', { text, minutes });
  userData.reminders = res.reminders;
  renderReminders();
  const rem = res.reminders.filter(r => r.text === text).sort((a, b) => b.due - a.due)[0];
  focus = { end: rem.due * 1000, total: minutes * 60000, label, reminderId: rem.id };
  storeFocus();
  renderFocus();
  TactileAudio.done();
  log(`${label} gestartet: ${minutes} min`, true);
}

async function stopFocus(silent = false) {
  if (!focus) return;
  const id = focus.reminderId;
  focus = null;
  storeFocus();
  renderFocus();
  const res = await api('/api/reminder_delete', { id });
  userData.reminders = res.reminders;
  renderReminders();
  if (!silent) log('Fokus-Timer gestoppt.');
}

function renderFocus() {
  const bar = document.getElementById('focus-bar');
  if (!focus) {
    if (document.getElementById('focus-phase').innerText !== 'FERTIG') {
      setText('focus-clock', '25:00');
      setText('focus-phase', 'BEREIT');
      bar.style.width = '0%';
    }
    return;
  }
  const left = Math.max(0, focus.end - Date.now());
  const secs = Math.ceil(left / 1000);
  setText('focus-clock', `${String(Math.floor(secs / 60)).padStart(2, '0')}:${String(secs % 60).padStart(2, '0')}`);
  setText('focus-phase', focus.label.toUpperCase());
  bar.style.width = `${(1 - left / focus.total) * 100}%`;
  if (left === 0) {
    log(`${focus.label} vorbei.`, true);
    focus = null;
    storeFocus();
    setText('focus-phase', 'FERTIG');
    TactileAudio.done();
  }
}

// ---------------- Systeminfo, Speicherfresser, Schnellordner ----------------
let sysInfoRows = null;

async function loadSystemInfo() {
  const res = await api('/api/system_info');
  sysInfoRows = res.rows;
  const tbody = document.getElementById('sysinfo-body');
  tbody.innerHTML = '';
  sysInfoRows.forEach(([key, value]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td style="font-family:var(--font-ui); color:var(--text-secondary); width:150px;">${esc(key)}</td><td>${esc(value)}</td>`;
    tbody.appendChild(tr);
  });
}

async function copySystemInfo() {
  if (!sysInfoRows) await loadSystemInfo();
  await copyText(sysInfoRows.map(([k, v]) => `${k}: ${v}`).join('\n'));
  TactileAudio.done();
  log('Systeminfo in die Zwischenablage kopiert.', true);
}

async function scanFolderSizes() {
  const path = document.getElementById('sort-path').value.trim();
  setLoading(true, "MEASURING FOLDERS...");
  const res = await api('/api/folder_sizes', { path });
  setLoading(false);
  TactileAudio.done();
  const box = document.getElementById('size-results');
  box.innerHTML = '';
  if (res.error) {
    box.innerHTML = `<div class="list-sub" style="color:var(--status-danger)">${esc(res.error)}</div>`;
    return;
  }
  const max = Math.max(1, ...res.entries.map(e => e.size));
  const head = document.createElement('div');
  head.className = 'list-sub';
  head.textContent = `${fmtBytes(res.total)} in ${res.folder}${res.partial ? ' · nach 20 s abgebrochen, Werte unvollständig' : ''}`;
  box.appendChild(head);
  res.entries.forEach(e => {
    const row = document.createElement('div');
    row.className = 'size-row';
    const files = e.files === null ? '' : ` · ${e.files.toLocaleString('de-DE')} Dateien`;
    row.innerHTML = `<div class="size-main" title="${esc(e.path)}">
        <div class="size-head"><span class="name">${esc(e.name)}</span><span class="val">${fmtBytes(e.size)}${files}</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:${(e.size / max) * 100}%"></div></div>
      </div>
      <button class="btn-secondary btn-mini">Zeigen</button>`;
    row.querySelector('button').addEventListener('click', () => revealFile(e.path));
    box.appendChild(row);
  });
  log(`Ordner analysiert: ${fmtBytes(res.total)} in ${res.folder}`, true);
}

async function openPlace(key) {
  await api('/api/open_place', { key });
  TactileAudio.click();
}

// ---------------- Automationen ----------------
let automations = [];
let editingAutoId = null;
const DAY_NAMES = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So'];
const PLAN_NAMES = { high: 'Höchstleistung', ultimate: 'Ultimative Leistung', balanced: 'Ausbalanciert', saver: 'Energiesparen' };
const AUTO_PRESETS = [
  { label: 'Gaming-Modus an', name: 'Gaming-Modus an', trigger: { type: 'process_start' }, action: { type: 'power_plan', target: 'high' } },
  { label: 'Gaming-Modus aus', name: 'Gaming-Modus aus', trigger: { type: 'process_stop' }, action: { type: 'power_plan', target: 'balanced' } },
  { label: 'Kein Standby beim Zocken', name: 'Kein Standby beim Zocken', trigger: { type: 'process_start' }, action: { type: 'caffeine_on' } },
  { label: 'Downloads stündlich sortieren', name: 'Downloads aufräumen', trigger: { type: 'interval', minutes: 60 }, action: { type: 'sort_downloads' } },
  { label: 'Feierabend-Popup', name: 'Feierabend', trigger: { type: 'daily', time: '18:00', days: [0, 1, 2, 3, 4] }, action: { type: 'popup', target: 'Feierabend! Zeit, den PC zuzumachen.' } },
  { label: 'Temp beim Start leeren', name: 'Temp aufräumen', trigger: { type: 'startup' }, action: { type: 'clean_temp' } },
];

function describeTrigger(t) {
  if (t.type === 'process_start') return `${t.process} startet`;
  if (t.type === 'process_stop') return `${t.process} beendet wird`;
  if (t.type === 'daily') return `${t.days.length === 7 ? 'täglich' : t.days.map(d => DAY_NAMES[d]).join(', ')} um ${t.time}`;
  if (t.type === 'interval') return `alle ${t.minutes} min`;
  return 'NEXUS startet';
}

function describeAction(a) {
  const ws = userData.workspaces.find(x => x.id === a.target);
  const cmd = userData.commands.find(x => x.id === a.target);
  return {
    power_plan: `Energieplan: ${PLAN_NAMES[a.target]}`,
    caffeine_on: 'Caffeine an',
    caffeine_off: 'Caffeine aus',
    workspace: `Workspace „${ws ? ws.name : '?'}“ öffnen`,
    command: `Befehl „${cmd ? cmd.name : '?'}“ ausführen`,
    popup: `Popup: ${a.target}`,
    sort_downloads: 'Downloads sortieren',
    clean_temp: 'Temp bereinigen',
  }[a.type];
}

async function loadAutomations() {
  const res = await api('/api/automations');
  automations = res.automations;
  renderAutomations();
  renderAutoLog(res.log);
}

async function loadProcessNames() {
  const res = await api('/api/process_names');
  document.getElementById('proc-names').innerHTML = res.names.map(n => `<option value="${esc(n)}">`).join('');
}

function renderAutomations() {
  const list = document.getElementById('auto-list');
  const active = automations.filter(a => a.enabled).length;
  setText('auto-count', `${active} AKTIV`);
  setText('nav-auto-badge', active ? `${active} ON` : 'FLOW');
  list.innerHTML = '';
  if (!automations.length) {
    list.innerHTML = '<div class="list-sub">Noch keine Automationen. Rechts anlegen oder unten eine Idee übernehmen.</div>';
  }
  automations.forEach(a => {
    const row = document.createElement('div');
    row.className = 'list-row';
    row.style.opacity = a.enabled ? '1' : '0.55';
    row.innerHTML = `<label class="switch" title="An/Aus"><input type="checkbox" ${a.enabled ? 'checked' : ''}><span class="slider"></span></label>
      <div class="grow"><b>${esc(a.name)}</b><div class="list-sub">Wenn ${esc(describeTrigger(a.trigger))} → ${esc(describeAction(a.action))}</div></div>
      <button class="btn-secondary btn-mini" title="Aktion jetzt einmal ausführen">Test</button>
      <button class="btn-secondary btn-mini">Bearbeiten</button>
      <button class="btn-danger btn-mini" title="Löschen">×</button>`;
    const [test, edit, del] = row.querySelectorAll('button');
    row.querySelector('input').addEventListener('change', (e) => toggleAutomation(a, e.target));
    test.addEventListener('click', () => runAutomationNow(a));
    edit.addEventListener('click', () => fillAutomationForm(a, a.id));
    del.addEventListener('click', () => deleteAutomation(a));
    list.appendChild(row);
  });

  const presets = document.getElementById('auto-presets');
  if (!presets.children.length) {
    AUTO_PRESETS.forEach(p => {
      const btn = document.createElement('button');
      btn.className = 'btn-secondary btn-mini';
      btn.textContent = `+ ${p.label}`;
      btn.addEventListener('click', () => fillAutomationForm(p, null));
      presets.appendChild(btn);
    });
  }
}

function renderAutoLog(entries) {
  const box = document.getElementById('auto-log');
  box.innerHTML = '';
  if (!entries.length) {
    box.innerHTML = '<div class="list-sub">Noch nichts ausgeführt.</div>';
    return;
  }
  entries.forEach(e => {
    const row = document.createElement('div');
    row.className = 'list-row';
    row.innerHTML = `<span style="color:${e.ok ? 'var(--status-ok)' : 'var(--status-warn)'}; font-weight:700; width:14px;">${e.ok ? '✓' : '⚠'}</span>
      <div class="grow"><b>${esc(e.name)}</b><div class="list-sub">${esc(e.reason)} → ${esc(e.result)}</div></div>
      <span class="list-sub" style="flex-shrink:0;">${esc(e.time)}</span>`;
    box.appendChild(row);
  });
}

function renderAutoFields(which) {
  if (which !== 'action') {
    const t = document.getElementById('auto-trigger').value;
    const box = document.getElementById('auto-trigger-fields');
    if (t === 'process_start' || t === 'process_stop') {
      box.innerHTML = '<input type="text" id="auto-process" class="mono" list="proc-names" placeholder="Programm, z.B. valorant.exe (Vorschläge = gerade laufende Prozesse)">';
    } else if (t === 'daily') {
      box.innerHTML = `<div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
        <input type="text" id="auto-time" class="mono" placeholder="HH:MM" maxlength="5" style="width:80px;">
        ${DAY_NAMES.map((d, i) => `<label style="display:flex; align-items:center; gap:4px; margin:0; cursor:pointer;"><input type="checkbox" class="auto-day" value="${i}" ${i < 5 ? 'checked' : ''}>${d}</label>`).join('')}
      </div>`;
    } else if (t === 'interval') {
      box.innerHTML = '<input type="number" id="auto-minutes" class="mono" min="5" max="1440" value="60" placeholder="Minuten (5–1440)">';
    } else {
      box.innerHTML = '';
    }
  }
  if (which !== 'trigger') {
    const a = document.getElementById('auto-action').value;
    const box = document.getElementById('auto-action-fields');
    const options = (items) => items.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('');
    if (a === 'power_plan') {
      box.innerHTML = `<select id="auto-target">${options(Object.entries(PLAN_NAMES))}</select>`;
    } else if (a === 'workspace' || a === 'command') {
      const items = a === 'workspace' ? userData.workspaces : userData.commands;
      box.innerHTML = items.length
        ? `<select id="auto-target">${options(items.map(x => [x.id, x.name]))}</select>`
        : `<div class="list-sub" style="white-space:normal;">Noch keine ${a === 'workspace' ? 'Workspaces (Alltag & Automatik)' : 'Befehle (Custom Commands)'} angelegt.</div>`;
    } else if (a === 'popup') {
      box.innerHTML = '<input type="text" id="auto-target" maxlength="200" placeholder="Text der Nachricht">';
    } else {
      box.innerHTML = '';
    }
  }
}

function fillAutomationForm(a, id) {
  editingAutoId = id;
  document.getElementById('auto-name').value = a.name || '';
  document.getElementById('auto-trigger').value = a.trigger.type;
  document.getElementById('auto-action').value = a.action.type;
  renderAutoFields();
  const t = a.trigger;
  if (t.process !== undefined) document.getElementById('auto-process').value = t.process;
  if (t.time) document.getElementById('auto-time').value = t.time;
  if (t.days) document.querySelectorAll('.auto-day').forEach(c => c.checked = t.days.includes(+c.value));
  if (t.minutes) document.getElementById('auto-minutes').value = t.minutes;
  const target = document.getElementById('auto-target');
  if (target && a.action.target !== undefined) target.value = a.action.target;
  setText('auto-form-title', id ? 'Automation bearbeiten' : 'Neue Automation');
  document.getElementById('auto-save').innerText = id ? 'Änderungen speichern' : 'Automation speichern';
  const firstEmpty = document.getElementById('auto-process');
  (firstEmpty && !firstEmpty.value ? firstEmpty : document.getElementById('auto-name')).focus();
}

function resetAutomationForm() {
  fillAutomationForm({ name: '', trigger: { type: 'process_start' }, action: { type: 'power_plan', target: 'high' } }, null);
}

function collectAutomation() {
  const t = document.getElementById('auto-trigger').value;
  const trigger = { type: t };
  if (t === 'process_start' || t === 'process_stop') trigger.process = document.getElementById('auto-process').value.trim();
  if (t === 'daily') {
    trigger.time = document.getElementById('auto-time').value.trim();
    trigger.days = [...document.querySelectorAll('.auto-day:checked')].map(c => +c.value);
  }
  if (t === 'interval') trigger.minutes = +document.getElementById('auto-minutes').value;
  const action = { type: document.getElementById('auto-action').value };
  const target = document.getElementById('auto-target');
  if (target) action.target = target.value;
  return { id: editingAutoId, name: document.getElementById('auto-name').value.trim(), trigger, action };
}

async function saveAutomation() {
  const body = collectAutomation();
  const res = await api('/api/automation_save', body);
  automations = res.automations;
  renderAutomations();
  resetAutomationForm();
  TactileAudio.done();
  log(`Automation „${body.name}“ gespeichert.`, true);
}

async function toggleAutomation(a, input) {
  try {
    const res = await api('/api/automation_toggle', { id: a.id, enabled: input.checked });
    automations = res.automations;
    renderAutomations();
    log(`Automation „${a.name}“ ${input.checked ? 'aktiviert' : 'pausiert'}.`);
  } catch (e) {
    input.checked = !input.checked;
    throw e;
  }
}

async function runAutomationNow(a) {
  const res = await api('/api/automation_run', { id: a.id });
  renderAutoLog(res.log);
  TactileAudio.done();
  log(`Automation „${a.name}“ getestet: ${res.result}`, res.ok ? true : 'error');
}

async function deleteAutomation(a) {
  if (!await nexusConfirm(`„${a.name}“ wird entfernt und läuft ab sofort nicht mehr.`,
    { title: 'Automation löschen?', confirm: 'Löschen', danger: true })) return;
  const res = await api('/api/automation_delete', { id: a.id });
  automations = res.automations;
  renderAutomations();
  log(`Automation „${a.name}“ gelöscht.`);
}

// ---------------- Speedtest ----------------
let speedPoll = null;
let speedWasRunning = false;

function fmtMbit(v) {
  return v == null ? '—' : `${v.toLocaleString('de-DE')} Mbit/s`;
}

async function startSpeedtest() {
  await api('/api/speedtest_start');
  speedWasRunning = true;
  log('Speedtest gestartet ...', true);
  pollSpeedtest();
}

async function pollSpeedtest() {
  clearTimeout(speedPoll);
  const st = await api('/api/speedtest_status');
  setText('speed-ping', st.ping == null ? '—' : `${st.ping.toLocaleString('de-DE')} ms`);
  setText('speed-jitter', st.jitter == null ? '—' : `${st.jitter.toLocaleString('de-DE')} ms`);
  setText('speed-down', st.phase === 'download' && st.live != null ? `${fmtMbit(st.live)} …` : fmtMbit(st.down));
  setText('speed-up', st.phase === 'upload' && st.live != null ? `${fmtMbit(st.live)} …` : fmtMbit(st.up));
  document.getElementById('speed-btn').disabled = st.running;
  if (st.running) {
    setText('speed-status', { ping: 'Messe Latenz …', download: 'Messe Download (8 s) …', upload: 'Messe Upload (8 s) …' }[st.phase] || 'Läuft …');
    speedPoll = setTimeout(() => pollSpeedtest().catch(() => {}), 500);
    return;
  }
  if (st.error) {
    setText('speed-status', `Fehler: ${st.error}`);
    if (speedWasRunning) log(`Speedtest fehlgeschlagen: ${st.error}`, 'error');
  } else if (st.finished_at) {
    setText('speed-status', `Gemessen um ${st.finished_at}. Näherungswerte – laufende Downloads oder Streams drücken das Ergebnis.`);
    if (speedWasRunning) {
      TactileAudio.done();
      log(`Speedtest: ↓ ${fmtMbit(st.down)} · ↑ ${fmtMbit(st.up)} · Ping ${st.ping} ms`, true);
    }
  }
  speedWasRunning = false;
}

// ---------------- Festplatten-Gesundheit ----------------
let diskLoaded = false;

async function loadDiskHealth() {
  diskLoaded = true;
  const res = await api('/api/disk_health');
  const tbody = document.getElementById('disk-body');
  tbody.innerHTML = '';
  const na = '<span style="color:var(--text-muted)" title="Nur mit Admin-Rechten bzw. vom Laufwerk nicht gemeldet">n/a</span>';
  res.disks.forEach(d => {
    const [color, label] = {
      Healthy: ['var(--status-ok)', '✓ Gesund'],
      Warning: ['var(--status-warn)', '⚠ Warnung'],
      Unhealthy: ['var(--status-danger)', '✕ Defekt'],
    }[d.health] || ['var(--text-secondary)', d.health || 'Unbekannt'];
    const tr = document.createElement('tr');
    tr.innerHTML = `<td style="font-family:var(--font-ui);">${esc(d.name)}<div class="list-sub">${esc(d.size_gb)} GB</div></td>
      <td>${esc(d.media)} · ${esc(d.bus)}</td>
      <td style="color:${color}; font-weight:600;">${esc(label)}</td>
      <td>${d.temp ? `${esc(d.temp)} °C` : na}</td>
      <td>${d.wear != null ? `${esc(d.wear)} %` : na}</td>
      <td>${d.hours != null ? `${esc(Number(d.hours).toLocaleString('de-DE'))} h` : na}</td>`;
    tbody.appendChild(tr);
  });
  if (!res.disks.length) tbody.innerHTML = '<tr><td colspan="6">Keine Laufwerke gefunden.</td></tr>';
}

// ---------------- Massen-Umbenennen ----------------
let renameTimer = null;
let renamePreviewShown = false;

function renameParams() {
  const val = id => document.getElementById(id).value;
  return {
    path: val('sort-path').trim(), pattern: val('ren-pattern'), ext: val('ren-ext').trim(),
    sort: val('ren-sort'), start: +val('ren-start') || 0, find: val('ren-find'), replace: val('ren-replace')
  };
}

function queueRenamePreview() {
  if (!renamePreviewShown) return;
  clearTimeout(renameTimer);
  renameTimer = setTimeout(() => previewRenames().catch(e => {
    setText('ren-summary', e.message);
    document.getElementById('ren-apply').disabled = true;
  }), 400);
}

async function previewRenames() {
  const res = await api('/api/rename_preview', renameParams());
  renamePreviewShown = true;
  const tbody = document.getElementById('ren-body');
  tbody.innerHTML = '';
  res.items.forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td style="color:var(--text-secondary)">${esc(p.old)}</td><td style="width:20px; color:var(--text-muted)">→</td>
      <td style="${p.conflict ? 'color:var(--status-warn); font-weight:600;' : ''}">${p.conflict ? '⚠ ' : ''}${esc(p.new)}</td>`;
    tbody.appendChild(tr);
  });
  const conflicts = res.conflicts ? ` · ${res.conflicts} Konflikte` : '';
  setText('ren-summary', `${res.changed} von ${res.total} Dateien ändern sich${conflicts}`);
  document.getElementById('ren-apply').disabled = !res.changed || res.conflicts > 0;
}

async function applyRenames() {
  const params = renameParams();
  if (!await nexusConfirm(`Die Dateien in ${params.path} werden umbenannt. Mit „Rückgängig“ lässt sich das danach zurücknehmen.`,
    { title: 'Jetzt umbenennen?', confirm: 'Umbenennen' })) return;
  const res = await api('/api/rename_apply', params);
  TactileAudio.done();
  log(`${res.renamed} Dateien umbenannt.`, true);
  await previewRenames();
}

async function undoRenames() {
  const res = await api('/api/rename_undo');
  log(`${res.restored} Umbenennungen zurückgenommen.`, true);
  if (renamePreviewShown) await previewRenames();
}

// ---------------- File Converter ----------------
const CONV_KINDS = {
  BILD: ['.png', '.jpg', '.jpeg', '.jfif', '.bmp', '.gif', '.tif', '.tiff', '.ico', '.webp', '.heic', '.heif', '.avif'],
  AUDIO: ['.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac', '.wma', '.opus'],
  VIDEO: ['.mp4', '.mkv', '.mov', '.avi', '.webm', '.wmv', '.flv', '.m4v', '.ts'],
  DATEN: ['.csv', '.json'],
};
const CONV_ACCEPTS = {
  png: ['BILD'], jpg: ['BILD'], bmp: ['BILD'], tiff: ['BILD'], ico: ['BILD'], pdf: ['BILD'], gif: ['BILD', 'VIDEO'],
  mp3: ['AUDIO', 'VIDEO'], m4a: ['AUDIO', 'VIDEO'], wav: ['AUDIO', 'VIDEO'], flac: ['AUDIO', 'VIDEO'], ogg: ['AUDIO', 'VIDEO'],
  mp4: ['VIDEO'], mp4_discord: ['VIDEO'],
};
const extOf = p => (p.match(/\.[^.\\/]+$/) || [''])[0].toLowerCase();
const kindOf = p => Object.keys(CONV_KINDS).find(k => CONV_KINDS[k].includes(extOf(p))) || 'DATEI';
let convertFiles = [];
let convertPoll = null;
let convertWasRunning = false;
let ffmpegPath = null;

function convAccepts(fmt, path) {
  if (fmt === 'json') return extOf(path) === '.csv';
  if (fmt === 'csv') return extOf(path) === '.json';
  return CONV_ACCEPTS[fmt].includes(kindOf(path));
}

function setConvertFiles(list) {
  convertFiles = [...new Set(list)];
  renderConvertFiles();
}

function moveConvertFile(i, delta) {
  const list = [...convertFiles];
  [list[i], list[i + delta]] = [list[i + delta], list[i]];
  setConvertFiles(list);
}

function renderConvertFiles() {
  const box = document.getElementById('conv-files');
  const fmt = document.getElementById('conv-format').value;
  setText('conv-count', `${convertFiles.length} DATEIEN`);
  box.innerHTML = '';
  if (!convertFiles.length) {
    box.innerHTML = '<div class="drop-hint">Noch keine Dateien. Klick auf „Dateien auswählen …“ – mit Strg mehrere markieren.</div>';
    return;
  }
  convertFiles.forEach((path, i) => {
    const ok = convAccepts(fmt, path);
    const row = document.createElement('div');
    row.className = 'list-row';
    row.style.opacity = ok ? '1' : '0.5';
    const folder = path.slice(0, path.length - baseName(path).length);
    row.innerHTML = `<span class="tag">${kindOf(path)}</span>
      <div class="grow" title="${esc(path)}"><b>${esc(baseName(path))}</b><div class="list-sub">${ok ? esc(folder) : 'passt nicht zum Zielformat – wird übersprungen'}</div></div>
      <button class="btn-secondary btn-mini" title="Nach oben">↑</button>
      <button class="btn-secondary btn-mini" title="Nach unten">↓</button>
      <button class="btn-danger btn-mini" title="Entfernen">×</button>`;
    const [up, down, del] = row.querySelectorAll('button');
    up.disabled = i === 0;
    down.disabled = i === convertFiles.length - 1;
    up.addEventListener('click', () => moveConvertFile(i, -1));
    down.addEventListener('click', () => moveConvertFile(i, 1));
    del.addEventListener('click', () => setConvertFiles(convertFiles.filter((_, j) => j !== i)));
    box.appendChild(row);
  });
}

async function pickConvertFiles() {
  setLoading(true, "WAITING FOR FILE DIALOG...");
  try {
    const res = await api('/api/convert_pick', { mode: 'files' });
    if (res.paths.length) {
      setConvertFiles([...convertFiles, ...res.paths]);
      log(`${res.paths.length} Dateien zur Konvertierung hinzugefügt.`);
    }
  } finally {
    setLoading(false);
  }
}

async function pickOutDir() {
  setLoading(true, "WAITING FOR FOLDER DIALOG...");
  try {
    const res = await api('/api/convert_pick', { mode: 'folder' });
    if (res.paths.length) document.getElementById('conv-outdir').value = res.paths[0];
  } finally {
    setLoading(false);
  }
}

function addPastedPaths() {
  const area = document.getElementById('conv-paste');
  const paths = area.value.split(/\r?\n/).map(s => s.trim().replace(/^"(.*)"$/, '$1')).filter(Boolean);
  setConvertFiles([...convertFiles, ...paths]);
  area.value = '';
}

function renderConvertOptions() {
  const fmt = document.getElementById('conv-format').value;
  const box = document.getElementById('conv-options');
  const sizeField = hint => `<label>Größe begrenzen (längste Seite in px)</label><input type="number" id="conv-maxside" class="mono" min="0" placeholder="${hint}">`;
  const note = text => `<div class="list-sub" style="white-space:normal; margin-top:6px;">${text}</div>`;
  let html = '';
  if (fmt === 'jpg') {
    html = `<label>Qualität: <span id="conv-q-val">90</span></label>
      <input type="range" id="conv-quality" min="40" max="100" value="90" oninput="setText('conv-q-val', this.value)" style="width:100%; margin-bottom:8px; accent-color:var(--accent);">`
      + sizeField('leer = Originalgröße');
  } else if (['png', 'bmp', 'tiff'].includes(fmt)) {
    html = sizeField('leer = Originalgröße');
  } else if (fmt === 'gif') {
    html = sizeField('leer = Original, bei Videos 480') + note('Aus Videos wird ein animiertes GIF mit 12 Bildern pro Sekunde.');
  } else if (fmt === 'pdf') {
    html = sizeField('leer = 2480 (A4 in 300 dpi)') + note('Jedes Bild wird eine A4-Seite, in der Reihenfolge der Liste – mit ↑ ↓ sortieren.');
  } else if (fmt === 'ico') {
    html = note('Wird quadratisch auf 256 × 256 eingepasst, Transparenz bleibt – ideal für Ordner- und Verknüpfungs-Icons.');
  } else if (fmt === 'mp4') {
    html = `<label>Qualität</label><div class="seg" id="conv-vq">${[['high', 'Hoch'], ['medium', 'Mittel · max. 1080p'], ['small', 'Klein · max. 720p']]
      .map(([v, l]) => `<button data-value="${v}" class="${v === 'medium' ? 'active' : ''}">${l}</button>`).join('')}</div>`;
  } else if (fmt === 'mp4_discord') {
    html = note('Die Bitrate wird aus der Videolänge berechnet, damit die Datei unter 10 MB bleibt (720p). Bei sehr langen Videos reicht das nicht – das steht dann im Ergebnis.');
  } else if (['mp3', 'm4a', 'wav', 'flac', 'ogg'].includes(fmt)) {
    html = note('Bei Videos wird nur die Tonspur übernommen.');
  } else if (fmt === 'csv') {
    html = note('Mit Semikolon und UTF-8-BOM – öffnet sich in deutschem Excel per Doppelklick mit richtigen Spalten und Umlauten.');
  } else if (fmt === 'json') {
    html = note('Das Trennzeichen (Komma, Semikolon, Tab) wird automatisch erkannt.');
  }
  box.innerHTML = html;
  box.querySelectorAll('#conv-vq button').forEach(b => b.addEventListener('click', () => {
    box.querySelectorAll('#conv-vq button').forEach(x => x.classList.toggle('active', x === b));
  }));
  renderConvertFiles();
}

async function loadConvertInfo() {
  const res = await api('/api/convert_info');
  ffmpegPath = res.ffmpeg;
  renderFfmpegInfo(false);
}

function renderFfmpegInfo(installing) {
  setText('ffmpeg-info', installing ? 'wird installiert … (dauert 1–3 Minuten)'
    : ffmpegPath ? `bereit · ${ffmpegPath}` : 'nicht installiert – nötig für MP4, MP3 und GIF aus Videos');
  const btn = document.getElementById('ffmpeg-btn');
  btn.style.display = ffmpegPath ? 'none' : '';
  btn.disabled = installing;
}

async function installFfmpeg() {
  if (!await nexusConfirm('Das Paket Gyan.FFmpeg (ca. 90 MB) wird über winget installiert. Das dauert 1–3 Minuten.',
    { title: 'ffmpeg installieren?', confirm: 'Installieren' })) return;
  await api('/api/ffmpeg_install');
  convertWasRunning = true;
  renderFfmpegInfo(true);
  log('ffmpeg-Installation gestartet …', true);
  pollConvert();
}

async function startConversion() {
  const fmt = document.getElementById('conv-format').value;
  const val = id => (document.getElementById(id) || {}).value;
  const vq = document.querySelector('#conv-vq button.active');
  await api('/api/convert_start', {
    format: fmt, files: convertFiles, out_dir: val('conv-outdir'),
    quality: +(val('conv-quality') || 90), max_side: +(val('conv-maxside') || 0),
    video_quality: vq ? vq.dataset.value : 'medium'
  });
  convertWasRunning = true;
  log(`Konvertierung nach ${fmt.toUpperCase()} gestartet.`, true);
  pollConvert();
}

async function pollConvert() {
  clearTimeout(convertPoll);
  const job = await api('/api/convert_status');
  document.getElementById('conv-start').disabled = job.running;
  if (job.format === 'ffmpeg-install') {
    setText('conv-state', job.running ? 'FFMPEG WIRD INSTALLIERT …' : 'BEREIT');
    if (job.running) {
      renderFfmpegInfo(true);
      convertPoll = setTimeout(() => pollConvert().catch(() => {}), 1500);
    } else if (convertWasRunning) {
      convertWasRunning = false;
      log(job.message, /fehlgeschlagen/i.test(job.message) ? 'error' : true);
      await loadConvertInfo();
    }
    return;
  }
  renderConvertResults(job);
  if (job.running) {
    convertPoll = setTimeout(() => pollConvert().catch(() => {}), 600);
  } else if (convertWasRunning) {
    convertWasRunning = false;
    TactileAudio.done();
    log(job.message || 'Konvertierung fertig.', true);
  }
}

function renderConvertResults(job) {
  const items = job.items || [];
  if (!items.length) return;
  const relevant = items.filter(i => i.status !== 'skipped');
  const finished = i => i.status === 'ok' || i.status === 'error';
  const pct = relevant.length ? relevant.reduce((s, i) => s + (finished(i) ? 100 : i.progress || 0), 0) / relevant.length : 0;
  document.getElementById('conv-bar').style.width = `${pct}%`;
  setText('conv-state', job.running
    ? `${relevant.filter(finished).length}/${relevant.length} · ${Math.round(pct)} %`
    : (job.message || 'FERTIG').toUpperCase());
  const box = document.getElementById('conv-results');
  box.innerHTML = '';
  items.forEach(it => {
    const [color, label] = {
      ok: ['var(--status-ok)', '✓ fertig'],
      error: ['var(--status-danger)', '✕ Fehler'],
      skipped: ['var(--text-muted)', '– übersprungen'],
      running: ['var(--text-secondary)', `… ${it.progress || 0} %`],
      pending: ['var(--text-muted)', 'wartet'],
    }[it.status];
    const target = it.status === 'ok' && it.out ? ` → ${baseName(it.out)}` : '';
    const row = document.createElement('div');
    row.className = 'list-row conv-row';
    row.innerHTML = `<div class="grow"><b>${esc(it.name)}</b><div class="list-sub">${esc((it.info || '') + target)}</div></div>
      <span class="conv-status" style="color:${color}">${label}</span>
      ${it.status === 'ok' && it.out ? '<button class="btn-secondary btn-mini">Zeigen</button>' : ''}`;
    const btn = row.querySelector('button');
    if (btn) btn.addEventListener('click', () => revealFile(it.out));
    box.appendChild(row);
  });
}

setInterval(() => {
  document.getElementById('sidebar-clock').innerText = fmtClock(new Date());
  pollPowerStatus().catch(() => {});
  pollMonitor();
  pollPing();
  renderFocus();
}, 1000);

let refreshTimer = null;

function restartRefreshTimer() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(refreshAll, settings.refresh_interval * 1000);
}

restartRefreshTimer();

setInterval(() => {
  const active = document.querySelector('.view-panel.active').id;
  if (active === 'view-daily' || active === 'view-files') refreshDaily().catch(() => {});
  if (active === 'view-auto') loadAutomations().catch(() => {});
}, 10000);

window.addEventListener('load', async () => {
  log("NEXUS OS v10.0 QUANTUM KERNEL initialisiert.", true);
  initSparks();
  initSettingsUI();
  restoreFocus();
  renderAutoFields();
  renderConvertOptions();
  loadAutomations().catch(() => {});
  loadUserData(true)
    .then(() => {
      if (settings.start_view !== 'view-dash') goView(settings.start_view);
      return settings.welcome ? showWelcome() : hideWelcomeNow();
    })
    .catch(e => {
      hideWelcomeNow();
      log(`Alltagsdaten konnten nicht geladen werden: ${e.message}`, 'error');
    });
  await refreshAll();
});
</script>
</body>
</html>
"""

# =====================================================================
# HTTP API ROUTER & LAUNCHER
# =====================================================================

# Pro Start neu erzeugt und nur in die ausgelieferte UI eingebettet. Fremde Webseiten im Browser
# kennen ihn nicht und können die Admin-API deshalb nicht per Cross-Site-Request auslösen.
API_TOKEN = secrets.token_urlsafe(32)

class NexusMonolithHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _host_allowed(self):
        # Schutz gegen DNS-Rebinding: eine fremde Domain, die auf 127.0.0.1 zeigt, schickt ihren eigenen Host-Header
        host = (self.headers.get("Host") or "").lower()
        port = self.server.server_port
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def do_GET(self):
        if not self._host_allowed():
            self.send_error(403)
            return
        body = HTML_UI.replace("__NEXUS_TOKEN__", API_TOKEN).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        token = self.headers.get("X-Nexus-Token", "")
        if not self._host_allowed() or not hmac.compare_digest(token, API_TOKEN):
            self._send_json({"error": "Nicht autorisiert"}, 403)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
            self._route(payload)
        except Exception as e:
            # Ohne Antwort hängt das Frontend; Fehler immer als JSON zurückgeben
            try:
                self._send_json({"error": str(e)}, 400 if isinstance(e, ValueError) else 500)
            except Exception:
                pass

    def _route(self, payload):
        if self.path == "/api/status":
            self._send_json({
                "adapters": get_network_adapters(),
                "hostname": get_current_hostname(),
                "ip": get_local_ip(),
                "gateway": get_gateway_ip(),
                "memory": get_memory_info(),
                "disk": get_disk_info(),
                "volume_serial": get_volume_serial("C:"),
                "uptime": get_uptime_str(),
                "guids": get_system_guids(),
                "backup": dict(ORIGINAL_IDS_BACKUP, file=BACKUP_FILE),
                "caffeine": POWER_STATE["caffeine_active"]
            })

        elif self.path == "/api/monitor":
            MONITOR_VIEWED["last"] = time.time()
            data = {k: list(v) for k, v in MONITOR.items()}
            data["gpu_info"] = GPU_STATE
            self._send_json(data)

        elif self.path == "/api/rotate":
            new_mac = resolve_mac(payload)
            new_host = resolve_hostname(payload)
            desc = get_adapter_desc(payload.get("subkey"))
            apply_hostname(new_host)
            apply_mac(payload["subkey"], desc, new_mac)
            spoof_system_guids(restore=False)
            flush_network()
            self._send_json({"status": "ok", "mac": new_mac, "hostname": new_host})

        elif self.path == "/api/mac":
            new_mac = resolve_mac(payload)
            apply_mac(payload.get("subkey"), get_adapter_desc(payload.get("subkey")), new_mac)
            run_cmd("ipconfig /renew")
            self._send_json({"status": "ok", "mac": new_mac})

        elif self.path == "/api/hostname":
            new_host = resolve_hostname(payload)
            apply_hostname(new_host)
            self._send_json({"status": "ok", "hostname": new_host})

        elif self.path == "/api/restore_mac":
            apply_mac(payload.get("subkey"), get_adapter_desc(payload.get("subkey")), None)
            flush_network()
            self._send_json({"status": "ok"})

        elif self.path == "/api/spoof_guids":
            res = spoof_system_guids(restore=payload.get("restore", False))
            self._send_json(res)

        elif self.path == "/api/restore_identity":
            self._send_json({"restored": restore_original_identity()})

        elif self.path == "/api/dns":
            apply_dns(get_adapter_desc(payload.get("subkey")), payload.get("provider", "cloudflare"))
            self._send_json({"status": "ok"})

        elif self.path == "/api/flush":
            flush_network()
            self._send_json({"status": "ok"})

        elif self.path == "/api/wipe_history":
            removed = clean_network_profiles()
            self._send_json({"status": "ok", "removed": removed})

        elif self.path == "/api/sort_files":
            res = scan_or_sort_folder(payload.get("path", "downloads"), dry_run=payload.get("dry_run", True))
            self._send_json(res)

        elif self.path == "/api/undo_sort":
            restored = undo_last_sort()
            self._send_json({"restored": restored})

        elif self.path == "/api/clean_empty_dirs":
            removed = clean_empty_folders(payload.get("path", "downloads"))
            self._send_json({"removed": removed})

        elif self.path == "/api/large_files":
            files = scan_large_files(payload.get("path", "downloads"))
            self._send_json({"files": files})

        elif self.path == "/api/duplicates":
            self._send_json(find_duplicate_files(payload.get("path", "downloads")))

        elif self.path == "/api/recycle_duplicate":
            self._send_json({"ok": recycle_duplicate(payload.get("path", ""))})

        elif self.path == "/api/reveal":
            self._send_json({"ok": reveal_in_explorer(payload.get("path", ""))})

        elif self.path == "/api/power_start":
            now = datetime.now()
            mode = payload.get("mode", "countdown")
            if mode == "clock":
                try:
                    parts = payload.get("clock_time", "23:30").split(":")
                    target = now.replace(hour=int(parts[0]), minute=int(parts[1]), second=0, microsecond=0)
                    if target <= now:
                        target += timedelta(days=1)
                    total_secs = int((target - now).total_seconds())
                except Exception:
                    total_secs = 1800
                    target = now + timedelta(seconds=1800)
            else:
                total_secs = max(1, payload.get("hours", 0) * 3600 + payload.get("mins", 0) * 60 + payload.get("secs", 0))
                target = now + timedelta(seconds=total_secs)

            POWER_STATE["action"] = payload.get("action", "Herunterfahren")
            POWER_STATE["total_seconds"] = total_secs
            POWER_STATE["remaining_seconds"] = total_secs
            POWER_STATE["target_time_str"] = target.strftime("%H:%M:%S")
            POWER_STATE["force"] = payload.get("force", False)
            POWER_STATE["test_mode"] = payload.get("test_mode", False)
            POWER_STATE["running"] = True
            POWER_STATE["last_message"] = f"AKTIV: {POWER_STATE['action'].upper()}"
            self._send_json(POWER_STATE)

        elif self.path == "/api/power_cancel":
            POWER_STATE["running"] = False
            POWER_STATE["remaining_seconds"] = 0
            POWER_STATE["last_message"] = "ABGEBROCHEN – BEREIT"
            self._send_json(POWER_STATE)

        elif self.path == "/api/power_status":
            self._send_json(POWER_STATE)

        elif self.path == "/api/caffeine":
            active = toggle_caffeine_mode(not POWER_STATE["caffeine_active"])
            self._send_json({"active": active})

        elif self.path == "/api/power_plan":
            msg = set_power_plan(payload.get("plan", "ultimate"))
            self._send_json({"msg": msg})

        elif self.path == "/api/battery_report":
            msg = generate_battery_report()
            self._send_json({"msg": msg})

        elif self.path == "/api/hosts_block":
            added = apply_hosts_blocklist()
            self._send_json({"added": added})

        elif self.path == "/api/clean":
            res = run_system_cleaner(payload.get("targets", []))
            self._send_json(res)

        elif self.path == "/api/ram_boost":
            res = optimize_ram_working_set()
            self._send_json(res)

        elif self.path == "/api/flush_standby_ram":
            res = flush_standby_memory()
            self._send_json(res)

        elif self.path == "/api/tweaks_get":
            self._send_json(get_tweak_states())

        elif self.path == "/api/tweaks_set":
            res = apply_tweak(payload.get("id"), payload.get("enable", False))
            self._send_json(res)

        elif self.path == "/api/processes":
            self._send_json({"processes": get_top_processes()})

        elif self.path == "/api/kill_proc":
            ok = kill_process_by_id(payload.get("pid", 0))
            self._send_json({"ok": ok})

        elif self.path == "/api/set_priority":
            ok = set_process_priority(payload.get("pid", 0), payload.get("priority", "Normal"))
            self._send_json({"ok": ok})

        elif self.path == "/api/startup":
            self._send_json({"items": get_startup_apps()})

        elif self.path == "/api/startup_toggle":
            enabled = set_startup_enabled(payload.get("scope"), payload.get("name", ""), bool(payload.get("enable")))
            self._send_json({"enabled": enabled})

        elif self.path == "/api/net_connections":
            self._send_json({"connections": get_active_connections()})

        elif self.path == "/api/port_scan":
            open_ports = scan_target_ports(payload.get("target", "127.0.0.1"))
            self._send_json({"open_ports": open_ports})

        elif self.path == "/api/dns_benchmark":
            benchmark = benchmark_dns_latencies()
            self._send_json({"benchmark": benchmark})

        elif self.path == "/api/user_data":
            with DATA_LOCK:
                self._send_json({
                    "workspaces": USER_DATA["workspaces"],
                    "reminders": USER_DATA["reminders"],
                    "notes": USER_DATA["notes"],
                    "snippets": USER_DATA["snippets"],
                    "autosort": autosort_status(),
                    "commands": USER_DATA["commands"],
                    "settings": get_settings(),
                    "data_file": DATA_FILE
                })

        elif self.path == "/api/open_place":
            self._send_json({"ok": open_known_place(payload.get("key"))})

        elif self.path == "/api/open_url":
            self._send_json({"ok": open_url(payload.get("url"))})

        elif self.path == "/api/automations":
            with DATA_LOCK:
                self._send_json({"automations": USER_DATA["automations"], "log": list(AUTOMATION_LOG)})

        elif self.path == "/api/automation_save":
            self._send_json({"automations": save_automation(payload)})

        elif self.path == "/api/automation_delete":
            self._send_json({"automations": delete_entry("automations", payload.get("id"))})

        elif self.path == "/api/automation_toggle":
            self._send_json({"automations": set_automation_enabled(payload.get("id"), payload.get("enabled"))})

        elif self.path == "/api/automation_run":
            auto = next((a for a in USER_DATA["automations"] if a["id"] == payload.get("id")), None)
            if not auto:
                raise ValueError("Automation nicht gefunden")
            ok, result = execute_automation(auto, "manuell getestet")
            self._send_json({"ok": ok, "result": result, "log": list(AUTOMATION_LOG)})

        elif self.path == "/api/process_names":
            self._send_json({"names": sorted(get_process_names())})

        elif self.path == "/api/ping_monitor":
            PING_STATE["active_until"] = time.time() + 6
            self._send_json({"slots": [{"label": s["label"], "host": s["host"], "ip": s["ip"],
                                        "samples": list(s["samples"])} for s in PING_SLOTS]})

        elif self.path == "/api/ping_host":
            set_ping_host(payload.get("host"))
            self._send_json({"settings": get_settings()})

        elif self.path == "/api/speedtest_start":
            self._send_json(start_speedtest())

        elif self.path == "/api/speedtest_status":
            self._send_json(SPEEDTEST)

        elif self.path == "/api/disk_health":
            self._send_json({"disks": get_disk_health()})

        elif self.path == "/api/rename_preview":
            self._send_json(preview_renames(payload))

        elif self.path == "/api/rename_apply":
            self._send_json(apply_renames(payload))

        elif self.path == "/api/rename_undo":
            self._send_json({"restored": undo_renames()})

        elif self.path == "/api/welcome":
            self._send_json(get_welcome_info())

        elif self.path == "/api/convert_info":
            self._send_json({"ffmpeg": find_ffmpeg()})

        elif self.path == "/api/convert_pick":
            self._send_json({"paths": pick_paths_dialog(payload.get("mode", "files"))})

        elif self.path == "/api/convert_start":
            self._send_json(start_conversion(payload))

        elif self.path == "/api/convert_status":
            self._send_json(CONVERT_JOB)

        elif self.path == "/api/ffmpeg_install":
            self._send_json(install_ffmpeg())

        elif self.path == "/api/user_data_export":
            with DATA_LOCK:
                self._send_json(USER_DATA)

        elif self.path == "/api/user_data_import":
            self._send_json({"imported": import_user_data(payload.get("data"))})

        elif self.path == "/api/open_data_folder":
            os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
            subprocess.Popen(["explorer.exe", os.path.dirname(DATA_FILE)])
            self._send_json({"status": "ok"})

        elif self.path == "/api/command_save":
            self._send_json({"commands": save_command(payload)})

        elif self.path == "/api/command_delete":
            self._send_json({"commands": delete_entry("commands", payload.get("id"))})

        elif self.path == "/api/command_run":
            self._send_json(run_custom_command(payload.get("id"), bool(payload.get("visible"))))

        elif self.path == "/api/command_status":
            self._send_json(COMMAND_RUNS.get(payload.get("id"), {"running": False, "output": "", "code": None}))

        elif self.path == "/api/settings_save":
            self._send_json(save_settings(payload))

        elif self.path == "/api/autostart_get":
            self._send_json({"enabled": is_autostart_enabled(), "command": autostart_command()})

        elif self.path == "/api/autostart_set":
            self._send_json({"enabled": set_autostart(bool(payload.get("enable")))})

        elif self.path == "/api/system_info":
            self._send_json(get_system_info())

        elif self.path == "/api/folder_sizes":
            self._send_json(get_folder_sizes(payload.get("path", "downloads")))

        elif self.path == "/api/workspace_save":
            self._send_json({"workspaces": save_workspace(payload)})

        elif self.path == "/api/workspace_delete":
            self._send_json({"workspaces": delete_entry("workspaces", payload.get("id"))})

        elif self.path == "/api/workspace_launch":
            self._send_json(launch_workspace(payload.get("id")))

        elif self.path == "/api/reminder_add":
            self._send_json({"reminders": add_reminder(payload)})

        elif self.path == "/api/reminder_delete":
            self._send_json({"reminders": delete_entry("reminders", payload.get("id"))})

        elif self.path == "/api/notes_save":
            save_notes(payload.get("text", ""))
            self._send_json({"status": "ok"})

        elif self.path == "/api/snippet_save":
            self._send_json({"snippets": save_snippet(payload)})

        elif self.path == "/api/snippet_delete":
            self._send_json({"snippets": delete_entry("snippets", payload.get("id"))})

        elif self.path == "/api/autosort_set":
            self._send_json(set_autosort(payload.get("enabled", False), payload.get("path")))

        elif self.path == "/api/app_updates_list":
            self._send_json({"packages": list_app_updates()})

        elif self.path == "/api/app_update_start":
            self._send_json(start_app_update(payload.get("id")))

        elif self.path == "/api/app_update_status":
            self._send_json(UPDATE_JOB)

        elif self.path == "/api/sys_tool":
            tool = payload.get("tool", "")
            if tool == "godmode":
                desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                gm_path = os.path.join(desktop, "GodMode.{ED7BA470-8E54-465E-825C-99712043e01c}")
                os.makedirs(gm_path, exist_ok=True)
            elif tool == "devmgmt":
                os.system("devmgmt.msc")
            elif tool == "ncpa":
                os.system("ncpa.cpl")
            elif tool == "diskmgmt":
                os.system("diskmgmt.msc")
            elif tool == "services":
                os.system("services.msc")
            elif tool == "regedit":
                os.system("regedit")
            self._send_json({"status": "ok"})

        else:
            self._send_json({"error": f"Unbekannter Endpoint: {self.path}"})


def launch_window(url):
    profile_dir = os.path.join(tempfile.gettempdir(), "Monolith_Nexus_Quantum_Profile")
    browsers = [
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    ]
    for b in browsers:
        if os.path.exists(b):
            subprocess.Popen([
                b,
                f"--app={url}",
                "--window-size=1280,840",
                f"--user-data-dir={profile_dir}",
                "--disable-extensions",
                "--no-first-run"
            ])
            return
    os.system(f'start msedge --app="{url}" --window-size=1280,840')


def main():
    ensure_admin()
    load_original_backup()
    load_user_data()
    # Erst nach load_user_data starten, sonst laufen "Beim NEXUS-Start"-Automationen gegen leere Daten ins Leere
    threading.Thread(target=automation_loop, daemon=True).start()
    server =ThreadingHTTPServer(("127.0.0.1", 0), NexusMonolithHandler)
    url = f"http://127.0.0.1:{server.server_port}"
    threading.Thread(target=launch_window, args=(url,), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
