"""
PhantomDroid — Extended Device Information Module
Author: Mr. Psycho | @the_psycho_of_hackers

Comprehensive device info collector with hardware, security, network,
services, and capabilities information.
"""

import subprocess
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.align import Align

console = Console()


def run_adb(args: list, device_id: str = None, capture: bool = True):
    """Run an adb command and return stdout."""
    cmd = ["adb"]
    if device_id:
        cmd += ["-s", device_id]
    cmd += args
    try:
        result = subprocess.run(cmd, capture_output=capture, text=True, timeout=30)
        return result.stdout.strip(), result.returncode
    except FileNotFoundError:
        return None, -1
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -2


def get_property(device_id: str, prop: str, default: str = "N/A") -> str:
    """Get a single device property."""
    out, rc = run_adb(["shell", f"getprop {prop}"], device_id)
    return out if out and rc == 0 else default


def get_device_properties(device_id: str) -> dict:
    """Gather basic device properties."""
    props_dict = {
        "Brand": "ro.product.brand",
        "Model": "ro.product.model",
        "Device Name": "ro.product.device",
        "Manufacturer": "ro.product.manufacturer",
        "Android Version": "ro.build.version.release",
        "SDK Level": "ro.build.version.sdk",
        "Build ID": "ro.build.id",
        "Build Fingerprint": "ro.build.fingerprint",
        "Build Type": "ro.build.type",
        "Security Patch": "ro.build.version.security_patch",
        "CPU ABI": "ro.product.cpu.abi",
        "Serial Number": "ro.serialno",
    }
    
    items = []
    for label, prop in props_dict.items():
        value = get_property(device_id, prop)
        severity = "info"
        items.append({
            "label": label,
            "value": value,
            "severity": severity
        })
    
    return {
        "category": "📱 Device Properties",
        "items": items
    }


def get_hardware_info(device_id: str) -> dict:
    """Gather hardware specifications."""
    items = []
    
    # CPU cores
    cpu_cmd = "cat /proc/cpuinfo | grep -i 'processor' | wc -l"
    out, _ = run_adb(["shell", cpu_cmd], device_id)
    cpu_cores = out if out and out.isdigit() else "N/A"
    items.append({"label": "CPU Cores", "value": str(cpu_cores), "severity": "info"})
    
    # RAM
    mem_cmd = "cat /proc/meminfo | grep MemTotal"
    out, _ = run_adb(["shell", mem_cmd], device_id)
    total_ram = "N/A"
    if out:
        match = re.search(r"MemTotal:\s+(\d+)", out)
        if match:
            total_ram_kb = int(match.group(1))
            total_ram = f"{total_ram_kb // 1024} MB"
    items.append({"label": "Total RAM", "value": total_ram, "severity": "info"})
    
    # Available RAM
    mem_cmd = "cat /proc/meminfo | grep MemAvailable"
    out, _ = run_adb(["shell", mem_cmd], device_id)
    avail_ram = "N/A"
    if out:
        match = re.search(r"MemAvailable:\s+(\d+)", out)
        if match:
            avail_ram_kb = int(match.group(1))
            avail_ram = f"{avail_ram_kb // 1024} MB"
    items.append({"label": "Available RAM", "value": avail_ram, "severity": "info"})
    
    # Storage
    storage_cmd = "df /data | tail -1"
    out, _ = run_adb(["shell", storage_cmd], device_id)
    storage_info = "N/A"
    if out:
        parts = out.split()
        if len(parts) >= 4:
            total = int(parts[1]) // 1024 if parts[1].isdigit() else 0
            used = int(parts[2]) // 1024 if parts[2].isdigit() else 0
            if total > 0:
                storage_info = f"{used} MB / {total} MB"
    items.append({"label": "Internal Storage", "value": storage_info, "severity": "info"})
    
    # Battery
    battery_cmd = "dumpsys battery | grep -E 'level|health|temperature|voltage'"
    out, _ = run_adb(["shell", battery_cmd], device_id)
    battery_info = "N/A"
    battery_level = "N/A"
    if out:
        lines = out.split('\n')
        for line in lines:
            if 'level:' in line.lower():
                match = re.search(r"(\d+)", line)
                if match:
                    battery_level = f"{match.group(1)}%"
                    break
    items.append({"label": "Battery Level", "value": battery_level, "severity": "info"})
    
    # Display
    display_cmd = "wm size"
    out, _ = run_adb(["shell", display_cmd], device_id)
    display_info = "N/A"
    if out:
        match = re.search(r"(\d+)x(\d+)", out)
        if match:
            display_info = f"{match.group(1)}x{match.group(2)}"
    items.append({"label": "Display Resolution", "value": display_info, "severity": "info"})
    
    return {
        "category": "⚙️  Hardware",
        "items": items
    }


def get_security_info(device_id: str) -> dict:
    """Gather security-related information."""
    items = []
    
    # Build type
    build_type = get_property(device_id, "ro.build.type")
    severity = "warning" if build_type == "userdebug" else "info"
    items.append({"label": "Build Type", "value": build_type, "severity": severity})
    
    # Root status
    root_cmd = "test -f /system/bin/su && echo 'ROOTED' || echo 'NOT_ROOTED'"
    out, _ = run_adb(["shell", root_cmd], device_id)
    root_status = "Rooted ⚠️" if "ROOTED" in out else "Not Rooted ✓"
    severity = "warning" if "ROOTED" in out else "info"
    items.append({"label": "Root Status", "value": root_status, "severity": severity})
    
    # SELinux
    selinux_cmd = "getenforce"
    out, _ = run_adb(["shell", selinux_cmd], device_id)
    selinux_status = out if out else "N/A"
    items.append({"label": "SELinux Status", "value": selinux_status, "severity": "info"})
    
    # Encryption
    enc_cmd = "getprop ro.crypto.state"
    enc_status = get_property(device_id, "ro.crypto.state", "Unknown")
    items.append({"label": "Encryption Status", "value": enc_status, "severity": "info"})
    
    # Debuggable
    debuggable = get_property(device_id, "ro.debuggable")
    severity = "warning" if debuggable == "1" else "info"
    debug_status = "Enabled ⚠️" if debuggable == "1" else "Disabled ✓"
    items.append({"label": "Debuggable", "value": debug_status, "severity": severity})
    
    # Security patch
    patch = get_property(device_id, "ro.build.version.security_patch")
    items.append({"label": "Security Patch", "value": patch, "severity": "info"})
    
    return {
        "category": "🔒 Security",
        "items": items
    }


def get_network_info(device_id: str) -> dict:
    """Gather network and connectivity information."""
    items = []
    
    # IP Address
    ip_cmd = "ip addr show | grep 'inet ' | grep -v '127.0.0.1' | head -1"
    out, _ = run_adb(["shell", ip_cmd], device_id)
    ip_addr = "N/A"
    if out:
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", out)
        if match:
            ip_addr = match.group(1)
    items.append({"label": "IP Address", "value": ip_addr, "severity": "info"})
    
    # MAC Address
    mac_cmd = "ip addr show wlan0 | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}'"
    out, _ = run_adb(["shell", mac_cmd], device_id)
    mac_addr = out if out else "N/A"
    items.append({"label": "MAC Address", "value": mac_addr, "severity": "info"})
    
    # WiFi SSID
    wifi_cmd = "iw wlan0 link 2>/dev/null | grep SSID || dumpsys wifi | grep Ssid"
    out, _ = run_adb(["shell", wifi_cmd], device_id)
    wifi_ssid = "N/A"
    if out:
        match = re.search(r"SSID[:\s]+(.+?)(\n|$)", out)
        if match:
            wifi_ssid = match.group(1).strip()
    items.append({"label": "Connected WiFi", "value": wifi_ssid, "severity": "info"})
    
    # Connectivity Type
    conn_cmd = "dumpsys connectivity | grep -E 'mNetworkInfo|type:' | head -5"
    out, _ = run_adb(["shell", conn_cmd], device_id)
    conn_type = out.split('\n')[0] if out else "Unknown"
    items.append({"label": "Connectivity Type", "value": conn_type[:50], "severity": "info"})
    
    return {
        "category": "🌐 Network",
        "items": items
    }


def get_running_services(device_id: str) -> dict:
    """Gather information about running services and processes."""
    items = []
    
    # Top processes by memory
    proc_cmd = "ps aux | sort -rn -k6 | head -4 | tail -3"
    out, _ = run_adb(["shell", proc_cmd], device_id)
    top_procs = "N/A"
    if out:
        lines = out.strip().split('\n')
        proc_names = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 11:
                proc_names.append(parts[10][:30])
        if proc_names:
            top_procs = ", ".join(proc_names)
    items.append({"label": "Top Processes", "value": top_procs, "severity": "info"})
    
    # System uptime
    uptime_cmd = "cat /proc/uptime | awk '{print int($1/3600) \" hours\"}'  "
    out, _ = run_adb(["shell", uptime_cmd], device_id)
    uptime = out if out else "N/A"
    items.append({"label": "System Uptime", "value": uptime, "severity": "info"})
    
    # Running services count
    services_cmd = "dumpsys | grep -c 'Service '"
    out, _ = run_adb(["shell", services_cmd], device_id)
    service_count = out if out and out.isdigit() else "N/A"
    items.append({"label": "Active Services", "value": str(service_count), "severity": "info"})
    
    return {
        "category": "📊 Services",
        "items": items
    }


def get_hardware_capabilities(device_id: str) -> dict:
    """Gather hardware capability information."""
    items = []
    
    # Sensors
    sensor_cmd = "dumpsys sensorservice | grep 'Sensor ' | head -5 | sed 's/Sensor [0-9]*: //' | awk '{print $1}'"
    out, _ = run_adb(["shell", sensor_cmd], device_id)
    sensors = "N/A"
    if out:
        sensor_list = [s.strip() for s in out.split('\n') if s.strip()]
        if sensor_list:
            sensors = ", ".join(sensor_list[:3])
            if len(sensor_list) > 3:
                sensors += f" +{len(sensor_list) - 3} more"
    items.append({"label": "Sensors", "value": sensors, "severity": "info"})
    
    # Cameras
    camera_cmd = "dumpsys media.camera | grep 'Camera [0-9]' | head -3"
    out, _ = run_adb(["shell", camera_cmd], device_id)
    cameras = "N/A"
    if out:
        camera_count = len(out.strip().split('\n'))
        cameras = f"{camera_count} camera(s)"
    items.append({"label": "Cameras", "value": cameras, "severity": "info"})
    
    # NFC
    nfc_cmd = "getprop ro.nfc.fw_version"
    nfc = get_property(device_id, "ro.nfc.fw_version", "Not Available")
    nfc_status = "Available ✓" if nfc != "Not Available" else "Not Available"
    items.append({"label": "NFC", "value": nfc_status, "severity": "info"})
    
    # Bluetooth
    bt_cmd = "getprop ro.bluetooth.library_name"
    bt = get_property(device_id, "ro.bluetooth.library_name", "Not Available")
    bt_status = "Available ✓" if bt != "Not Available" else "Not Available"
    items.append({"label": "Bluetooth", "value": bt_status, "severity": "info"})
    
    # USB Version
    usb_cmd = "getprop ro.usb.bcdDevice"
    usb_ver = get_property(device_id, "ro.usb.bcdDevice", "N/A")
    items.append({"label": "USB Version", "value": usb_ver, "severity": "info"})
    
    return {
        "category": "💾 Hardware Capabilities",
        "items": items
    }


def display_full_device_info(device_id: str):
    """Main function: Display comprehensive device information in formatted tables."""
    console.print(f"\n[bold magenta]🔎 Full Device Information [{device_id}][/]\n")
    
    # Collect all info
    collectors = [
        get_device_properties,
        get_hardware_info,
        get_security_info,
        get_network_info,
        get_running_services,
        get_hardware_capabilities,
    ]
    
    all_data = []
    for collector in collectors:
        try:
            data = collector(device_id)
            all_data.append(data)
        except Exception as e:
            console.print(f"[yellow]⚠️  Error collecting {collector.__name__}: {e}[/]")
    
    # Display tables
    for data in all_data:
        table = Table(
            title=f"[bold cyan]{data['category']}[/]",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan"
        )
        table.add_column("Property", style="white", width=25)
        table.add_column("Value", style="white")
        
        for item in data["items"]:
            label = item["label"]
            value = item["value"]
            
            # Color code by severity
            if item["severity"] == "warning":
                value_style = "yellow"
            elif item["severity"] == "critical":
                value_style = "red bold"
            else:
                value_style = "white"
            
            table.add_row(label, f"[{value_style}]{value}[/]")
        
        console.print(table)
        console.print()


def get_full_device_info_dict(device_id: str) -> dict:
    """Return all device info as a structured dictionary (for JSON export, etc.)."""
    collectors = [
        get_device_properties,
        get_hardware_info,
        get_security_info,
        get_network_info,
        get_running_services,
        get_hardware_capabilities,
    ]
    
    result = {"device_id": device_id}
    for collector in collectors:
        try:
            data = collector(device_id)
            result[data["category"]] = data["items"]
        except Exception as e:
            console.print(f"[yellow]⚠️  Error: {e}[/]")
    
    return result
