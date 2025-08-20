import flet as ft
import psutil
import platform
import threading
import time
import socket
import subprocess
import smtplib
import ssl
from email.message import EmailMessage
from cryptography.fernet import Fernet
import certifi
import os
import shutil
from cryptography.fernet import Fernet
from dotenv import load_dotenv  # new

# Load environment variables from .env file
load_dotenv()

# Get secret key securely (must be in .env, not in script)
SECRET_KEY = os.getenv("SECRET_KEY")
if SECRET_KEY is None:
    raise ValueError("❌ SECRET_KEY not found. Please add it to your .env file.")
fernet = Fernet(SECRET_KEY.encode())


# ---------------------------
# GLOBAL ERROR LOG
# ---------------------------
error_messages = []

def log_error(error_message, page=None):
    """Log errors locally, show dismissable popup, and store for email report"""
    try:
        # Save to local log
        with open("error_log.txt", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {error_message}\n")

        # Show popup if page is available
        if page:
            dlg = ft.AlertDialog(
                title=ft.Text("⚠️ Error"),
                content=ft.Text(error_message),
                actions=[ft.ElevatedButton("OK", on_click=lambda e: close_dialog(page))]
            )
            page.dialog = dlg
            dlg.open = True
            page.update()

        # Append to global error list for email report
        global error_messages
        error_messages.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {error_message}")

    except Exception as e:
        print(f"Error while logging error: {e}")

def close_dialog(page):
    page.dialog.open = False
    page.update()

# ---------------------------
# ENCRYPTED EMAIL SETUP
# ---------------------------
ENCRYPTED_EMAIL = b"PLACEHOLDER"
ENCRYPTED_PASSWORD = b"PLACEHOLDER"
fernet = Fernet(SECRET_KEY)
EMAIL = fernet.decrypt(ENCRYPTED_EMAIL).decode()
PASSWORD = fernet.decrypt(ENCRYPTED_PASSWORD).decode()

def send_report(to_address, report_text):
    msg = EmailMessage()
    msg.set_content(report_text)
    msg["Subject"] = "Mac Diagnostic Report"
    msg["From"] = EMAIL
    msg["To"] = to_address
    context = ssl.create_default_context(cafile=certifi.where())
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(EMAIL, PASSWORD)
        server.send_message(msg)

# ---------------------------
# SYSTEM INFO FUNCTIONS
# ---------------------------
# (All your existing system info functions remain unchanged)
def get_cpu_per_core():
    return psutil.cpu_percent(percpu=True)

def get_ram_info():
    v = psutil.virtual_memory()
    used = round((v.used/1024**3),1)
    free = round((v.available/1024**3),1)
    total = round((v.total/1024**3),1)
    percent = v.percent
    return used, free, total, percent

def get_disk_info():
    d = psutil.disk_usage("/")
    used = round(d.used/1024**3,1)
    free = round(d.free/1024**3,1)
    total = round(d.total/1024**3,1)
    percent = d.percent
    return used, free, total, percent

def get_battery_info():
    b = psutil.sensors_battery()
    if b:
        cycles = "N/A"
        try:
            output = subprocess.check_output(["system_profiler","SPPowerDataType"]).decode()
            for line in output.splitlines():
                if "Cycle Count" in line:
                    cycles = int(line.split(":")[1].strip())
                    break
        except:
            cycles = "N/A"
        return {"percent": int(b.percent), "cycles": cycles, "plugged": b.power_plugged}
    return {"percent":0, "cycles":"N/A", "plugged":False}

def get_network_usage():
    net_io = psutil.net_io_counters()
    return net_io.bytes_sent, net_io.bytes_recv

def get_ip_address():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "N/A"

def get_wifi_name():
    try:
        output = subprocess.check_output([
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport","-I"
        ]).decode()
        for line in output.splitlines():
            if "SSID" in line:
                return line.split(":")[1].strip()
        return "N/A"
    except:
        return "N/A"

def get_boot_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(psutil.boot_time()))

def get_macos_name():
    try:
        output = subprocess.check_output(["sw_vers","-productName"]).decode().strip()
        version = subprocess.check_output(["sw_vers","-productVersion"]).decode().strip()
        return f"{output} {version}"
    except:
        return platform.system()

def get_mac_model():
    try:
        output = subprocess.check_output(["sysctl","-n","hw.model"]).decode().strip()
        return output
    except:
        return "N/A"

def get_cpu_temp():
    if shutil.which("istats"):
        try:
            output = subprocess.check_output(["istats","cpu","temperature"]).decode().strip()
            import re
            match = re.search(r"(\d+(\.\d+)?)", output)
            if match:
                return float(match.group(1))
            else:
                return None
        except:
            return None
    return None

def get_gpu_info():
    try:
        output = subprocess.check_output(["system_profiler", "SPDisplaysDataType"]).decode()
        lines = output.splitlines()
        model = ""
        vram = ""
        for line in lines:
            if "Chipset Model" in line:
                model = line.split(":")[1].strip()
            if "VRAM" in line:
                vram = line.split(":")[1].strip()
        return f"{model} ({vram})" if model else "N/A"
    except:
        return "N/A"

def get_installed_apps():
    apps = []
    try:
        for app in os.listdir("/Applications"):
            if app.endswith(".app"):
                app_path = f"/Applications/{app}/Contents/Info.plist"
                try:
                    version = subprocess.check_output(["defaults","read", app_path, "CFBundleShortVersionString"]).decode().strip()
                except:
                    version = "N/A"
                apps.append(f"{app} ({version})")
        return apps[:20]
    except:
        return ["N/A"]

def get_top_processes():
    try:
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        time.sleep(0.1)
        procs = []
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent']):
            try:
                procs.append(p.info)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        procs = sorted(procs, key=lambda x: x.get('cpu_percent',0), reverse=True)
        top10 = procs[:10]
        result = []
        for p in top10:
            cpu = p.get('cpu_percent','N/A')
            mem = p.get('memory_percent','N/A')
            name = p.get('name','N/A')
            result.append(f"{name} | CPU: {cpu}% | RAM: {mem if mem=='N/A' else round(mem,1)}%")
        return result if result else ["N/A"]
    except:
        return ["N/A"]

def get_disk_smart_status():
    try:
        output = subprocess.check_output(["diskutil","info","/"]).decode()
        for line in output.splitlines():
            if "SMART Status" in line:
                return line.split(":")[1].strip()
        return "N/A"
    except:
        return "N/A"

def get_color(percent, thresholds=(70,90)):
    if percent < thresholds[0]:
        return "#00ff00"
    elif percent < thresholds[1]:
        return "#ff9900"
    else:
        return "#ff0000"

def net_color(speed):
    if speed < 500:
        return "#00ff00"
    elif speed < 1500:
        return "#ff9900"
    else:
        return "#ff0000"

# ---------------------------
# FLET APP
# ---------------------------
def main(page: ft.Page):
    page.title = "MacMate Diagnostics"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0f0f0f"
    page.vertical_alignment = "center"
    page.horizontal_alignment = "center"

    title = ft.Text("🖥️ MacMate Diagnostics", size=28, color="#00bfff", text_align="center")

    core_count = psutil.cpu_count()
    cpu_core_labels = [ft.Text("", size=16, color="#ffffff") for _ in range(core_count)]
    cpu_core_bars = [ft.ProgressBar(width=400, bgcolor="#00ffff", value=0) for _ in range(core_count)]

    ram_label = ft.Text("", size=16, color="#ffffff")
    ram_bar = ft.ProgressBar(width=400,bgcolor="#00ffff",value=0)

    storage_label = ft.Text("", size=16, color="#ffffff")
    storage_bar = ft.ProgressBar(width=400,bgcolor="#00ffff",value=0)

    battery_label = ft.Text("", size=16, color="#ffffff")
    battery_bar = ft.ProgressBar(width=400,bgcolor="#00ffff",value=0)

    network_label = ft.Text("", size=16, color="#ffffff")
    network_up_bar = ft.ProgressBar(width=400,bgcolor="#00ff00",value=0)
    network_down_bar = ft.ProgressBar(width=400,bgcolor="#ff9900",value=0)

    gpu_info = ft.Text("", size=16,color="#ffffff")
    disk_smart = ft.Text("", size=16,color="#ffffff")
    system_info = ft.Text("", size=16,color="#ffffff")
    kernel_info = ft.Text("", size=16,color="#ffffff")
    ip_info = ft.Text("", size=16,color="#ffffff")
    wifi_info = ft.Text("", size=16,color="#ffffff")
    boot_info = ft.Text("", size=16,color="#ffffff")
    cpu_core_info = ft.Text("", size=16,color="#ffffff")
    model_info = ft.Text("", size=16,color="#ffffff")
    installed_apps_list = ft.Column()
    top_processes_list = ft.Column()

    email_field = ft.TextField(label="Recipient Email", width=350, text_size=16)
    send_button = ft.ElevatedButton("📧 Send Report", bgcolor="#1e90ff")
    status = ft.Text("", size=14, color="#00ff00", text_align="center")

    # ---------------------------
    # Update metrics
    # ---------------------------
    def update_fast_metrics():
        while True:
            try:
                cpu_percents = get_cpu_per_core()
                for i,val in enumerate(cpu_percents):
                    cpu_core_bars[i].value = val/100
                    cpu_core_labels[i].value = f"CPU Core {i+1}: {val}% | Temp: {get_cpu_temp() or 'N/A'}°C"
                ru,rf,rt,rp = get_ram_info()
                ram_bar.value = rp/100
                ram_label.value = f"RAM Usage: {rp}% | {ru}GB used / {rf}GB free / {rt}GB total"

                su,sf,st,sp = get_disk_info()
                storage_bar.value = sp/100
                storage_label.value = f"Storage: {sp}% | {su}GB used / {sf}GB free / {st}GB total"

                bat= get_battery_info()
                battery_bar.value = bat['percent']/100

                if bat['percent'] >= 80:
                    battery_bar.bgcolor = "#00ff00"
                elif bat['percent'] >= 30:
                    battery_bar.bgcolor = "#ff9900"
                else:
                    battery_bar.bgcolor = "#ff0000"

                if isinstance(bat['cycles'], int):
                    if bat['cycles'] < 1000:
                        status_emoji = "✅"
                        status_text = "OK"
                    else:
                        status_emoji = "⚠️"
                        status_text = "Replace Soon"
                else:
                    status_emoji = "❓"
                    status_text = "Unknown"

                battery_label.value = f"🔋 Battery: {bat['percent']}% | Cycles: {bat['cycles']} | {status_emoji} {status_text}"
                    
                sent,recv = get_network_usage()
                network_up_bar.value = sent/1024/100
                network_down_bar.value = recv/1024/100
                network_label.value = f"🌐 Network: ⬆️ {sent/1024:.1f} KB/s ⬇️ {recv/1024:.1f} KB/s"

                page.update()
            except Exception as e:
                log_error(f"Fast metrics update failed: {e}", page)
            time.sleep(30)

    def update_slow_metrics():
        while True:
            try:
                system_info.value = f"🖥️ System: {get_macos_name()}"
                kernel_info.value = f"🧩 Kernel: {platform.release()}"
                model_info.value = f"💻 Model: {get_mac_model()}"
                boot_info.value = f"⏱️ Boot: {get_boot_time()}"
                ip_info.value = f"🌐 IP: {get_ip_address()}"
                wifi_info.value = f"📶 Wi-Fi: {get_wifi_name()}"
                cpu_core_info.value = f"⚡ CPU Cores: {psutil.cpu_count()}"
                gpu_info.value = f"🎨 GPU: {get_gpu_info()}"
                disk_smart.value = f"💽 Disk SMART Status: {get_disk_smart_status()}"

                installed_apps_list.controls.clear()
                for app in get_installed_apps():
                    installed_apps_list.controls.append(ft.Text(f"📦 {app}", color="#ffffff", size=14))

                top_processes_list.controls.clear()
                for proc in get_top_processes():
                    top_processes_list.controls.append(ft.Text(f"⚙️ {proc}", color="#ffffff", size=14))

                page.update()
            except Exception as e:
                log_error(f"Slow metrics update failed: {e}", page)
            time.sleep(60)

    threading.Thread(target=update_fast_metrics, daemon=True).start()
    threading.Thread(target=update_slow_metrics, daemon=True).start()

    # ---------------------------
    # Send report
    # ---------------------------
    def send_clicked(e):
        try:
            report = f"{system_info.value}\n{kernel_info.value}\n{ip_info.value}\n{wifi_info.value}\n{boot_info.value}\n{cpu_core_info.value}\n{model_info.value}\n\n"
            for i,val in enumerate(get_cpu_per_core()):
                report += f"CPU Core {i+1}: {val}% | Temp: {get_cpu_temp() or 'N/A'}°C\n"
            ru,rf,rt,rp = get_ram_info()
            report += f"RAM: {rp}% | {ru}GB used / {rf}GB free / {rt}GB total\n"
            su,sf,st,sp = get_disk_info()
            report += f"Storage: {sp}% | {su}GB used / {sf}GB free / {st}GB total\n"
            bat = get_battery_info()
            report += f"Battery: {bat['percent']}% | Cycles: {bat['cycles']}\n"
            sent,recv = get_network_usage()
            report += f"Network: ⬆️ {sent/1024:.1f} KB/s ⬇️ {recv/1024:.1f} KB/s\n"
            report += f"{gpu_info.value}\n"
            for app in get_installed_apps():
                report += f"📦 {app}\n"
            for proc in get_top_processes():
                report += f"⚙️ {proc}\n"
            report += f"{disk_smart.value}\n"

            # Include all logged errors in email report
            if error_messages:
                report += "\n⚠️ Errors detected during monitoring:\n"
                report += "\n".join(error_messages)

            send_report(email_field.value, report)
            status.value = "✅ Report sent successfully"
            status.color = "#00ff00"
        except Exception as ex:
            log_error(f"Failed to send report: {ex}", page)
            status.value = f"❌ Failed: {ex}"
            status.color = "#ff0000"
        page.update()

    send_button.on_click = send_clicked

    # ---------------------------
    # Tabs
    # ---------------------------
    tabs = ft.Tabs(selected_index=0, tabs=[
        ft.Tab(
            text="CPU",
            content=ft.ListView(
                [ft.Column([cpu_core_labels[i], cpu_core_bars[i]]) for i in range(core_count)],
                auto_scroll=True
            )
        ),
        ft.Tab(
            text="RAM",
            content=ft.ListView([ram_label, ram_bar], auto_scroll=True)
        ),
        ft.Tab(
            text="Storage",
            content=ft.ListView([storage_label, storage_bar, disk_smart], auto_scroll=True)
        ),
        ft.Tab(
            text="Battery",
            content=ft.ListView([battery_label, battery_bar], auto_scroll=True)
        ),
        ft.Tab(
            text="Network",
            content=ft.ListView([network_label, network_up_bar, network_down_bar], auto_scroll=True)
        ),
        ft.Tab(
            text="System Info",
            content=ft.ListView([
                system_info, kernel_info, ip_info, wifi_info, boot_info, cpu_core_info, model_info,
                gpu_info, ft.Text("📦 Installed Apps (Top 20):", color="#00bfff"), installed_apps_list,
                ft.Text("⚙️ Top Processes:", color="#00bfff"), top_processes_list
            ], auto_scroll=True)
        ),
        ft.Tab(
            text="Send Report",
            content=ft.ListView([email_field, send_button, status], auto_scroll=True)
        )
    ])

    page.add(title, ft.Divider(), tabs)

ft.app(target=main)
