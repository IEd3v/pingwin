import sys
import threading
import itertools
import subprocess
import time
import socket
from typing import Optional

# PyQt GUI
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit
)
from PyQt5.QtGui import QIntValidator
from PyQt5.QtCore import QThread, pyqtSignal, QObject, Qt

INTERFACE = "Wi-Fi" # Имя сетевого интерфейса на macOS
MASK = "255.255.255.0" # Маска подсети
DNS = "172.16.1.5" # DNS-серверы 
GATEWAY = "172.16.23.1" # Шлюз по умолчанию

# GUI will collect NETUSE, START and END from user

DELAY = 4   # Задержка после смены IP (секунды)
PING_TIMEOUT = 2 # Таймаут для ping (секунды)
HTTP_TIMEOUT = 7 # Таймаут для проверки интернета (секунды)

def spinner(text: str, stop_event: threading.Event) -> None:
    for c in itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\r{text} {c}")
        sys.stdout.flush()
        time.sleep(0.1)

    sys.stdout.write("\r" + " " * (len(text) + 4) + "\r")
    sys.stdout.flush()

def run(cmd: str) -> int:
    return subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).returncode

def set_dns(dns: str, interface: str) -> None:
    run(f'networksetup -setdnsservers "{interface}" {dns}')
    time.sleep(DELAY)

def set_ip(ip: str, interface: str, mask: str, gateway: str) -> None:
    run("arp -a -d")
    run(f'networksetup -setmanual "{interface}" {ip} {mask} {gateway}')
    time.sleep(DELAY)

def ip_is_used(ip: str) -> int:
    return run(f"ping -c 1 -W {PING_TIMEOUT} {ip}") == 0

def internet_ok() -> bool:
    try:
        socket.create_connection(("8.8.4.4", 443), timeout=HTTP_TIMEOUT)
        return True
    except Exception:
        return False

if __name__ == "__main__":

    # Worker class to run scanning in background thread
    class ScanWorker(QObject):
        log = pyqtSignal(str)
        finished = pyqtSignal(bool)

        def __init__(self, network: str, start: int, end: int, interface: str, mask: str, dns: str, gateway: str):
            super().__init__()
            self.network = network
            self.start = start
            self.end = end
            self.interface = interface
            self.mask = mask
            self.dns = dns
            self.gateway = gateway

        def run(self):
            NETWORK = self.network
            gateway_to_use = self.gateway if self.gateway else f"{NETWORK}.1"

            self.log.emit(f"Scanning network {NETWORK}.0/24 from {self.start} to {self.end}")

            set_dns(self.dns, self.interface)

            for last in range(self.start, self.end + 1):
                ip = f"{NETWORK}.{last}"
                self.log.emit(f"Trying {ip}...")

                if ip_is_used(ip):
                    self.log.emit(f"🟡 {ip} is used, skipping")
                    continue

                # set IP (this will require sudo and may prompt in terminal)
                set_ip(ip, self.interface, self.mask, gateway_to_use)

                if internet_ok():
                    self.log.emit(f"🟢 Internet OK on {ip}")
                    self.finished.emit(True)
                    return
                else:
                    self.log.emit(f"🔴 No internet on {ip}")

            self.log.emit("\n🚫 Рабочий IP не найден")
            self.finished.emit(False)

    # Simple GUI
    class MainWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("IP Scanner")
            self.setMinimumWidth(200)
            layout = QVBoxLayout()

            # Row: Interface
            row_iface = QHBoxLayout()
            row_iface.addWidget(QLabel("Interface:"))
            self.interface_edit = QLineEdit()
            self.interface_edit.setText(INTERFACE)
            row_iface.addWidget(self.interface_edit)
            layout.addLayout(row_iface)

            # Row: Mask
            row_mask = QHBoxLayout()
            row_mask.addWidget(QLabel("Mask:"))
            self.mask_edit = QLineEdit()
            self.mask_edit.setText(MASK)
            row_mask.addWidget(self.mask_edit)
            layout.addLayout(row_mask)

            # Row: DNS
            row_dns = QHBoxLayout()
            row_dns.addWidget(QLabel("DNS:"))
            self.dns_edit = QLineEdit()
            self.dns_edit.setText(DNS)
            row_dns.addWidget(self.dns_edit)
            layout.addLayout(row_dns)

            # Row: Gateway
            row_gw = QHBoxLayout()
            row_gw.addWidget(QLabel("Gateway:"))
            self.gateway_edit = QLineEdit()
            self.gateway_edit.setText(GATEWAY)
            row_gw.addWidget(self.gateway_edit)
            layout.addLayout(row_gw)

            # Row: Network prefix
            row_net = QHBoxLayout()
            row_net.addWidget(QLabel("Network (3 octets):"))
            self.netuse_edit = QLineEdit()
            self.netuse_edit.setText("172.16.32")
            self.netuse_edit.setPlaceholderText("e.g. 172.16.32")
            row_net.addWidget(self.netuse_edit)
            layout.addLayout(row_net)


            # Row: START / END
            row_range = QHBoxLayout()
            row_range.addWidget(QLabel("Начальный IP:"))
            self.start_edit = QLineEdit()
            self.start_edit.setValidator(QIntValidator(1, 254))
            row_range.addWidget(self.start_edit)
            row_range.addWidget(QLabel("Конечный IP:"))
            self.end_edit = QLineEdit()
            self.end_edit.setValidator(QIntValidator(1, 254))
            row_range.addWidget(self.end_edit)
            layout.addLayout(row_range)

            # Buttons row: Start and Clear logs
            btn_row = QHBoxLayout()

            self.start_btn = QPushButton("Start")
            self.start_btn.setStyleSheet("background-color: orange; font-weight: bold; padding: 6px;")
            btn_row.addWidget(self.start_btn)

            self.clear_btn = QPushButton("Clear")
            self.clear_btn.setStyleSheet("padding: 6px;")
            btn_row.addWidget(self.clear_btn)

            layout.addLayout(btn_row)

            # Log area
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            layout.addWidget(self.log)

            self.setLayout(layout)

            self.start_btn.clicked.connect(self.on_start)
            self.clear_btn.clicked.connect(self.log.clear)

            self.thread: Optional[QThread] = None
            self.worker: Optional[ScanWorker] = None

        def append_log(self, text: str):
            self.log.append(text)

        def on_start(self):
            network_prefix = self.netuse_edit.text().strip()
            start = self.start_edit.text().strip()
            end = self.end_edit.text().strip()
            interface = self.interface_edit.text().strip()
            mask = self.mask_edit.text().strip()
            dns = self.dns_edit.text().strip()
            gateway = self.gateway_edit.text().strip()

            if network_prefix.count(".") != 2:
                self.append_log("Network must be like 172.16.32")
                return

            if not interface or not mask or not dns:
                self.append_log("Please fill interface, mask and dns fields")
                return

            network_prefix_i = int(network_prefix.split(".")[-1])
            start_i = int(start)
            end_i = int(end)
            
            # disable UI
            self.start_btn.setEnabled(False)
            self.netuse_edit.setEnabled(False)
            self.start_edit.setEnabled(False)
            self.end_edit.setEnabled(False)
            self.interface_edit.setEnabled(False)
            self.mask_edit.setEnabled(False)
            self.dns_edit.setEnabled(False)
            self.gateway_edit.setEnabled(False)

            # create worker and thread
            self.thread = QThread()
            self.worker = ScanWorker(network_prefix, start_i, end_i, interface, mask, dns, gateway)
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run) # type: ignore
            self.worker.log.connect(self.append_log)
            self.worker.finished.connect(self.on_finished)
            self.thread.start()

        def on_finished(self, found: bool):
            if found:
                self.append_log("🏁 Found working IP. Done.")
            else:
                self.append_log("🏁 Scan finished. No working IP found.")

            # cleanup thread
            if self.thread is not None:
                self.thread.quit()
                self.thread.wait()
                self.thread = None

            # re-enable UI
            self.start_btn.setEnabled(True)
            self.netuse_edit.setEnabled(True)
            self.start_edit.setEnabled(True)
            self.end_edit.setEnabled(True)
            self.interface_edit.setEnabled(True)
            self.mask_edit.setEnabled(True)
            self.dns_edit.setEnabled(True)
            self.gateway_edit.setEnabled(True)

    # Start the Qt application
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())