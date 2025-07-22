import sys
import os
import ipaddress
import psutil
import pyshark
import socket
import time
import asyncio
import re
import subprocess
from collections import deque
from datetime import datetime

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QComboBox, QLineEdit, QTableWidget, QTableWidgetItem, QFileDialog,
    QMessageBox, QHeaderView, QSplitter, QTextEdit, QDialog,
    QFormLayout
)
try:
    import pyqtgraph as pg
except Exception:
    pg = None
try:
    from pyshark.capture.capture import Capture as _CapForDel
    def _safe_del(self):
        try:
            for p in getattr(self, "_running_processes", []):
                try:
                    p.terminate()
                except Exception:
                    pass
        except Exception:
            pass
    _CapForDel.__del__ = _safe_del
except Exception:
    pass
if os.name == 'nt':
    try:
        import ctypes, threading, time, re, asyncio, subprocess, _winapi

        CREATE_NO_WINDOW = 0x08000000
        DETACHED_PROCESS = 0x00000008
        SW_HIDE = 0
        _exe_re = re.compile(r'(?:^|[\/])(tshark|dumpcap)\.exe$', re.IGNORECASE)
        def _match_ws(cmd):
            parts = cmd if isinstance(cmd, (list, tuple)) else [cmd]
            return any(_exe_re.search(str(p)) for p in parts)
        _orig_CreateProcess = _winapi.CreateProcess
        def _CreateProcess_hidden(appName, commandLine, procAttrs, threadAttrs,
                                  inheritHandles, creationFlags, env, cwd, startupInfo):
            creationFlags |= CREATE_NO_WINDOW | DETACHED_PROCESS
            try:
                if startupInfo:
                    startupInfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupInfo.wShowWindow = SW_HIDE
            except Exception:
                pass
            return _orig_CreateProcess(appName, commandLine, procAttrs, threadAttrs,
                                       inheritHandles, creationFlags, env, cwd, startupInfo)
        _winapi.CreateProcess = _CreateProcess_hidden
        user32 = ctypes.windll.user32
        EnumWindows = user32.EnumWindows
        GetWindowThreadProcessId = user32.GetWindowThreadProcessId
        ShowWindow = user32.ShowWindow
        IsWindowVisible = user32.IsWindowVisible
        EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def _hide_pid_windows(pid):
            def _cb(hwnd, _):
                wnd_pid = ctypes.c_ulong()
                GetWindowThreadProcessId(hwnd, ctypes.byref(wnd_pid))
                if wnd_pid.value == pid and IsWindowVisible(hwnd):
                    ShowWindow(hwnd, SW_HIDE)
                return True
            EnumWindows(EnumWindowsProc(_cb), 0)

        def _hide_async(pid):
            for _ in range(15):
                _hide_pid_windows(pid)
                time.sleep(0.1)
        _orig_popen = subprocess.Popen
        def _popen_hidden(cmd, *pargs, **kwargs):
            proc = _orig_popen(cmd, *pargs, **kwargs)
            if _match_ws(cmd):
                threading.Thread(target=_hide_async, args=(proc.pid,), daemon=True).start()
            return proc
        subprocess.Popen = _popen_hidden
        try:
            _orig_exec  = asyncio.subprocess.create_subprocess_exec
            _orig_shell = asyncio.subprocess.create_subprocess_shell
            async def _exec_hidden(*cmd, **kwargs):
                proc = await _orig_exec(*cmd, **kwargs)
                if _match_ws(cmd):
                    threading.Thread(target=_hide_async, args=(proc.pid,), daemon=True).start()
                return proc
            async def _shell_hidden(*cmd, **kwargs):
                proc = await _orig_shell(*cmd, **kwargs)
                threading.Thread(target=_hide_async, args=(proc.pid,), daemon=True).start()
                return proc
            asyncio.subprocess.create_subprocess_exec  = _exec_hidden
            asyncio.subprocess.create_subprocess_shell = _shell_hidden
        except Exception:
            pass
    except Exception:
        pass
LANGS = {
    "en": "English",
    "it": "Italiano",
    "fr": "Français",
    "es": "Español",
    "de": "Deutsch",
}

STRINGS = {
    "en": {
        "app_title":"IP Discovery Monitor",
        "iface":"Interface:",
        "search_type":"Search type:",
        "search_total":"Total (private IPs only)",
        "search_private":"Private in specific subnet",
        "subnet":"Subnet:",
        "start":"▶️ Start",
        "stop":"⏹️ Stop",
        "save":"💾 Save (TXT)",
        "reset":"🧹 Reset",
        "sniffer_started":"Sniffer started on interface: {iface}",
        "sniffer_stopped":"Sniffer stopped",
        "table_ip":"IP",
        "table_mac":"MAC",
        "table_host":"Hostname",
        "table_first":"First seen",
        "warn_running":"Sniffer already running",
        "err_select_iface":"Select an interface",
        "err_enter_subnet":"Insert a valid subnet",
        "err_bad_subnet":"Invalid subnet format",
        "info_nodata":"No data to save",
        "save_dialog":"Save report (TXT)",
        "save_filter":"Text Files (*.txt)",
        "save_success":"Report saved to: {path}",
        "log_reset":"Table reset",
        "log_saved":"Report saved: {path}",
        "new_device":"New device: {ip} ({mac}) - Hostname: {host}",
        "language":"Language:",
        "status_idle":"Idle",
        "status_running":"Running",
        "status_stopped":"Stopped",
        "details_title":"Device details",
        "details_ip":"IP",
        "details_mac":"MAC",
        "details_host":"Hostname",
        "details_first":"First seen",
        "footer_version":"v2.0.0",
        "footer_by":"Lucio Gigliofiorito",
    },
    "it": {
        "app_title":"IP Discovery Monitor",
        "iface":"Interfaccia:",
        "search_type":"Tipo ricerca:",
        "search_total":"Totale (solo IP privati)",
        "search_private":"Privati in subnet specifica",
        "subnet":"Subnet:",
        "start":"▶️ Avvia",
        "stop":"⏹️ Stop",
        "save":"💾 Salva (TXT)",
        "reset":"🧹 Reset",
        "sniffer_started":"Sniffer avviato su interfaccia: {iface}",
        "sniffer_stopped":"Sniffer fermato",
        "table_ip":"IP",
        "table_mac":"MAC",
        "table_host":"Hostname",
        "table_first":"Primo rilevamento",
        "warn_running":"Sniffer già in esecuzione",
        "err_select_iface":"Seleziona un'interfaccia",
        "err_enter_subnet":"Inserisci una subnet valida",
        "err_bad_subnet":"Formato subnet non valido",
        "info_nodata":"Nessun dato da salvare",
        "save_dialog":"Salva report (TXT)",
        "save_filter":"File di testo (*.txt)",
        "save_success":"Report salvato in: {path}",
        "log_reset":"Tabella resettata",
        "log_saved":"Report salvato: {path}",
        "new_device":"Nuovo dispositivo: {ip} ({mac}) - Hostname: {host}",
        "language":"Lingua:",
        "status_idle":"In attesa",
        "status_running":"In esecuzione",
        "status_stopped":"Fermato",
        "details_title":"Dettagli dispositivo",
        "details_ip":"IP",
        "details_mac":"MAC",
        "details_host":"Hostname",
        "details_first":"Primo rilevamento",
        "footer_version":"v2.0.0",
        "footer_by":"Lucio Gigliofiorito",
    },
    "fr": {
        "app_title":"IP Discovery Monitor",
        "iface":"Interface :",
        "search_type":"Type de recherche :",
        "search_total":"Total (IP privées uniquement)",
        "search_private":"Privées dans un sous-réseau spécifique",
        "subnet":"Sous-réseau :",
        "start":"▶️ Démarrer",
        "stop":"⏹️ Arrêter",
        "save":"💾 Enregistrer (TXT)",
        "reset":"🧹 Réinitialiser",
        "sniffer_started":"Sniffer démarré sur l'interface : {iface}",
        "sniffer_stopped":"Sniffer arrêté",
        "table_ip":"IP",
        "table_mac":"MAC",
        "table_host":"Hostname",
        "table_first":"Première détection",
        "warn_running":"Sniffer déjà en cours d'exécution",
        "err_select_iface":"Sélectionnez une interface",
        "err_enter_subnet":"Entrez un sous-réseau valide",
        "err_bad_subnet":"Format de sous-réseau invalide",
        "info_nodata":"Aucune donnée à enregistrer",
        "save_dialog":"Enregistrer le rapport (TXT)",
        "save_filter":"Fichiers texte (*.txt)",
        "save_success":"Rapport enregistré dans : {path}",
        "log_reset":"Table réinitialisée",
        "log_saved":"Rapport enregistré : {path}",
        "new_device":"Nouvel appareil : {ip} ({mac}) - Hostname : {host}",
        "language":"Langue :",
        "status_idle":"En attente",
        "status_running":"En cours",
        "status_stopped":"Arrêté",
        "details_title":"Détails de l'appareil",
        "details_ip":"IP",
        "details_mac":"MAC",
        "details_host":"Hostname",
        "details_first":"Première détection",
        "footer_version":"v2.0.0",
        "footer_by":"Lucio Gigliofiorito",
    },
    "es": {
        "app_title":"IP Discovery Monitor",
        "iface":"Interfaz:",
        "search_type":"Tipo de búsqueda:",
        "search_total":"Total (solo IP privadas)",
        "search_private":"Privadas en subred específica",
        "subnet":"Subred:",
        "start":"▶️ Iniciar",
        "stop":"⏹️ Detener",
        "save":"💾 Guardar (TXT)",
        "reset":"🧹 Reset",
        "sniffer_started":"Sniffer iniciado en la interfaz: {iface}",
        "sniffer_stopped":"Sniffer detenido",
        "table_ip":"IP",
        "table_mac":"MAC",
        "table_host":"Hostname",
        "table_first":"Primera detección",
        "warn_running":"Sniffer ya está en ejecución",
        "err_select_iface":"Selecciona una interfaz",
        "err_enter_subnet":"Introduce una subred válida",
        "err_bad_subnet":"Formato de subred no válido",
        "info_nodata":"No hay datos para guardar",
        "save_dialog":"Guardar informe (TXT)",
        "save_filter":"Archivos de texto (*.txt)",
        "save_success":"Informe guardado en: {path}",
        "log_reset":"Tabla reiniciada",
        "log_saved":"Informe guardado: {path}",
        "new_device":"Nuevo dispositivo: {ip} ({mac}) - Hostname: {host}",
        "language":"Idioma:",
        "status_idle":"Inactivo",
        "status_running":"En ejecución",
        "status_stopped":"Detenido",
        "details_title":"Detalles del dispositivo",
        "details_ip":"IP",
        "details_mac":"MAC",
        "details_host":"Hostname",
        "details_first":"Primera detección",
        "footer_version":"v2.0.0",
        "footer_by":"Lucio Gigliofiorito",
    },
    "de": {
        "app_title":"IP Discovery Monitor",
        "iface":"Schnittstelle:",
        "search_type":"Suchtyp:",
        "search_total":"Gesamt (nur private IPs)",
        "search_private":"Private in spezifischem Subnetz",
        "subnet":"Subnetz:",
        "start":"▶️ Start",
        "stop":"⏹️ Stop",
        "save":"💾 Speichern (TXT)",
        "reset":"🧹 Zurücksetzen",
        "sniffer_started":"Sniffer auf Schnittstelle gestartet: {iface}",
        "sniffer_stopped":"Sniffer gestoppt",
        "table_ip":"IP",
        "table_mac":"MAC",
        "table_host":"Hostname",
        "table_first":"Erst gesehen",
        "warn_running":"Sniffer läuft bereits",
        "err_select_iface":"Wähle eine Schnittstelle",
        "err_enter_subnet":"Gib ein gültiges Subnetz ein",
        "err_bad_subnet":"Ungültiges Subnetzformat",
        "info_nodata":"Keine Daten zu speichern",
        "save_dialog":"Bericht speichern (TXT)",
        "save_filter":"Textdateien (*.txt)",
        "save_success":"Bericht gespeichert unter: {path}",
        "log_reset":"Tabelle zurückgesetzt",
        "log_saved":"Bericht gespeichert: {path}",
        "new_device":"Neues Gerät: {ip} ({mac}) - Hostname: {host}",
        "language":"Sprache:",
        "status_idle":"Wartend",
        "status_running":"Läuft",
        "status_stopped":"Gestoppt",
        "details_title":"Gerätedetails",
        "details_ip":"IP",
        "details_mac":"MAC",
        "details_host":"Hostname",
        "details_first":"Erst gesehen",
        "footer_version":"v2.0.0",
        "footer_by":"Lucio Gigliofiorito",
    },
}
class SortableItem(QTableWidgetItem):
    def __init__(self, text, sort_key=None):
        super().__init__(text)
        self.sort_key = sort_key if sort_key is not None else text
        self.setFlags(self.flags() ^ Qt.ItemFlag.ItemIsEditable)

    def __lt__(self, other):
        if isinstance(other, SortableItem):
            return self.sort_key < other.sort_key
        return super().__lt__(other)

def ip_sort_key(ip_str):
    try:
        return int(ipaddress.ip_address(ip_str))
    except Exception:
        return -1

def date_sort_key(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return 0
class SnifferWorker(QThread):
    device_found = pyqtSignal(str, str, str)
    error        = pyqtSignal(str)
    pkt_count    = pyqtSignal(int)

    def __init__(self, interface, search_type, subnet):
        super().__init__()
        self.interface   = interface
        self.search_type = search_type
        self.subnet      = subnet
        self._stop       = False
        self._detected   = set()
        self._packet_tot = 0
        self._last_emit  = time.time()

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        capture = None
        try:
            capture = pyshark.LiveCapture(interface=self.interface, use_json=True)
            if not hasattr(capture, "_running_processes"):
                capture._running_processes = []

            for packet in capture.sniff_continuously():
                if self._stop:
                    break
                self._packet_tot += 1
                self._handle_packet(packet)

                now = time.time()
                if now - self._last_emit >= 1:
                    self.pkt_count.emit(self._packet_tot)
                    self._last_emit = now

                try:
                    del packet
                except Exception:
                    pass

        except Exception as e:
            if not self._stop:
                self.error.emit(str(e))
        finally:
            try:
                if capture:
                    capture.close()
            except Exception:
                pass
            try:
                loop.stop()
            except Exception:
                pass
            loop.close()
            asyncio.set_event_loop(None)

    def stop(self):
        self._stop = True

    def _hostname(self, ip):
        try:
            h = socket.gethostbyaddr(ip)[0]
            return h if h != ip else "N/A"
        except Exception:
            return "N/A"

    def _handle_packet(self, packet):
        try:
            ip_src = packet.ip.src
        except AttributeError:
            return
        mac_src = getattr(getattr(packet, 'eth', None), 'src', "N/A")

        if self.search_type == "total" and not ipaddress.ip_address(ip_src).is_private:
            return
        if self.search_type == "private" and self.subnet and ipaddress.ip_address(ip_src) not in self.subnet:
            return

        host = self._hostname(ip_src)
        det  = (ip_src, mac_src, host)
        if det not in self._detected:
            self._detected.add(det)
            self.device_found.emit(ip_src, mac_src, host)
class DeviceDialog(QDialog):
    def __init__(self, strings, data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(strings["details_title"])
        form = QFormLayout(self)
        form.addRow(strings["details_ip"]   + ":", QLabel(data["ip"]))
        form.addRow(strings["details_mac"]  + ":", QLabel(data["mac"]))
        form.addRow(strings["details_host"] + ":", QLabel(data["hostname"]))
        form.addRow(strings["details_first"]+ ":", QLabel(data["first"]))
class MainWindow(QWidget):
    def __init__(self, icon_path, default_lang="en"):
        super().__init__()
        self.setWindowIcon(QIcon(icon_path))

        self.current_lang = default_lang if default_lang in STRINGS else "en"
        self.worker       = None
        self.search_type  = "total"
        self.subnet       = None
        self.interface    = None
        self.results      = []

        self.max_points   = 120
        self.traffic_data = deque(maxlen=self.max_points)
        self._last_pkt    = 0

        self._init_refs()
        self._build_ui()
        self._load_ifaces()
        self.apply_i18n()
        self.set_status("idle")

    def _init_refs(self):
        self.lbl_iface = QLabel(); self.lbl_search_type = QLabel()
        self.lbl_subnet = QLabel(); self.lbl_language = QLabel()
        self.status_dot = QLabel("●"); self.status_text = QLabel()

        self.iface_combo = QComboBox(); self.search_type_combo = QComboBox()
        self.subnet_edit = QLineEdit(); self.lang_combo = QComboBox()

        self.start_btn = QPushButton(); self.stop_btn = QPushButton()
        self.save_btn  = QPushButton(); self.reset_btn = QPushButton()

        self.table    = QTableWidget(0, 4)
        self.log_box  = QTextEdit()
        self.plot_widget = pg.PlotWidget() if pg else None
        self.footer_lbl = QLabel()

    def _build_ui(self):
        self.setMinimumSize(1050, 720)
        root = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(self.lbl_language)
        for code, name in LANGS.items():
            self.lang_combo.addItem(name, code)
        self.lang_combo.setCurrentIndex(list(LANGS.keys()).index(self.current_lang))
        self.lang_combo.currentIndexChanged.connect(lambda _: self._on_lang_changed())
        top.addWidget(self.lang_combo)

        top.addStretch()
        self.status_dot.setFixedWidth(18)
        self.status_text.setMinimumWidth(90)
        top.addWidget(self.status_dot); top.addWidget(self.status_text)
        root.addLayout(top)
        ctl = QHBoxLayout()
        ctl.addWidget(self.lbl_iface); ctl.addWidget(self.iface_combo, 2)
        ctl.addWidget(self.lbl_search_type)
        self.search_type_combo.currentIndexChanged.connect(self._on_search_type_changed)
        ctl.addWidget(self.search_type_combo, 2)
        ctl.addWidget(self.lbl_subnet)
        self.subnet_edit.setPlaceholderText("192.168.1.0/24"); self.subnet_edit.setEnabled(False)
        ctl.addWidget(self.subnet_edit, 2)
        root.addLayout(ctl)
        btns = QHBoxLayout()
        self.start_btn.clicked.connect(self.start_sniffer); btns.addWidget(self.start_btn)
        self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop_sniffer); btns.addWidget(self.stop_btn)
        self.save_btn.clicked.connect(self.save_report); btns.addWidget(self.save_btn)
        self.reset_btn.clicked.connect(self.reset_table); btns.addWidget(self.reset_btn)
        root.addLayout(btns)
        main_split = QSplitter(Qt.Orientation.Vertical)
        up_split   = QSplitter(Qt.Orientation.Vertical)

        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(self.show_details_dialog)
        up_split.addWidget(self.table)

        self.log_box.setReadOnly(True)
        up_split.addWidget(self.log_box)
        up_split.setSizes([400,170])
        main_split.addWidget(up_split)

        if pg:
            self.plot_widget.showGrid(x=True, y=True)
            self.plot_widget.setLabel('left','Packets/s')
            self.plot_widget.setLabel('bottom','t')
            self.curve = self.plot_widget.plot()
            main_split.addWidget(self.plot_widget)
            main_split.setSizes([500,180])
        else:
            dummy = QLabel("pyqtgraph not installed - no traffic graph")
            dummy.setAlignment(Qt.AlignmentFlag.AlignCenter)
            main_split.addWidget(dummy)
            main_split.setSizes([600,80])

        root.addWidget(main_split)
        self.footer_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.footer_lbl.setTextFormat(Qt.TextFormat.RichText)
        self.footer_lbl.setOpenExternalLinks(True)
        root.addWidget(self.footer_lbl)

    def _load_ifaces(self):
        for iface in psutil.net_if_addrs().keys():
            self.iface_combo.addItem(iface)
    def t(self, key, **kw):
        return STRINGS[self.current_lang].get(key, key).format(**kw)

    def apply_i18n(self):
        self.setWindowTitle(self.t("app_title"))
        self.lbl_iface.setText(self.t("iface"))
        self.lbl_search_type.setText(self.t("search_type"))
        self.lbl_subnet.setText(self.t("subnet"))
        self.lbl_language.setText(self.t("language"))

        self.start_btn.setText(self.t("start"))
        self.stop_btn.setText(self.t("stop"))
        self.save_btn.setText(self.t("save"))
        self.reset_btn.setText(self.t("reset"))

        self.search_type_combo.blockSignals(True)
        self.search_type_combo.clear()
        self.search_type_combo.addItems([self.t("search_total"), self.t("search_private")])
        self.search_type_combo.setCurrentIndex(0 if self.search_type == "total" else 1)
        self.search_type_combo.blockSignals(False)

        self.table.setHorizontalHeaderLabels([
            self.t("table_ip"), self.t("table_mac"),
            self.t("table_host"), self.t("table_first")
        ])

        if hasattr(self, "_current_status"):
            self.set_status(self._current_status)
        gh_icon = resource_path("assets/github.png")
        footer = f"{self.t('footer_version')} • <a href='https://github.com/Angrido'>{self.t('footer_by')}</a>"
        self.footer_lbl.setText(footer)

    def set_status(self, state):
        self._current_status = state
        colors = {"idle":"#9E9E9E","running":"#4CAF50","stopped":"#F44336"}
        texts  = {"idle":self.t("status_idle"),"running":self.t("status_running"),"stopped":self.t("status_stopped")}
        self.status_dot.setStyleSheet(f"color:{colors.get(state,'#9E9E9E')}; font-size:18px;")
        self.status_text.setText(texts.get(state, state))
    def _on_lang_changed(self):
        self.current_lang = self.lang_combo.currentData()
        self.apply_i18n()

    def _on_search_type_changed(self, idx):
        if idx == 0:
            self.search_type = "total"
            self.subnet_edit.setEnabled(False)
        else:
            self.search_type = "private"
            self.subnet_edit.setEnabled(True)

    def start_sniffer(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, self.t("app_title"), self.t("warn_running"))
            return

        self.interface = self.iface_combo.currentText()
        if not self.interface:
            QMessageBox.critical(self, self.t("app_title"), self.t("err_select_iface"))
            return

        if self.search_type == "private":
            val = self.subnet_edit.text().strip()
            if not val:
                QMessageBox.critical(self, self.t("app_title"), self.t("err_enter_subnet"))
                return
            try:
                self.subnet = ipaddress.ip_network(val, strict=False)
            except ValueError:
                QMessageBox.critical(self, self.t("app_title"), self.t("err_bad_subnet"))
                return
        else:
            self.subnet = None

        self._last_pkt = 0
        self.traffic_data.clear()

        self.worker = SnifferWorker(self.interface, self.search_type, self.subnet)
        self.worker.device_found.connect(self._on_device_found)
        self.worker.error.connect(self._on_error)
        self.worker.pkt_count.connect(self._on_pkt_count)
        self.worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.set_status("running")
        self.log(self.t("sniffer_started", iface=self.interface))

    def stop_sniffer(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)
            self.log(self.t("sniffer_stopped"))
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.set_status("stopped")

    def reset_table(self):
        self.table.setRowCount(0)
        self.results.clear()
        self.log(self.t("log_reset"))

    def save_report(self):
        if not self.results:
            QMessageBox.information(self, self.t("app_title"), self.t("info_nodata"))
            return
        default = os.path.expanduser('~') + "/Downloads/scan_results_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"
        path, _ = QFileDialog.getSaveFileName(self, self.t("save_dialog"), default, self.t("save_filter"))
        if not path:
            return
        if not path.lower().endswith(".txt"):
            path += ".txt"
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("Scan Results\n" + "-"*40 + "\n")
                for r in self.results:
                    f.write(f"IP: {r['ip']}\tMAC: {r['mac']}\tHostname: {r['hostname']}\tFirstSeen: {r['first']}\n")
                f.write("-"*40 + "\n")
            QMessageBox.information(self, self.t("app_title"), self.t("save_success", path=path))
            self.log(self.t("log_saved", path=path))
        except Exception as e:
            QMessageBox.critical(self, self.t("app_title"), str(e))

    def closeEvent(self, e):
        if self.worker and self.worker.isRunning():
            self.worker.stop(); self.worker.wait(2000)
        e.accept()
    def _on_device_found(self, ip, mac, host):
        mac  = mac  or "N/A"
        host = host or "N/A"
        now  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)

        row = self.table.rowCount()
        self.table.insertRow(row)

        ip_item   = SortableItem(ip,  ip_sort_key(ip))
        mac_item  = SortableItem(mac)
        host_item = SortableItem(host)
        date_item = SortableItem(now, date_sort_key(now))

        self.table.setItem(row, 0, ip_item)
        self.table.setItem(row, 1, mac_item)
        self.table.setItem(row, 2, host_item)
        self.table.setItem(row, 3, date_item)

        self.results.append({"ip": ip, "mac": mac, "hostname": host, "first": now})

        self.table.setSortingEnabled(was_sorting)

        self.log(self.t("new_device", ip=ip, mac=mac, host=host))

    def _on_error(self, msg):
        QMessageBox.warning(self, self.t("app_title"), msg)
        self.log(msg)

    def _on_pkt_count(self, total):
        delta = total - self._last_pkt
        self._last_pkt = total
        if pg:
            self.traffic_data.append(delta)
            self.curve.setData(range(len(self.traffic_data)), list(self.traffic_data))

    def log(self, text):
        self.log_box.append(f"[{datetime.now().strftime('%H:%M:%S')}] {text}")

    def show_details_dialog(self, index):
        r = index.row()
        if r < 0 or r >= len(self.results):
            return
        DeviceDialog(STRINGS[self.current_lang], self.results[r], self).exec()
def resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)
if __name__ == "__main__":
    app = QApplication(sys.argv)
    try:
        import qdarktheme
        qdarktheme.setup_theme("dark")
    except Exception:
        pass

    icon_path = resource_path("assets/ip_device_scan.png")
    app.setWindowIcon(QIcon(icon_path))

    win = MainWindow(icon_path=icon_path, default_lang="en")
    win.show()
    sys.exit(app.exec())