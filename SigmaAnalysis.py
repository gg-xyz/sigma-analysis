
import os
import re
import sys
import json
import threading
import subprocess
import tempfile
import shutil
from pathlib import Path
import platform
import zipfile
import base64
import mimetypes
import requests
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QFileDialog
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QWidget, QLabel, QTextEdit 
from PyQt5.QtWidgets import QTabWidget, QLineEdit, QStatusBar, QScrollArea, QFrame
from PyQt5.QtWidgets import QListWidget, QMessageBox, QListWidgetItem, QSplitter
from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QGroupBox, QCheckBox, QComboBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QUrl
from PyQt5.QtGui import QIcon, QFont, QPixmap, QDrag, QDragEnterEvent, QDropEvent, QColor
class SettingsDialog(QDialog):
    """Settings dialog for application configuration"""
    def __init__(self, current_settings, parent=None):
        super().__init__(parent)
        self.current_settings = current_settings.copy()
        self.setWindowTitle("Sigma Analysis Settings")
        self.setMinimumWidth(500)
        
        # Apply theme
        self.setStyleSheet(get_app_style(current_settings["theme"]))
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Default tab section
        default_tab_group = QGroupBox("Default View")
        default_tab_layout = QVBoxLayout(default_tab_group)
        
        self.default_tab_combo = QComboBox()
        self.default_tab_combo.addItem("Overview")
        self.default_tab_combo.addItem("Indicators")
        self.default_tab_combo.addItem("Configuration")
        self.default_tab_combo.addItem("Strings")
        self.default_tab_combo.addItem("Quick Web")
        self.default_tab_combo.setCurrentIndex(current_settings["default_tab"])
        
        default_tab_layout.addWidget(QLabel("Default tab when opening results:"))
        default_tab_layout.addWidget(self.default_tab_combo)
        
        # Theme section
        theme_group = QGroupBox("Application Theme")
        theme_layout = QVBoxLayout(theme_group)
        
        self.theme_combo = QComboBox()
        for theme_name in THEMES.keys():
            self.theme_combo.addItem(theme_name)
        
        # Set current theme
        index = self.theme_combo.findText(current_settings["theme"])
        if index >= 0:
            self.theme_combo.setCurrentIndex(index)
            
        theme_layout.addWidget(QLabel("Select theme:"))
        theme_layout.addWidget(self.theme_combo)
        
        # Auto-analyze section
        auto_analyze_group = QGroupBox("Analysis Options")
        auto_analyze_layout = QVBoxLayout(auto_analyze_group)
        
        self.auto_analyze_check = QCheckBox("Automatically analyze when file is selected")
        self.auto_analyze_check.setChecked(current_settings.get("auto_analyze", False))
        
        auto_analyze_layout.addWidget(self.auto_analyze_check)
        
        # Discord webhook section
        webhook_group = QGroupBox("Discord Integration")
        webhook_layout = QVBoxLayout(webhook_group)
        
        self.webhook_input = QLineEdit(current_settings.get("discord_webhook", ""))
        self.webhook_input.setPlaceholderText("Enter Discord webhook URL")
        
        self.send_webhook_check = QCheckBox("Automatically send results to webhook")
        self.send_webhook_check.setChecked(current_settings.get("send_to_webhook", False))
        
        webhook_layout.addWidget(QLabel("Discord webhook URL:"))
        webhook_layout.addWidget(self.webhook_input)
        webhook_layout.addWidget(self.send_webhook_check)
        
        # Test webhook button
        self.test_webhook_button = QPushButton("Test Webhook")
        self.test_webhook_button.clicked.connect(self.test_webhook)
        webhook_layout.addWidget(self.test_webhook_button)
        
        # Add all sections to main layout
        layout.addWidget(default_tab_group)
        layout.addWidget(theme_group)
        layout.addWidget(auto_analyze_group)
        layout.addWidget(webhook_group)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
    def get_settings(self):
        """Get the current settings"""
        self.current_settings["default_tab"] = self.default_tab_combo.currentIndex()
        self.current_settings["theme"] = self.theme_combo.currentText()
        self.current_settings["auto_analyze"] = self.auto_analyze_check.isChecked()
        self.current_settings["discord_webhook"] = self.webhook_input.text().strip()
        self.current_settings["send_to_webhook"] = self.send_webhook_check.isChecked()
        
        return self.current_settings
        
    def test_webhook(self):
        """Test the Discord webhook"""
        webhook_url = self.webhook_input.text().strip()
        
        if not webhook_url:
            QMessageBox.warning(self, "Invalid Webhook", "Please enter a Discord webhook URL first.")
            return
            
        try:
            # Prepare test webhook data
            webhook_data = {
                "embeds": [
                    {
                        "title": "Sigma Analysis: Webhook Test",
                        "description": "This is a test message from Sigma Analysis tool. If you're seeing this, your webhook is configured correctly!",
                        "color": 0x00ff00,  # Green color
                        "footer": {
                            "text": f"Sigma Analysis Tool • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        }
                    }
                ]
            }
            
            # Send to Discord webhook
            response = requests.post(
                webhook_url,
                json=webhook_data
            )
            
            if response.status_code == 204:
                QMessageBox.information(self, "Webhook Test", "Webhook test successful! Check your Discord channel.")
            else:
                QMessageBox.warning(self, "Webhook Test Failed", f"Error: HTTP status code {response.status_code}")
                
        except Exception as e:
            QMessageBox.critical(self, "Webhook Test Error", f"Error: {str(e)}")


# More comprehensive malware family detection database
IMPROVED_MALWARE_FAMILIES = {
    # Information stealers
    'RedLine Stealer': {
        'description': 'Information-stealing malware that targets credentials, crypto wallets, and system data',
        'type': 'Information Stealer',
        'indicators': [
            (r'redlinestealer', 'string'),
            (r'RedLineStealer', 'string'),
            (r'redline\.', 'regex'),
            (r'grab_browsers\.', 'string'),
            (r'https?://.*\.(top|space|xyz|club)/gate\.php', 'regex'),
            (r'bot_id|hwid', 'string'),
            (r'browser_passwords|browser_cookies|crypto_wallets', 'regex'),
            (r'screenshot_grabber', 'string'),
            (r'data_collector', 'string'),
            (r'FtpClients|VpnClients|MessengerClients', 'regex')
        ]
    },
    'Agent Tesla': {
        'description': 'Remote access trojan and keylogger that collects credentials and system information',
        'type': 'RAT / Keylogger',
        'indicators': [
            (r'agenttesla', 'string'),
            (r'AgentTesla', 'string'),
            (r'agenttsl', 'string'),
            (r'atexec', 'string'),
            (r'smtp_(?:creds|config)', 'regex'),
            (r'keylog', 'string'),
            (r'password_recovery', 'string'),
            (r'GetKeyboardState|GetAsyncKeyState', 'regex'),
            (r'WebMail|WebPanel', 'regex'),
            (r'screenshot_interval', 'string'),
            (r'RecordKeys|KeyboardCapture', 'regex'),
            (r'mail_client_credentials', 'string')
        ]
    },
    'Raccoon Stealer': {
        'description': 'Info-stealer targeting browser data, cryptocurrency wallets, and credentials',
        'type': 'Information Stealer',
        'indicators': [
            (r'raccoon', 'string'),
            (r'RaccoonStealer', 'string'),
            (r'raccoongrab', 'string'),
            (r'racoon', 'string'),  # Common misspelling
            (r'c2_url=', 'string'),
            (r'steal_cookies|steal_wallets', 'regex'),
            (r'RecordCredentials|DataStealer', 'regex'),
            (r'GetPasswords|GetCookies|GetAutofill', 'regex'),
            (r'CryptoExtension|WalletStealer', 'regex'),
            (r'telegram_credential', 'string')
        ]
    },
    'Formbook': {
        'description': 'Information stealer with form grabbing, keylogging, and screenshot capabilities',
        'type': 'Information Stealer / Keylogger',
        'indicators': [
            (r'formbook', 'string'),
            (r'FormBook', 'string'),
            (r'XLoader', 'string'),  # Formbook variant
            (r'form_grabber', 'string'),
            (r'send_logs\.php', 'string'),
            (r'api/formlog', 'string'),
            (r'FormGrabber|KeyLogger|ScreenLogger', 'regex'),
            (r'GetWindowTextW|GetClipboardData', 'regex'),
            (r'InternetReadFile|InternetWriteFile', 'regex'),
            (r'HttpSendRequestA|HttpOpenRequestA', 'regex')
        ]
    },
    # RATs
    'AsyncRAT': {
        'description': 'Remote access trojan with extensive capabilities for controlling infected machines',
        'type': 'Remote Access Trojan',
        'indicators': [
            (r'asyncrat', 'string'),
            (r'AsyncRAT', 'string'),
            (r'async_client', 'string'),
            (r'plugins/keylogger', 'string'),
            (r'socket_connect', 'string'),
            (r'RemoteDesktop|RemoteCamera|RemoteControl', 'regex'),
            (r'keylogger_plugin|webcam_plugin|audio_plugin', 'regex'),
            (r'system_information_plugin', 'string'),
            (r'file_manager_plugin', 'string'),
            (r'process_manager_plugin', 'string')
        ]
    },
    'NjRAT': {
        'description': 'Remote access trojan targeting Windows systems',
        'type': 'Remote Access Trojan',
        'indicators': [
            (r'njrat', 'string'),
            (r'NjRat', 'string'),
            (r'njw0rm', 'string'),
            (r'Njw0rm', 'string'),
            (r'netframework', 'string'),
            (r'NjRAT_.+_stub', 'regex'),
            (r'cmd\.Prepare\(|cmd\.Start\(', 'regex'),
            (r'cam|mic|chat|plg', 'regex'),
            (r'RemoteShell|RemoteCamera|RemoteChat', 'regex'),
            (r'ProcessManager|RegistryManager|ServiceManager', 'regex')
        ]
    },
    # Banking Trojans
    'TrickBot': {
        'description': 'Banking trojan and credential stealer that has evolved into a multi-purpose malware',
        'type': 'Banking Trojan / Botnet',
        'indicators': [
            (r'trickbot', 'string'),
            (r'TrickBot', 'string'),
            (r'trick_config', 'string'),
            (r'group_tag', 'string'),
            (r'module=injectDll', 'string'),
            (r'gtag=|servconf|mexec', 'regex'),
            (r'moduleconfig|systeminfo|autorun', 'regex'),
            (r'user_platform|bot_version|user_country', 'regex'),
            (r'<servconf>|<mcconf>|<moduleinfo>', 'regex'),
            (r'webinject|formgrabber|task', 'regex')
        ]
    },
    'QakBot': {
        'description': 'Banking trojan with worm capabilities for spreading across networks',
        'type': 'Banking Trojan / Worm',
        'indicators': [
            (r'qakbot', 'string'),
            (r'QakBot', 'string'),
            (r'qbot', 'string'),
            (r'QBot', 'string'),
            (r'obama\\system32', 'string'),
            (r'pony\\system32', 'string'),
            (r'C:\\ProgramData\\[A-Za-z]{8}', 'regex'),
            (r'InstallPath=|TaskFolder=|TaskName=', 'regex'),
            (r'EmailPasswords|BrowserPasswords|BrowserCookies', 'regex'),
            (r'wmic\.exe.+\s+shadowcopy', 'regex')
        ]
    },
    # Ransomware
    'Lockbit': {
        'description': 'Ransomware-as-a-service that encrypts files and demands payment for decryption',
        'type': 'Ransomware',
        'indicators': [
            (r'lockbit', 'string'),
            (r'LockBit', 'string'),
            (r'lock-bit', 'string'),
            (r'locker_', 'string'),
            (r'\.lockbit', 'string'),
            (r'Restore-My-Files\.txt', 'string'),
            (r'encryption_key|decryption_key', 'regex'),
            (r'README\.txt|RESTORE\.txt', 'regex'),
            (r'vssadmin delete shadows', 'string'),
            (r'bcdedit /set {default} bootstatuspolicy ignoreallfailures', 'string')
        ]
    },
    'REvil': {
        'description': 'Ransomware-as-a-service that targets high-value organizations',
        'type': 'Ransomware',
        'indicators': [
            (r'revil', 'string'),
            (r'REvil', 'string'),
            (r'Sodinokibi', 'string'),
            (r'sodin', 'string'),
            (r'\.rvil', 'string'),
            (r'README\.txt|DECRYPTION\.txt', 'regex'),
            (r'vssadmin delete shadows', 'string'),
            (r'Your_Files_Are_Encrypted', 'string'),
            (r'enter personal code', 'string'),
            (r'ransom\.', 'regex')
        ]
    },
    # Cryptominers
    'XMRig': {
        'description': 'Cryptocurrency miner focused on Monero (XMR)',
        'type': 'Cryptocurrency Miner',
        'indicators': [
            (r'xmrig', 'string'),
            (r'XMRig', 'string'),
            (r'monero', 'string'),
            (r'stratum\+tcp://', 'regex'),
            (r'pool\.minexmr\.com', 'string'),
            (r'hashrate', 'string'),
            (r'cryptonight', 'string'),
            (r'randomx', 'string'),
            (r'donate-level', 'string'),
            (r'rx/0', 'string')
        ]
    }
}
# Dependency installer function
def install_dependencies():
    """Check and install required dependencies"""
    required_packages = [
        'PyQt5',
        'requests',
        'pyaxmlparser',
        'pefile',
        'androguard',
        'uncompyle6',
        'colorama'
    ]
    
    # Check if each package is installed, install if not
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package} is already installed")
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✓ {package} installed successfully")

# Install dependencies before imports
print("Checking dependencies...")
install_dependencies()

# Now import the dependencies
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QFileDialog, 
                             QVBoxLayout, QHBoxLayout, QWidget, QLabel, QTextEdit, 
                             QTabWidget, QLineEdit, QStatusBar, QScrollArea, QFrame,
                             QListWidget, QMessageBox, QListWidgetItem, QSplitter,
                             QDialog, QDialogButtonBox, QGroupBox, QCheckBox, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QUrl
from PyQt5.QtGui import QIcon, QFont, QPixmap, QDrag, QDragEnterEvent, QDropEvent, QColor

import requests
import pefile

# Regex patterns for common malware indicators
PATTERNS = {
    'urls': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[/\w\.-=&%]*',
    'discord_webhooks': r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+',
    'telegram_bots': r'[0-9]{9}:[a-zA-Z0-9_-]{35}',
    'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'bitcoin_addresses': r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',
    'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'domain_names': r'(?:https?://|ftp://|)?(?<!\w)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|info|biz|xyz|online|site|shop|app|dev|me|us|uk|ru|cn|de|jp|fr|au|ca|nl|br|it|pl|in|se|ch|es|no|fi|nz|za|mx|sg|kr|pt|at|dk|ie|be|tr|il|hk|vn|cl|id|th|ph)[a-zA-Z]{0,3})(?!\w)',
    'registry_keys': r'HKEY_[A-Za-z_]+\\[A-Za-z0-9\\]+',
    'aws_keys': r'AKIA[0-9A-Z]{16}'
}

# Known malware families and their signatures
MALWARE_FAMILIES = {
    'RedLine Stealer': {
        'description': 'Information-stealing malware that targets credentials, crypto wallets, and system data',
        'type': 'Information Stealer',
        'indicators': [
            (r'redlinestealer', 'string'),
            (r'RedLineStealer', 'string'),
            (r'grab_browsers\.', 'string'),
            (r'https?://.*\.(top|space|xyz|club)/gate\.php', 'regex'),
            (r'bot_id|hwid', 'string')
        ]
    },
    'Agent Tesla': {
        'description': 'Remote access trojan and keylogger that collects credentials and system information',
        'type': 'RAT / Keylogger',
        'indicators': [
            (r'agenttesla', 'string'),
            (r'AgentTesla', 'string'),
            (r'atexec', 'string'),
            (r'smtp_(?:creds|config)', 'regex'),
            (r'keylog', 'string'),
            (r'password_recovery', 'string')
        ]
    },
    'Raccoon Stealer': {
        'description': 'Info-stealer targeting browser data, cryptocurrency wallets, and credentials',
        'type': 'Information Stealer',
        'indicators': [
            (r'raccoon', 'string'),
            (r'RaccoonStealer', 'string'),
            (r'raccoongrab', 'string'),
            (r'c2_url=', 'string'),
            (r'steal_cookies|steal_wallets', 'regex')
        ]
    },
    'Formbook': {
        'description': 'Information stealer with form grabbing, keylogging, and screenshot capabilities',
        'type': 'Information Stealer / Keylogger',
        'indicators': [
            (r'formbook', 'string'),
            (r'FormBook', 'string'),
            (r'form_grabber', 'string'),
            (r'send_logs\.php', 'string'),
            (r'api/formlog', 'string')
        ]
    },
    'LokiBot': {
        'description': 'Information stealer targeting credentials from various applications',
        'type': 'Information Stealer',
        'indicators': [
            (r'lokibot', 'string'),
            (r'LokiBot', 'string'),
            (r'loki_', 'string'),
            (r'gate\.php', 'string'),
            (r'fre\.php', 'string')
        ]
    },
    'AsyncRAT': {
        'description': 'Remote access trojan with extensive capabilities for controlling infected machines',
        'type': 'Remote Access Trojan',
        'indicators': [
            (r'asyncrat', 'string'),
            (r'AsyncRAT', 'string'),
            (r'async_client', 'string'),
            (r'plugins/keylogger', 'string'),
            (r'socket_connect', 'string')
        ]
    },
    'Remcos': {
        'description': 'Commercial remote control software often misused as a RAT',
        'type': 'Remote Access Trojan',
        'indicators': [
            (r'remcos', 'string'),
            (r'Remcos', 'string'),
            (r'remcos_client', 'string'),
            (r'RemcomService', 'string'),
            (r'rcid=', 'string')
        ]
    },
    'NjRAT': {
        'description': 'Remote access trojan targeting Windows systems',
        'type': 'Remote Access Trojan',
        'indicators': [
            (r'njrat', 'string'),
            (r'NjRat', 'string'),
            (r'njw0rm', 'string'),
            (r'netframework', 'string'),
            (r'Njw0rm', 'string')
        ]
    },
    'DarkComet': {
        'description': 'Remote access trojan with keylogging and password stealing capabilities',
        'type': 'Remote Access Trojan',
        'indicators': [
            (r'darkcomet', 'string'),
            (r'DarkComet', 'string'),
            (r'DCRAT', 'string'),
            (r'#KCMDDC', 'string'),
            (r'DCR Server', 'string')
        ]
    },
    'TrickBot': {
        'description': 'Banking trojan and credential stealer that has evolved into a multi-purpose malware',
        'type': 'Banking Trojan / Botnet',
        'indicators': [
            (r'trickbot', 'string'),
            (r'TrickBot', 'string'),
            (r'trick_config', 'string'),
            (r'group_tag', 'string'),
            (r'module=injectDll', 'string')
        ]
    },
    'Zeus': {
        'description': 'Banking trojan targeting financial credentials and information',
        'type': 'Banking Trojan',
        'indicators': [
            (r'zeus', 'string'),
            (r'ZeuS', 'string'),
            (r'zeus_report', 'string'),
            (r'config\.bin', 'string'),
            (r'webinjects', 'string')
        ]
    },
    'QakBot': {
        'description': 'Banking trojan with worm capabilities for spreading across networks',
        'type': 'Banking Trojan / Worm',
        'indicators': [
            (r'qakbot', 'string'),
            (r'QakBot', 'string'),
            (r'qbot', 'string'),
            (r'QBot', 'string'),
            (r'obama\\system32', 'string')
        ]
    },
    'Emotet': {
        'description': 'Advanced modular banking trojan that primarily functions as a downloader for other malware',
        'type': 'Banking Trojan / Dropper',
        'indicators': [
            (r'emotet', 'string'),
            (r'Emotet', 'string'),
            (r'e_static_config', 'string'),
            (r'emotetloader', 'string'),
            (r'epoch[1-3]', 'regex')
        ]
    },
    'AZORult': {
        'description': 'Information stealer targeting browser history, cookies, IDs, and cryptocurrency wallets',
        'type': 'Information Stealer',
        'indicators': [
            (r'azorult', 'string'),
            (r'AZORult', 'string'),
            (r'azor_report', 'string'),
            (r'azor_config', 'string'),
            (r'gate\.php', 'string')
        ]
    },
    'Vidar': {
        'description': 'Information stealer targeting browser data, documents, and cryptocurrency wallets',
        'type': 'Information Stealer',
        'indicators': [
            (r'vidar', 'string'),
            (r'Vidar', 'string'),
            (r'vidar_config', 'string'),
            (r'vidar_report', 'string'),
            (r'vidarstealer', 'string')
        ]
    },
    'Snake Keylogger': {
        'description': 'Keylogger with credential stealing and screenshot capabilities',
        'type': 'Keylogger / Stealer',
        'indicators': [
            (r'snake.*keylogger', 'regex'),
            (r'SnakeKeylogger', 'string'),
            (r'snake_log', 'string'),
            (r'snakekeylogger', 'string'),
            (r'snake_config', 'string')
        ]
    },
    'Arkei': {
        'description': 'Information stealer targeting web browser, cryptocurrency data, and FTP credentials',
        'type': 'Information Stealer',
        'indicators': [
            (r'arkei', 'string'),
            (r'Arkei', 'string'),
            (r'arkeigrabber', 'string'),
            (r'arkei_config', 'string'),
            (r'arkei_report', 'string')
        ]
    }
}

# Define application themes
THEMES = {
    "Dark (Default)": {
        "name": "Dark (Default)",
        "background": "#2D2D30",
        "foreground": "#FFFFFF",
        "accent": "#007ACC",
        "accent_hover": "#005A9C",
        "accent_pressed": "#003D6B",
        "field_background": "#1E1E1E",
        "field_foreground": "#DCDCDC",
        "border": "#3F3F46",
        "tab_background": "#2D2D30",
        "tab_selected": "#007ACC",
        "tab_hover": "#3E3E42",
        "scrollbar": "#686868"
    },
    "Light": {
        "name": "Light",
        "background": "#F5F5F5",
        "foreground": "#000000",
        "accent": "#0078D7",
        "accent_hover": "#0067B8",
        "accent_pressed": "#004E8C",
        "field_background": "#FFFFFF",
        "field_foreground": "#000000",
        "border": "#D1D1D1",
        "tab_background": "#E5E5E5",
        "tab_selected": "#0078D7",
        "tab_hover": "#DADADA",
        "scrollbar": "#C1C1C1"
    },
    "Hacker": {
        "name": "Hacker",
        "background": "#0A0A0A",
        "foreground": "#00FF00",
        "accent": "#008F11",
        "accent_hover": "#00670D",
        "accent_pressed": "#004D09",
        "field_background": "#121212",
        "field_foreground": "#00FF00",
        "border": "#008F11",
        "tab_background": "#0A0A0A",
        "tab_selected": "#008F11",
        "tab_hover": "#121212",
        "scrollbar": "#008F11"
    },
    "Night Blue": {
        "name": "Night Blue",
        "background": "#172030",
        "foreground": "#E0E0E0",
        "accent": "#3694FF",
        "accent_hover": "#2D7AD3",
        "accent_pressed": "#1F5A9A",
        "field_background": "#0E1621",
        "field_foreground": "#E0E0E0",
        "border": "#2E3C50",
        "tab_background": "#172030",
        "tab_selected": "#3694FF",
        "tab_hover": "#273850",
        "scrollbar": "#3E4D63"
    },
    "Monokai": {
        "name": "Monokai",
        "background": "#272822",
        "foreground": "#F8F8F2",
        "accent": "#F92672",
        "accent_hover": "#D01A5A",
        "accent_pressed": "#A0164E",
        "field_background": "#1E1F1C",
        "field_foreground": "#F8F8F2",
        "border": "#49483E",
        "tab_background": "#272822",
        "tab_selected": "#F92672",
        "tab_hover": "#3E3D32",
        "scrollbar": "#5E5D52"
    },
    "Solarized": {
        "name": "Solarized",
        "background": "#002B36",
        "foreground": "#839496",
        "accent": "#268BD2",
        "accent_hover": "#1E6EA0",
        "accent_pressed": "#15506E",
        "field_background": "#073642",
        "field_foreground": "#839496",
        "border": "#094352",
        "tab_background": "#002B36",
        "tab_selected": "#268BD2",
        "tab_hover": "#073642",
        "scrollbar": "#094352"
    },
    "Nord": {
        "name": "Nord",
        "background": "#2E3440",
        "foreground": "#D8DEE9",
        "accent": "#5E81AC",
        "accent_hover": "#4C6A8C",
        "accent_pressed": "#3A536D",
        "field_background": "#3B4252",
        "field_foreground": "#D8DEE9",
        "border": "#434C5E",
        "tab_background": "#2E3440",
        "tab_selected": "#5E81AC",
        "tab_hover": "#3B4252",
        "scrollbar": "#4C566A"
    },
    "Dracula": {
        "name": "Dracula",
        "background": "#282A36",
        "foreground": "#F8F8F2",
        "accent": "#BD93F9",
        "accent_hover": "#9A7BD1",
        "accent_pressed": "#7256A5",
        "field_background": "#1E1F29",
        "field_foreground": "#F8F8F2",
        "border": "#44475A",
        "tab_background": "#282A36",
        "tab_selected": "#BD93F9",
        "tab_hover": "#44475A",
        "scrollbar": "#6272A4"
    },
    "High Contrast": {
        "name": "High Contrast",
        "background": "#000000",
        "foreground": "#FFFFFF",
        "accent": "#FFFF00",
        "accent_hover": "#D9D900",
        "accent_pressed": "#B0B000",
        "field_background": "#000000",
        "field_foreground": "#FFFFFF",
        "border": "#FFFFFF",
        "tab_background": "#000000",
        "tab_selected": "#FFFF00",
        "tab_hover": "#333333",
        "scrollbar": "#FFFFFF"
    },
    "Material": {
        "name": "Material",
        "background": "#263238",
        "foreground": "#EEFFFF",
        "accent": "#80CBC4",
        "accent_hover": "#5FA9A1",
        "accent_pressed": "#488C84",
        "field_background": "#1A2327",
        "field_foreground": "#EEFFFF",
        "border": "#37474F",
        "tab_background": "#263238",
        "tab_selected": "#80CBC4",
        "tab_hover": "#37474F",
        "scrollbar": "#546E7A"
    }
}

# Default settings
DEFAULT_SETTINGS = {
    "default_tab": 0,  # 0 = Overview, 1 = Indicators, 2 = Configuration, 3 = Strings, 4 = Quick Web
    "auto_analyze": False,
    "theme": "Dark (Default)",
    "discord_webhook": "",
    "send_to_webhook": False
}

# Initialize application styles
def get_app_style(theme_name="Dark (Default)"):
    """Generate application stylesheet based on selected theme"""
    if theme_name not in THEMES:
        theme_name = "Dark (Default)"
        
    theme = THEMES[theme_name]
    
    return f"""
        QMainWindow {{
            background-color: {theme["background"]};
            color: {theme["foreground"]};
        }}
        QLabel {{
            color: {theme["foreground"]};
            font-size: 14px;
        }}
        QPushButton {{
            background-color: {theme["accent"]};
            color: {theme["foreground"]};
            border: none;
            padding: 8px 12px;
            border-radius: 4px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background-color: {theme["accent_hover"]};
        }}
        QPushButton:pressed {{
            background-color: {theme["accent_pressed"]};
        }}
        QTabWidget::pane {{
            border: 1px solid {theme["border"]};
            background-color: {theme["background"]};
            border-radius: 5px;
        }}
        QTabBar::tab {{
            background-color: {theme["tab_background"]};
            color: {theme["foreground"]};
            padding: 8px 15px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }}
        QTabBar::tab:selected {{
            background-color: {theme["tab_selected"]};
        }}
        QTabBar::tab:hover:!selected {{
            background-color: {theme["tab_hover"]};
        }}
        QTextEdit, QListWidget {{
            background-color: {theme["field_background"]};
            color: {theme["field_foreground"]};
            border: 1px solid {theme["border"]};
            border-radius: 4px;
            font-family: 'Consolas', 'Courier New', monospace;
            padding: 5px;
        }}
        QLineEdit, QComboBox {{
            background-color: {theme["field_background"]};
            color: {theme["field_foreground"]};
            border: 1px solid {theme["border"]};
            border-radius: 4px;
            padding: 5px;
        }}
        QComboBox QAbstractItemView {{
            background-color: {theme["field_background"]};
            color: {theme["field_foreground"]};
            selection-background-color: {theme["accent"]};
            selection-color: {theme["foreground"]};
        }}
        QCheckBox {{
            color: {theme["foreground"]};
        }}
        QCheckBox::indicator:checked {{
            background-color: {theme["accent"]};
            border: 1px solid {theme["border"]};
        }}
        QStatusBar {{
            background-color: {theme["accent"]};
            color: {theme["foreground"]};
        }}
        QScrollBar:vertical {{
            border: none;
            background-color: {theme["background"]};
            width: 10px;
            margin: 0px;
        }}
        QScrollBar::handle:vertical {{
            background-color: {theme["scrollbar"]};
            min-height: 20px;
            border-radius: 5px;
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            border: none;
            background: none;
            height: 0px;
        }}
    """

def load_settings():
    """Load settings from settings.json or create with defaults if not exists"""
    settings_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")
    
    if os.path.exists(settings_path):
        try:
            with open(settings_path, 'r') as f:
                settings = json.load(f)
                
            # Validate settings has all required keys, add defaults for missing ones
            for key, value in DEFAULT_SETTINGS.items():
                if key not in settings:
                    settings[key] = value
                    
            return settings
        except:
            # If there's an error reading, return defaults
            return DEFAULT_SETTINGS
    else:
        # Create settings file with defaults
        try:
            with open(settings_path, 'w') as f:
                json.dump(DEFAULT_SETTINGS, f, indent=4)
        except:
            # If can't write, just continue with defaults in memory
            pass
            
        return DEFAULT_SETTINGS

def save_settings(settings):
    """Save settings to settings.json"""
    settings_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")
    
    try:
        with open(settings_path, 'w') as f:
            json.dump(settings, f, indent=4)
        return True
    except:
        return False

class FileAnalyzerThread(QThread):
    """Thread for file analysis to keep UI responsive"""
    analysis_complete = pyqtSignal(dict)
    progress_update = pyqtSignal(str)
    
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        
    def run(self):
        try:
            file_type = self._determine_file_type()
            self.progress_update.emit(f"Detected file type: {file_type}")
            
            results = {
                'file_info': {
                    'name': os.path.basename(self.file_path),
                    'size': os.path.getsize(self.file_path),
                    'type': file_type
                },
                'indicators': {},
                'config': {},
                'strings': [],
                'malware_info': {
                    'family': 'Unknown',
                    'type': 'Unknown',
                    'description': 'Could not determine malware family',
                    'confidence': 0
                },
                'errors': []
            }
            
            # Extract general indicators from file
            self.progress_update.emit("Extracting indicators...")
            extracted_indicators = self._extract_indicators()
            results['indicators'] = extracted_indicators
            
            # Perform file-specific analysis
            self.progress_update.emit(f"Performing detailed analysis for {file_type}...")
            if file_type == 'PE Executable':
                self._analyze_pe(results)
            elif file_type == 'APK':
                self._analyze_apk(results)
            elif file_type == 'Python':
                self._analyze_python(results)
            elif file_type == 'Batch':
                self._analyze_batch(results)
            else:
                self._analyze_generic(results)
                
            # Extract interesting strings
            self.progress_update.emit("Extracting interesting strings...")
            results['strings'] = self._extract_interesting_strings()
            
            # Identify malware family
            self.progress_update.emit("Identifying malware family...")
            self._identify_malware_family(results)
            
            self.progress_update.emit("Analysis complete!")
            self.analysis_complete.emit(results)
        except Exception as e:
            self.progress_update.emit(f"Error during analysis: {str(e)}")
            results = {'error': str(e)}
            self.analysis_complete.emit(results)
    
    def _determine_file_type(self):
        """Determine the type of file being analyzed without using libmagic"""
        file_extension = os.path.splitext(self.file_path)[1].lower()
        
        # Check file extension first
        if file_extension == '.exe':
            # Verify if it's a PE file by checking for MZ header
            try:
                with open(self.file_path, 'rb') as f:
                    header = f.read(2)
                    if header == b'MZ':
                        return 'PE Executable'
            except:
                pass
                
        elif file_extension == '.apk':
            # Verify if it's a valid APK (zip file with AndroidManifest.xml)
            try:
                if zipfile.is_zipfile(self.file_path):
                    with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                        file_list = zip_ref.namelist()
                        if 'AndroidManifest.xml' in file_list:
                            return 'APK'
            except:
                pass
                
        elif file_extension == '.py':
            # Check if file contains Python syntax
            try:
                with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024)  # Read first 1KB
                    if 'import ' in content or 'def ' in content or 'class ' in content:
                        return 'Python'
            except:
                pass
                
        elif file_extension == '.bat':
            # Simple check for batch file
            try:
                with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024).lower()  # Read first 1KB
                    if '@echo' in content or 'rem ' in content or 'set ' in content:
                        return 'Batch'
            except:
                pass
        
        # Fall back to built-in mime type detection
        mime_type, _ = mimetypes.guess_type(self.file_path)
        
        # If still undetermined, do binary checks
        if not mime_type:
            try:
                with open(self.file_path, 'rb') as f:
                    header = f.read(4)
                    # Check for common file signatures
                    if header.startswith(b'MZ'):
                        return 'PE Executable'
                    elif header.startswith(b'PK\x03\x04'):
                        return 'ZIP/APK'
            except:
                pass
            
            return 'Unknown (Binary)'
            
        return f'Other ({mime_type})'
    
    def _extract_indicators(self):
        """Extract various indicators from the file using regex patterns"""
        indicators = {}
        
        # Python keywords and built-in functions to exclude from domain name detection
        self.python_patterns = [
            r'import\s+\w+',
            r'from\s+\w+\s+import',
            r'class\s+\w+',
            r'def\s+\w+',
            r'\w+\s*=\s*\w+\.\w+\(',
            r'\s*return\s+\w+\.\w+',
            r'print\(',
            r'self\.\w+',
            r'\s*if\s+',
            r'\s*for\s+',
            r'\s*while\s+',
            r'\s*with\s+',
            r'\s*try\s*:',
            r'\s*except\s+',
            r'__\w+__'
        ]
        
        # Read file contents
        try:
            if os.path.getsize(self.file_path) > 10 * 1024 * 1024:  # 10MB limit for text reading
                with open(self.file_path, 'rb') as f:
                    content = f.read()
                    text_content = self._extract_strings_from_binary(content)
            else:
                try:
                    with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        text_content = f.read()
                except:
                    with open(self.file_path, 'rb') as f:
                        content = f.read()
                        text_content = self._extract_strings_from_binary(content)
            
            # Apply regex patterns
            for indicator_type, pattern in PATTERNS.items():
                matches = list(set(re.findall(pattern, text_content)))
                
                # Special handling for domain names to filter out Python code
                if indicator_type == 'domain_names' and matches:
                    # Filter out common Python patterns
                    filtered_matches = []
                    for match in matches:
                        # Skip if it appears to be part of Python code
                        is_python_code = False
                        for py_pattern in self.python_patterns:
                            if re.search(py_pattern, match, re.IGNORECASE) or \
                               any(re.search(r'\b' + re.escape(match) + r'\b', line) and 
                                   re.search(py_pattern, line) 
                                   for line in text_content.split('\n')):
                                is_python_code = True
                                break
                                
                        # Only add if it's not part of Python code
                        if not is_python_code:
                            # Additional validation - check for valid domain structure
                            parts = match.split('.')
                            if len(parts) >= 2 and all(len(part) > 0 for part in parts):
                                filtered_matches.append(match)
                    
                    if filtered_matches:
                        indicators[indicator_type] = filtered_matches
                else:
                    if matches:
                        indicators[indicator_type] = matches
            
            return indicators
        except Exception as e:
            self.progress_update.emit(f"Error extracting indicators: {str(e)}")
            return {'error': str(e)}
    
    def _extract_strings_from_binary(self, binary_data, min_length=4):
        """Extract ASCII and UTF-16 strings from binary data"""
        result = []
        
        # ASCII strings
        current_string = ""
        for byte in binary_data:
            if 32 <= byte <= 127:
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    result.append(current_string)
                current_string = ""
        if len(current_string) >= min_length:
            result.append(current_string)
        
        # UTF-16 strings (simplified approach)
        try:
            utf16_str = binary_data.decode('utf-16', errors='ignore')
            result.extend([s for s in utf16_str.split('\0') if len(s) >= min_length])
        except:
            pass
            
        return '\n'.join(result)
    
    def _analyze_pe(self, results):
        """Analyze PE (Portable Executable) files"""
        try:
            pe = pefile.PE(self.file_path)
            
            # Extract imports
            imports = {}
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8')
                    imports[dll_name] = []
                    for imp in entry.imports:
                        if imp.name:
                            imports[dll_name].append(imp.name.decode('utf-8'))
                        else:
                            imports[dll_name].append(f"Ordinal {imp.ordinal}")
                except:
                    continue
            
            results['config']['imports'] = imports
            
            # Extract PE headers info
            results['config']['timestamp'] = pe.FILE_HEADER.TimeDateStamp
            
            # Extract sections
            sections = []
            for section in pe.sections:
                try:
                    section_name = section.Name.decode('utf-8').strip('\x00')
                    sections.append({
                        'name': section_name,
                        'size': section.SizeOfRawData,
                        'entropy': section.get_entropy()
                    })
                except:
                    continue
            
            results['config']['sections'] = sections
            
            # Extract resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resources = []
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        resource_type_id = resource_type.id
                        resources.append({
                            'type_id': resource_type_id,
                            'name': resource_type.name.decode('utf-8') if resource_type.name else str(resource_type_id)
                        })
                    except:
                        continue
                results['config']['resources'] = resources
            
            pe.close()
        except Exception as e:
            results['errors'].append(f"PE analysis error: {str(e)}")
    
    def _analyze_apk(self, results):
        """Analyze APK files"""
        try:
            # Import here to avoid issues if not installed
            from pyaxmlparser import APK
            apk = APK(self.file_path)
            
            # Extract APK info
            results['config']['package'] = apk.package
            results['config']['version_name'] = apk.version_name
            results['config']['version_code'] = apk.version_code
            results['config']['permissions'] = apk.permissions
            results['config']['activities'] = apk.activities
            results['config']['services'] = apk.services
            results['config']['receivers'] = apk.receivers
            
            # Create a temp directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                    
                # Look for configuration files
                configs = []
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file.endswith('.xml') or file.endswith('.json') or file.endswith('.properties'):
                            try:
                                file_path = os.path.join(root, file)
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    
                                # Only add if file contains interesting data
                                if re.search(r'(api|url|key|token|secret|password|endpoint|server)', content, re.IGNORECASE):
                                    rel_path = os.path.relpath(file_path, temp_dir)
                                    configs.append({
                                        'file': rel_path,
                                        'content': content[:1000] + ("..." if len(content) > 1000 else "")
                                    })
                            except:
                                continue
                
                results['config']['config_files'] = configs
                
                # Look for hardcoded secrets in smali files
                smali_secrets = []
                smali_dir = os.path.join(temp_dir, "smali")
                if os.path.exists(smali_dir):
                    for root, dirs, files in os.walk(smali_dir):
                        for file in files:
                            if file.endswith('.smali'):
                                try:
                                    file_path = os.path.join(root, file)
                                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                        
                                    # Look for const-string with URLs or secrets
                                    matches = re.findall(r'const-string.*?"(http[s]?://.*?)"', content)
                                    matches.extend(re.findall(r'const-string.*?"([A-Za-z0-9_-]{20,})"', content))
                                    
                                    if matches:
                                        rel_path = os.path.relpath(file_path, temp_dir)
                                        smali_secrets.append({
                                            'file': rel_path,
                                            'secrets': matches
                                        })
                                except:
                                    continue
                
                results['config']['smali_secrets'] = smali_secrets
                
        except Exception as e:
            results['errors'].append(f"APK analysis error: {str(e)}")
    
    def _analyze_python(self, results):
        """Analyze Python files"""
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # For Python files, we need to be extra careful with domain detection
            # Filter out any domain names that are clearly part of the Python code
            if 'domain_names' in results.get('indicators', {}):
                domains_to_keep = []
                lines = content.split('\n')
                for domain in results['indicators']['domain_names']:
                    # Check in which lines the domain appears
                    appears_in_code = False
                    for line in lines:
                        if domain in line:
                            # Check if the line looks like Python code
                            if re.search(r'(import|class|def|return|print|if|for|while|with|try|except|=)', line):
                                appears_in_code = True
                                break
                    
                    # Additional checks for common Python patterns
                    if not appears_in_code and \
                       not domain.endswith('.py') and \
                       not re.match(r'[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+', domain):  # Doesn't match module.function pattern
                        domains_to_keep.append(domain)
                        
                if domains_to_keep:
                    results['indicators']['domain_names'] = domains_to_keep
                else:
                    # If all domains were filtered out, remove the entry
                    results['indicators'].pop('domain_names', None)
            
            # Look for imports
            imports = re.findall(r'(?:from\s+(\S+)\s+import\s+(.+)|import\s+(.+))', content)
            results['config']['imports'] = [
                {'module': match[0] or match[2], 'items': match[1]} 
                for match in imports
            ]
            
            # Look for variable assignments with potential configuration
            assignments = re.findall(r'([A-Z][A-Z0-9_]*)\s*=\s*([\'\"].*?[\'\"]|\[.*?\]|\{.*?\})', content)
            config_vars = {}
            for var, value in assignments:
                if re.search(r'(API|URL|TOKEN|KEY|SECRET|PASSWORD|WEBHOOK)', var):
                    config_vars[var] = value
            
            results['config']['variables'] = config_vars
            
            # Look for potentially obfuscated strings
            obfuscated = []
            # Base64 encoded strings
            b64_candidates = re.findall(r'base64\.b(?:64)?decode\(["\']([A-Za-z0-9+/=]+)["\']\)', content)
            for candidate in b64_candidates:
                try:
                    decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                    if len(decoded) > 3 and not re.match(r'^\s*$', decoded):
                        obfuscated.append({
                            'type': 'base64',
                            'encoded': candidate[:50] + ('...' if len(candidate) > 50 else ''),
                            'decoded': decoded
                        })
                except:
                    pass
            
            # XOR obfuscation (simple detection)
            xor_candidates = re.findall(r'('
                                       r'(?:["\'](?:\\x[0-9a-f]{2})+["\'])|\w+\s*\^\s*\w+|'
                                       r'for\s+\w+\s+in\s+.+?:\s*\w+\s*\^\s*\w+)'
                                       r'', content)
            if xor_candidates:
                obfuscated.append({
                    'type': 'possible_xor',
                    'patterns': xor_candidates[:10]
                })
            
            results['config']['obfuscated'] = obfuscated
            
            # Extract class definitions
            classes = re.findall(r'class\s+(\w+)\s*(?:\((.+?)\))?:', content)
            results['config']['classes'] = [
                {'name': name, 'inherits': inherits.strip()} 
                for name, inherits in classes
            ]
            
        except Exception as e:
            results['errors'].append(f"Python analysis error: {str(e)}")
    
    def _analyze_batch(self, results):
        """Analyze Batch files"""
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for variables
            variables = re.findall(r'set\s+([^=]+)=(.+)', content, re.IGNORECASE)
            results['config']['variables'] = {var.strip(): value.strip() for var, value in variables}
            
            # Look for commands
            commands = []
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('::') and not line.startswith('rem'):
                    if re.match(r'(powershell|cmd|certutil|bitsadmin|schtasks|net|reg|wmic)', line.lower()):
                        commands.append(line)
            
            results['config']['commands'] = commands[:20]  # Limit to first 20 commands
            
            # Look for downloads
            downloads = []
            download_patterns = [
                r'(curl\s+(?:-[A-Za-z]+ )*https?://[^\s]+)',
                r'(wget\s+(?:-[A-Za-z]+ )*https?://[^\s]+)',
                r'(certutil\s+-urlcache\s+-split\s+-f\s+https?://[^\s]+)',
                r'(bitsadmin\s+/transfer\s+[^\s]+\s+https?://[^\s]+)',
                r'(Invoke-WebRequest\s+.*https?://[^\s]+)',
                r'(Start-BitsTransfer\s+.*https?://[^\s]+)',
                r'(powershell.*DownloadFile\s*\(.*https?://[^\s]+)'
            ]
            
            for pattern in download_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                downloads.extend(matches)
            
            results['config']['downloads'] = downloads
            
            # Look for persistence
            persistence = []
            persistence_patterns = [
                r'(reg\s+add\s+.*?\\Run\s+.*)',
                r'(schtasks\s+/create\s+.*)',
                r'(wmic\s+startup\s+.*)',
                r'(New-ScheduledTask.*)'
            ]
            
            for pattern in persistence_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                persistence.extend(matches)
            
            results['config']['persistence'] = persistence
            
        except Exception as e:
            results['errors'].append(f"Batch analysis error: {str(e)}")
    
    def _analyze_generic(self, results):
        """Generic analysis for other file types"""
        # No special handling, rely on general indicator extraction
        pass
        
    def _identify_malware_family(self, results):
        """Identify the malware family based on detected indicators and strings"""
        # Combine all text data for analysis
        all_text = ""
        
        # Add strings
        all_text += "\n".join(results.get('strings', []))
        
        # Add found indicators
        indicators = results.get('indicators', {})
        for indicator_type, items in indicators.items():
            all_text += "\n".join(items) + "\n"
            
        # Add config data if available
        config = results.get('config', {})
        if config:
            all_text += json.dumps(config)
            
        # Check for matches against known malware families (using improved database)
        matches = {}
        
        # Use the improved database for better detection
        for family, info in IMPROVED_MALWARE_FAMILIES.items():
            match_count = 0
            total_indicators = len(info['indicators'])
            
            for pattern, match_type in info['indicators']:
                if match_type == 'string' and pattern.lower() in all_text.lower():
                    match_count += 1
                elif match_type == 'regex' and re.search(pattern, all_text, re.IGNORECASE):
                    match_count += 1
                    
            if match_count > 0:
                # Calculate confidence score (0-100%)
                confidence = (match_count / total_indicators) * 100
                matches[family] = {
                    'confidence': confidence,
                    'type': info['type'],
                    'description': info['description'],
                    'match_count': match_count,
                    'total_patterns': total_indicators
                }
        
        # If nothing matched in improved database, check original database
        if not matches:
            for family, info in MALWARE_FAMILIES.items():
                match_count = 0
                total_indicators = len(info['indicators'])
                
                for pattern, match_type in info['indicators']:
                    if match_type == 'string' and pattern.lower() in all_text.lower():
                        match_count += 1
                    elif match_type == 'regex' and re.search(pattern, all_text, re.IGNORECASE):
                        match_count += 1
                        
                if match_count > 0:
                    # Calculate confidence score (0-100%)
                    confidence = (match_count / total_indicators) * 100
                    matches[family] = {
                        'confidence': confidence,
                        'type': info['type'],
                        'description': info['description'],
                        'match_count': match_count,
                        'total_patterns': total_indicators
                    }
        
        # Determine the best match
        if matches:
            best_match = max(matches.items(), key=lambda x: x[1]['confidence'])
            family_name, match_info = best_match
            
            # Add some additional diagnostics
            match_details = f"{match_info['match_count']} of {match_info['total_patterns']} patterns matched"
            
            results['malware_info'] = {
                'family': family_name,
                'type': match_info['type'],
                'description': match_info['description'],
                'confidence': match_info['confidence'],
                'match_details': match_details
            }
        else:
            # Check for generic malware indicators if no specific family was found
            malware_types = self._detect_generic_malware_type(all_text)
            if malware_types:
                results['malware_info'] = {
                    'family': 'Unknown',
                    'type': malware_types[0],
                    'description': f'Possible {malware_types[0]} functionality detected',
                    'confidence': 30,  # Lower confidence for generic detection
                    'match_details': 'Generic detection based on behavior patterns'
                }
                
    def _detect_generic_malware_type(self, text_data):
        """Detect generic malware type based on functionality indicators"""
        malware_types = []
        
        # Check for ransomware indicators
        ransomware_patterns = [
            r'encrypt', r'ransom', r'bitcoin', r'payment', r'decrypt', 
            r'\.locked', r'\.crypt', r'your files', r'restore', r'pay'
        ]
        if any(re.search(pattern, text_data, re.IGNORECASE) for pattern in ransomware_patterns):
            malware_types.append('Ransomware')
            
        # Check for keylogger indicators
        keylogger_patterns = [
            r'keylog', r'keystroke', r'typing', r'keyboard hook', 
            r'GetAsyncKeyState', r'GetKeyboardState'
        ]
        if any(re.search(pattern, text_data, re.IGNORECASE) for pattern in keylogger_patterns):
            malware_types.append('Keylogger')
            
        # Check for RAT indicators
        rat_patterns = [
            r'remote', r'command', r'control', r'backdoor', r'remote desktop',
            r'screen capture', r'webcam', r'microphone'
        ]
        if any(re.search(pattern, text_data, re.IGNORECASE) for pattern in rat_patterns):
            malware_types.append('Remote Access Trojan')
            
        # Check for stealer indicators
        stealer_patterns = [
            r'credentials', r'passwords', r'cookies', r'wallets', r'steal',
            r'browser data', r'chrome', r'firefox', r'edge'
        ]
        if any(re.search(pattern, text_data, re.IGNORECASE) for pattern in stealer_patterns):
            malware_types.append('Information Stealer')
            
        # Check for botnet indicators
        botnet_patterns = [
            r'bot', r'command', r'c2', r'ddos', r'flood', r'spam',
            r'proxy', r'sock'
        ]
        if any(re.search(pattern, text_data, re.IGNORECASE) for pattern in botnet_patterns):
            malware_types.append('Botnet')
            
        # Check for banking trojan indicators
        banking_patterns = [
            r'bank', r'account', r'webinject', r'screenshot', r'form grab',
            r'certificate', r'https'
        ]
        if any(re.search(pattern, text_data, re.IGNORECASE) for pattern in banking_patterns):
            malware_types.append('Banking Trojan')
            
        # Check for cryptocurrency miners
        miner_patterns = [
            r'miner', r'mining', r'monero', r'bitcoin', r'stratum',
            r'xmrig', r'hashrate', r'cpu usage'
        ]
        if any(re.search(pattern, text_data, re.IGNORECASE) for pattern in miner_patterns):
            malware_types.append('Cryptocurrency Miner')
            
        return malware_types
    
    def _extract_interesting_strings(self):
        """Extract potentially interesting strings"""
        try:
            # Use strings utility or equivalent
            if platform.system() == "Windows":
                # No built-in strings utility, use our own function
                with open(self.file_path, 'rb') as f:
                    content = f.read()
                strings = self._extract_strings_from_binary(content, min_length=8).split('\n')
            else:
                # Use the strings utility on Unix-like systems
                process = subprocess.Popen(['strings', self.file_path], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE)
                stdout, _ = process.communicate()
                strings = stdout.decode('utf-8', errors='ignore').split('\n')
            
            # Filter for interesting strings
            interesting_patterns = [
                r'password',
                r'admin',
                r'login',
                r'secret',
                r'credential',
                r'key',
                r'token',
                r'api',
                r'config',
                r'ftp',
                r'ssh',
                r'http',
                r'auth',
                r'user',
                r'account'
            ]
            
            interesting_strings = []
            for s in strings:
                s = s.strip()
                if len(s) > 8:  # Minimum length for interesting string
                    for pattern in interesting_patterns:
                        if re.search(pattern, s, re.IGNORECASE):
                            interesting_strings.append(s)
                            break
            
            # Deduplicate and limit
            return list(set(interesting_strings))[:100]  # Limit to 100 interesting strings
            
        except Exception as e:
            return [f"Error extracting strings: {str(e)}"]


class DropLabel(QLabel):
    """Custom label that supports drag and drop for files"""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.setMinimumHeight(150)
        self.base_style = """
            QLabel {
                border: 2px dashed #3F3F46;
                border-radius: 5px;
                color: #CCCCCC;
                font-size: 16px;
            }
            QLabel:hover {
                border-color: #007ACC;
            }
        """
        self.setStyleSheet(self.base_style)
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        try:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
        except Exception as e:
            print(f"Error in dragEnterEvent: {str(e)}")  # Debug output
    
    def dropEvent(self, event: QDropEvent):
        try:
            for url in event.mimeData().urls():
                file_path = url.toLocalFile()
                if os.path.isfile(file_path):
                    # Find the main application window to call analyze_file
                    main_window = self.get_main_window()
                    if main_window and hasattr(main_window, 'analyze_file'):
                        main_window.analyze_file(file_path)
                    break
        except Exception as e:
            print(f"Error in dropEvent: {str(e)}")  # Debug output
    
    def get_main_window(self):
        """Find the main application window by traversing up the parent hierarchy"""
        parent = self.parent()
        while parent:
            if isinstance(parent, QMainWindow):
                return parent
            parent = parent.parent()
        return None


class MalwareInsightApp(QMainWindow):
    """Main application window"""
    def __init__(self):
        super().__init__()
        
        # Load settings
        self.settings = load_settings()
        
        self.setWindowTitle(f"Sigma Analysis: Malware Configuration Extractor v{APP_VERSION}")
        self.setMinimumSize(1000, 700)
        self.setStyleSheet(get_app_style(self.settings["theme"]))
        
        self.current_file = None
        self.analysis_results = None
        
        # Create the main layout
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        
        # Header section
        header_layout = QHBoxLayout()
        app_title_label = QLabel("Sigma Analysis: Malware Configuration Extractor")
        app_title_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        header_layout.addWidget(app_title_label)
        header_layout.addStretch(1)
        
        # Settings button
        self.settings_button = QPushButton("Settings")
        self.settings_button.clicked.connect(self.open_settings)
        header_layout.addWidget(self.settings_button)
        
        # File selection section
        file_section_layout = QVBoxLayout()
        file_label = QLabel("Drop malware file or click to browse:")
        self.drop_area = DropLabel("Drop file here or click to browse")
        self.drop_area.mousePressEvent = self.browse_file
        
        file_section_layout.addWidget(file_label)
        file_section_layout.addWidget(self.drop_area)
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        self.browse_button = QPushButton("Browse File")
        self.browse_button.clicked.connect(self.browse_file)
        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.clicked.connect(self.start_analysis)
        self.analyze_button.setEnabled(False)
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_analysis)
        
        buttons_layout.addWidget(self.browse_button)
        buttons_layout.addWidget(self.analyze_button)
        buttons_layout.addWidget(self.clear_button)
        buttons_layout.addStretch(1)
        
        # Current file info
        self.file_info_label = QLabel("No file selected")
        
        # Progress section
        self.progress_text = QTextEdit()
        self.progress_text.setReadOnly(True)
        self.progress_text.setMaximumHeight(80)
        
        # Results section
        self.results_tabs = QTabWidget()
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        overview_layout.addWidget(self.overview_text)
        
        # Indicators tab
        indicators_tab = QWidget()
        indicators_layout = QVBoxLayout(indicators_tab)
        self.indicators_list = QListWidget()
        indicators_layout.addWidget(self.indicators_list)
        
        # Config tab
        config_tab = QWidget()
        config_layout = QVBoxLayout(config_tab)
        self.config_text = QTextEdit()
        self.config_text.setReadOnly(True)
        config_layout.addWidget(self.config_text)
        
        # Strings tab
        strings_tab = QWidget()
        strings_layout = QVBoxLayout(strings_tab)
        self.strings_list = QListWidget()
        strings_layout.addWidget(self.strings_list)
        
        # Quick Web tab
        quick_web_tab = QWidget()
        quick_web_layout = QVBoxLayout(quick_web_tab)
        
        # Add malware info section to Quick Web
        quick_web_malware_group = QGroupBox("Malware Information")
        quick_web_malware_layout = QVBoxLayout(quick_web_malware_group)
        self.quick_web_malware_text = QTextEdit()
        self.quick_web_malware_text.setReadOnly(True)
        self.quick_web_malware_text.setMaximumHeight(150)
        quick_web_malware_layout.addWidget(self.quick_web_malware_text)
        
        # Add webhook section to Quick Web
        quick_web_webhook_group = QGroupBox("Web Hooks")
        quick_web_webhook_layout = QVBoxLayout(quick_web_webhook_group)
        self.quick_web_webhook_list = QListWidget()
        quick_web_webhook_layout.addWidget(self.quick_web_webhook_list)
        
        # Add Discord webhook sending section
        quick_web_send_group = QGroupBox("Send Results")
        quick_web_send_layout = QHBoxLayout(quick_web_send_group)
        self.send_webhook_button = QPushButton("Send to Discord Webhook")
        self.send_webhook_button.clicked.connect(self.send_to_discord_webhook)
        self.send_webhook_button.setEnabled(False)
        quick_web_send_layout.addWidget(self.send_webhook_button)
        
        # Add sections to Quick Web tab
        quick_web_layout.addWidget(quick_web_malware_group)
        quick_web_layout.addWidget(quick_web_webhook_group)
        quick_web_layout.addWidget(quick_web_send_group)
        
        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        # Add tabs
        self.results_tabs.addTab(overview_tab, "Overview")
        self.results_tabs.addTab(indicators_tab, "Indicators")
        self.results_tabs.addTab(config_tab, "Configuration")
        self.results_tabs.addTab(strings_tab, "Strings")
        self.results_tabs.addTab(quick_web_tab, "Quick Web")
        
        # Set default tab
        self.results_tabs.setCurrentIndex(self.settings["default_tab"])
        
        # Add everything to main layout
        main_layout.addLayout(header_layout)
        main_layout.addLayout(file_section_layout)
        main_layout.addLayout(buttons_layout)
        main_layout.addWidget(self.file_info_label)
        main_layout.addWidget(QLabel("Analysis Progress:"))
        main_layout.addWidget(self.progress_text)
        main_layout.addWidget(QLabel("Results:"))
        main_layout.addWidget(self.results_tabs, 1)  # Give it stretch factor
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Set the main widget
        self.setCentralWidget(main_widget)
        
    def open_settings(self):
        """Open the settings dialog"""
        settings_dialog = SettingsDialog(self.settings, parent=self)
        if settings_dialog.exec_():
            # If dialog is accepted, update settings
            self.settings = settings_dialog.get_settings()
            save_settings(self.settings)
            
            # Apply settings
            self.setStyleSheet(get_app_style(self.settings["theme"]))
            
            # Update any UI elements based on settings
            self.status_bar.showMessage("Settings updated", 3000)
            
    def send_to_discord_webhook(self):
        """Send quick web results to Discord webhook"""
        if not self.analysis_results or not self.settings.get("discord_webhook"):
            return
            
        try:
            # Format data for Discord webhook
            file_info = self.analysis_results.get('file_info', {})
            malware_info = self.analysis_results.get('malware_info', {})
            indicators = self.analysis_results.get('indicators', {})
            
            # Prepare webhook data
            webhook_data = {
                "embeds": [
                    {
                        "title": f"Sigma Analysis: {file_info.get('name', 'Unknown')}",
                        "color": 0x007acc,  # Blue color
                        "fields": [
                            {
                                "name": "File Information",
                                "value": f"Name: {file_info.get('name', 'Unknown')}\nSize: {file_info.get('size', 0) / 1024:.2f} KB\nType: {file_info.get('type', 'Unknown')}",
                                "inline": False
                            },
                            {
                                "name": "Malware Classification",
                                "value": f"Family: {malware_info.get('family', 'Unknown')}\nType: {malware_info.get('type', 'Unknown')}\nConfidence: {malware_info.get('confidence', 0):.1f}%",
                                "inline": False
                            }
                        ],
                        "footer": {
                            "text": f"Sigma Analysis Tool • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        }
                    }
                ]
            }
            
            # Add webhooks field if found
            webhooks = indicators.get('discord_webhooks', [])
            if webhooks:
                webhook_text = "\n".join(webhooks[:10])  # Limit to first 10
                if len(webhooks) > 10:
                    webhook_text += f"\n...and {len(webhooks) - 10} more"
                
                webhook_data["embeds"][0]["fields"].append({
                    "name": "Discord Webhooks",
                    "value": f"```{webhook_text}```",
                    "inline": False
                })
            
            # Add telegram bots if found
            telegram_bots = indicators.get('telegram_bots', [])
            if telegram_bots:
                bot_text = "\n".join(telegram_bots[:10])  # Limit to first 10
                if len(telegram_bots) > 10:
                    bot_text += f"\n...and {len(telegram_bots) - 10} more"
                
                webhook_data["embeds"][0]["fields"].append({
                    "name": "Telegram Bot Tokens",
                    "value": f"```{bot_text}```",
                    "inline": False
                })
            
            # Send to Discord webhook
            response = requests.post(
                self.settings.get("discord_webhook"),
                json=webhook_data
            )
            
            if response.status_code == 204:
                self.status_bar.showMessage("Results sent to Discord webhook successfully", 5000)
            else:
                self.status_bar.showMessage(f"Failed to send to Discord webhook: {response.status_code}", 5000)
                
        except Exception as e:
            self.status_bar.showMessage(f"Error sending to Discord webhook: {str(e)}", 5000)
    
    def browse_file(self, event=None):
        """Open file dialog to browse for a file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Analyze",
            "",
            "All Files (*);;Executables (*.exe);;APK Files (*.apk);;Python Files (*.py);;Batch Files (*.bat)"
        )
        
        if file_path:
            self.current_file = file_path
            self.file_info_label.setText(f"Selected: {os.path.basename(file_path)}")
            self.analyze_button.setEnabled(True)
            self.drop_area.setText(f"Selected: {os.path.basename(file_path)}")
            self.drop_area.setStyleSheet(self.drop_area.styleSheet() + "border-color: #007ACC;")
    
    def start_analysis(self):
        """Start the analysis process"""
        if not self.current_file:
            QMessageBox.warning(self, "No File", "Please select a file to analyze first.")
            return
        
        # Clear previous results
        self.clear_results()
        
        # Update UI
        self.status_bar.showMessage("Analyzing...")
        self.progress_text.append(f"Starting analysis of: {os.path.basename(self.current_file)}")
        self.analyze_button.setEnabled(False)
        
        # Start analysis in separate thread
        self.analyzer_thread = FileAnalyzerThread(self.current_file)
        self.analyzer_thread.progress_update.connect(self.update_progress)
        self.analyzer_thread.analysis_complete.connect(self.display_results)
        self.analyzer_thread.start()
    
    def update_progress(self, message):
        """Update the progress text with a new message"""
        self.progress_text.append(message)
        # Auto-scroll to bottom
        self.progress_text.verticalScrollBar().setValue(
            self.progress_text.verticalScrollBar().maximum()
        )
    
    def display_results(self, results):
        """Display the analysis results"""
        self.analysis_results = results
        self.analyze_button.setEnabled(True)
        
        if 'error' in results:
            self.status_bar.showMessage("Analysis failed")
            QMessageBox.critical(self, "Analysis Error", 
                                f"Error during analysis: {results['error']}")
            return
        
        # Update status bar
        self.status_bar.showMessage("Analysis complete")
        
        # Fill overview tab
        file_info = results.get('file_info', {})
        file_size_kb = file_info.get('size', 0) / 1024
        malware_info = results.get('malware_info', {})
        
        overview_html = f"""
        <h2>Analysis Summary</h2>
        <p><b>File:</b> {file_info.get('name', 'Unknown')}</p>
        <p><b>Size:</b> {file_size_kb:.2f} KB</p>
        <p><b>Type:</b> {file_info.get('type', 'Unknown')}</p>
        
        <h3>Malware Classification</h3>
        <div style="background-color: #1E1E1E; border: 1px solid #3F3F46; padding: 10px; border-radius: 5px; margin-bottom: 15px;">
            <p><b>Family:</b> {malware_info.get('family', 'Unknown')}</p>
            <p><b>Type:</b> {malware_info.get('type', 'Unknown')}</p>
            <p><b>Description:</b> {malware_info.get('description', 'Unknown')}</p>
            <p><b>Confidence:</b> {malware_info.get('confidence', 0):.1f}%</p>
        </div>
        
        <h3>Findings</h3>
        <ul>
        """
        
        # Summary of indicators
        indicators = results.get('indicators', {})
        for indicator_type, items in indicators.items():
            if items:
                overview_html += f"<li><b>{indicator_type.replace('_', ' ').title()}:</b> {len(items)} found</li>"
        
        # Summary of configuration
        config = results.get('config', {})
        if config:
            overview_html += "<li><b>Configuration elements:</b> "
            config_items = []
            for key in config.keys():
                config_items.append(key.replace('_', ' ').title())
            overview_html += ", ".join(config_items) + "</li>"
        
        # Errors summary
        errors = results.get('errors', [])
        if errors:
            overview_html += "<li><b>Analysis errors:</b> "
            overview_html += ", ".join(errors) + "</li>"
        
        overview_html += "</ul>"
        
        self.overview_text.setHtml(overview_html)
        
        # Fill indicators tab
        self.indicators_list.clear()
        for indicator_type, items in indicators.items():
            category_item = QListWidgetItem(f"{indicator_type.replace('_', ' ').title()} ({len(items)})")
            category_item.setBackground(QColor("#2D2D30"))
            category_item.setForeground(QColor("white"))
            font = category_item.font()
            font.setBold(True)
            category_item.setFont(font)
            self.indicators_list.addItem(category_item)
            
            for item in items:
                self.indicators_list.addItem(f"  {item}")
        
        # Fill config tab
        config_text = json.dumps(config, indent=2)
        self.config_text.setText(config_text)
        
        # Fill strings tab
        self.strings_list.clear()
        for string in results.get('strings', []):
            self.strings_list.addItem(string)
            
        # Fill Quick Web tab
        # Malware info section
        quick_web_malware_html = f"""
        <h3>{malware_info.get('family', 'Unknown')} ({malware_info.get('type', 'Unknown')})</h3>
        <p><b>Description:</b> {malware_info.get('description', 'Unknown')}</p>
        <p><b>Confidence:</b> {malware_info.get('confidence', 0):.1f}%</p>
        """
        self.quick_web_malware_text.setHtml(quick_web_malware_html)
        
        # Webhooks list
        self.quick_web_webhook_list.clear()
        
        # Add Discord webhooks
        discord_webhooks = indicators.get('discord_webhooks', [])
        if discord_webhooks:
            webhook_header = QListWidgetItem("Discord Webhooks")
            webhook_header.setBackground(QColor("#2D2D30"))
            webhook_header.setForeground(QColor("white"))
            font = webhook_header.font()
            font.setBold(True)
            webhook_header.setFont(font)
            self.quick_web_webhook_list.addItem(webhook_header)
            
            for webhook in discord_webhooks:
                self.quick_web_webhook_list.addItem(f"  {webhook}")
        
        # Add Telegram bot tokens
        telegram_bots = indicators.get('telegram_bots', [])
        if telegram_bots:
            bot_header = QListWidgetItem("Telegram Bot Tokens")
            bot_header.setBackground(QColor("#2D2D30"))
            bot_header.setForeground(QColor("white"))
            font = bot_header.font()
            font.setBold(True)
            bot_header.setFont(font)
            self.quick_web_webhook_list.addItem(bot_header)
            
            for bot in telegram_bots:
                self.quick_web_webhook_list.addItem(f"  {bot}")
                
        # Enable webhook sending if Discord webhook is configured
        if self.settings.get("discord_webhook") and self.settings.get("send_to_webhook"):
            self.send_webhook_button.setEnabled(True)
            
            # Auto-send to webhook if enabled
            if self.settings.get("send_to_webhook"):
                self.send_to_discord_webhook()
        else:
            self.send_webhook_button.setEnabled(False)
    
    def clear_analysis(self):
        """Clear all analysis data and results"""
        self.current_file = None
        self.analysis_results = None
        self.clear_results()
        self.file_info_label.setText("No file selected")
        self.drop_area.setText("Drop file here or click to browse")
        self.drop_area.setStyleSheet(self.drop_area.styleSheet().replace("border-color: #007ACC;", ""))
        self.analyze_button.setEnabled(False)
        self.status_bar.showMessage("Ready")
    
    def clear_results(self):
        """Clear just the results display"""
        self.progress_text.clear()
        self.overview_text.clear()
        self.indicators_list.clear()
        self.config_text.clear()
        self.strings_list.clear()
    
    def analyze_file(self, file_path):
        """Analyze a specific file (called from drag & drop)"""
        try:
            # Validate the file exists
            if not os.path.exists(file_path):
                self.status_bar.showMessage(f"Error: File {file_path} not found", 3000)
                return
        
            self.current_file = file_path
            self.file_info_label.setText(f"Selected: {os.path.basename(file_path)}")
            self.analyze_button.setEnabled(True)
            self.drop_area.setText(f"Selected: {os.path.basename(file_path)}")

            # Reset and reapply the border color to avoid style accumulation
            base_style = """
                QLabel {
                border: 2px dashed #3F3F46;
                border-radius: 5px;
                color: #CCCCCC;
                font-size: 16px;
            }
               QLabel:hover {
                border-color: #007ACC;
            }
            """
            self.drop_area.setStyleSheet(base_style + "border-color: #007ACC;")
        
            # Auto-analyze if enabled in settings
            if self.settings.get("auto_analyze", False):
                self.start_analysis()
    
        except Exception as e:
            self.status_bar.showMessage(f"Error processing file: {str(e)}", 5000)
            print(f"Error in analyze_file: {str(e)}")  # Debug output


def main():
    """Application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Sigma Analysis")
    window = MalwareInsightApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    APP_VERSION = "1.1"
    main()
