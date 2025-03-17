import sys
import re
import idna
import win32gui
import win32con
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QSystemTrayIcon, QMenu, QInputDialog, QMessageBox
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QIcon
from unicodedata import normalize
import pyperclip
import ctypes
from ctypes import wintypes
from pywinauto import Desktop, Application

# تعریف ساختارها برای هوک ماوس
class POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG),
                ("y", wintypes.LONG)]

class MOUSEHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("pt", POINT),
                ("hwnd", wintypes.HWND),
                ("wHitTestCode", wintypes.UINT),
                ("dwExtraInfo", wintypes.ULONG)]

user32 = ctypes.windll.user32
LowLevelMouseProc = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(MOUSEHOOKSTRUCT))
HOOK_ID = None

HOMOGRAPHS = {
    'a': ['а', 'ä', 'ạ', 'α'],
    'b': ['Ь', 'ḅ', 'ƅ'],
    'e': ['е', 'ë', 'ẹ', 'ɛ'],
    'i': ['і', 'í', 'ï', 'ị'],
    'l': ['ӏ', 'ł', 'ḷ'],
    'o': ['о', 'ö', 'ọ', '○'],
    's': ['ѕ', 'ṡ', 'ṣ'],
}

# لیست پسوندهای معتبر دامنه
VALID_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'me', 'info', 'biz', 'ir'}

class DomainChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SafeLinker Desktop - NewWay")
        self.setGeometry(100, 100, 500, 200)
        self.label = QLabel("Checking...", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.setCentralWidget(self.label)

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("icon.ico"))
        tray_menu = QMenu()
        quit_action = tray_menu.addAction("Exit")
        manual_check_action = tray_menu.addAction("Manual Check")
        quit_action.triggered.connect(QApplication.instance().quit)
        manual_check_action.triggered.connect(self.manual_check)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

        self.last_clipboard_text = ""
        self.is_suspicious_domain = False
        self.current_domain = None

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_all)
        self.timer.start(1000)

        self.install_mouse_hook()

    def to_punycode(self, domain):
        try:
            return idna.encode(domain).decode('ascii')
        except idna.core.IDNAError:
            return None

    def check_homographs(self, domain):
        suspicious_chars = []
        for char in domain.lower():
            for key, homographs in HOMOGRAPHS.items():
                if char in homographs:
                    suspicious_chars.append((char, key))
        return suspicious_chars

    def is_suspicious(self, domain):
        domain = normalize('NFKC', domain)
        punycode = self.to_punycode(domain)
        homographs = self.check_homographs(domain)
        result = homographs or (punycode and punycode.startswith('xn--'))
        print(f"Domain: {domain}, Punycode: {punycode}, Homographs: {homographs}, Suspicious: {result}")
        return result

    def extract_domain(self, text):
        # اصلاح regex برای دامنه‌های معتبر
        domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9а-яА-Я][a-zA-Z0-9а-яА-Я-._~]*\.[a-zA-Z]{2,6})'
        match = re.search(domain_pattern, text)
        if match:
            domain = match.group(1)
            # چک کردن پسوند دامنه
            tld = domain.split('.')[-1].lower()
            if tld in VALID_TLDS:
                print(f"Extracted domain: {domain}")
                return domain
            else:
                print(f"Invalid TLD in {domain}, skipping...")
                return None
        print("No domain found")
        return None

    def get_text_under_cursor(self):
        pos_x, pos_y = win32gui.GetCursorPos()
        hwnd = win32gui.WindowFromPoint((pos_x, pos_y))
        try:
            app = Application(backend="uia").connect(handle=hwnd)
            window = app.top_window()
            text = window.get_value() or window.window_text() or ""
            if not text or "Word" in window.window_text():
                clipboard_backup = pyperclip.paste()
                pyperclip.copy("")
                window.type_keys("^c")
                QApplication.processEvents()
                text = pyperclip.paste()
                pyperclip.copy(clipboard_backup)
        except Exception as e:
            print(f"Error getting text with pywinauto: {e}")
            text = win32gui.GetWindowText(hwnd) or ""
        print(f"Text under cursor: {text}")
        return text

    def check_all(self):
        self.is_suspicious_domain = False
        self.current_domain = None

        text = self.get_text_under_cursor()
        domain = self.extract_domain(text)

        if not domain:
            clipboard_text = pyperclip.paste()
            if clipboard_text and clipboard_text != self.last_clipboard_text:
                print(f"Clipboard text: {clipboard_text}")
                self.last_clipboard_text = clipboard_text
                domain = self.extract_domain(clipboard_text)

        if domain:
            self.current_domain = domain
            if self.is_suspicious(domain):
                self.label.setText(f"Suspicious domain: {domain}")
                self.show_warning(domain)
                self.is_suspicious_domain = True
            else:
                self.label.setText(f"Domain: {domain} - Safe")
                self.show_safe_message(domain)
                self.is_suspicious_domain = False
        else:
            self.label.setText("Checking...")

    def manual_check(self):
        domain, ok = QInputDialog.getText(self, "Manual Check", "Enter a domain:")
        if ok and domain:
            if self.is_suspicious(domain):
                self.show_warning(domain)
                self.label.setText(f"Suspicious domain: {domain}")
            else:
                self.show_safe_message(domain)
                self.label.setText(f"Domain: {domain} - Safe")

    def show_warning(self, domain):
        self.tray_icon.showMessage(
            "Suspicious Link Warning!",
            f"The domain '{domain}' might be fake!",
            QSystemTrayIcon.Warning,
            2000
        )
        QMessageBox.warning(self, "Warning", f"The domain '{domain}' might be fake!")

    def show_safe_message(self, domain):
        self.tray_icon.showMessage(
            "Safe Link",
            f"The domain '{domain}' is safe!",
            QSystemTrayIcon.Information,
            2000
        )
        QMessageBox.information(self, "Safe", f"The domain '{domain}' is safe!")

    def mouse_hook(self, nCode, wParam, lParam):
        if nCode >= 0 and wParam == win32con.WM_LBUTTONDOWN:
            if self.is_suspicious_domain and self.current_domain:
                print(f"Click on {self.current_domain} blocked!")
                return 1
        return user32.CallNextHookEx(HOOK_ID, nCode, wParam, lParam)

    def install_mouse_hook(self):
        global HOOK_ID
        self.cm_fp = LowLevelMouseProc(self.mouse_hook)
        HOOK_ID = user32.SetWindowsHookExW(win32con.WH_MOUSE_LL, self.cm_fp, 0, 0)
        if not HOOK_ID:
            print("Mouse hook installation failed!")
        else:
            print("Mouse hook installed.")

    def closeEvent(self, event):
        if HOOK_ID:
            user32.UnhookWindowsHookEx(HOOK_ID)
        self.timer.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DomainChecker()
    window.show()
    sys.exit(app.exec_())