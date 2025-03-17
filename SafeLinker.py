import sys
import re
import idna
import pyperclip
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QInputDialog
from PyQt5.QtCore import QTimer, Qt
from unicodedata import normalize
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtCore import QUrl

HOMOGRAPHS = {
    'a': ['а', 'ä', 'ạ', 'α'],
    'b': ['Ь', 'ḅ', 'ƅ'],
    'e': ['е', 'ë', 'ẹ', 'ɛ'],
    'i': ['і', 'í', 'ï', 'ị'],
    'l': ['ӏ', 'ł', 'ḷ'],
    'o': ['о', 'ö', 'ọ', '○'],
    's': ['ѕ', 'ṡ', 'ṣ'],
}

VALID_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'me', 'info', 'biz', 'ir'}

class DomainChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SafeLinker Desktop - NewWay")
        self.setGeometry(100, 100, 500, 200)

        self.label = QLabel("Checking...", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setOpenExternalLinks(True)  # اجازه کلیک روی لینک‌های ایمن را می‌دهد
        self.setCentralWidget(self.label)

        self.last_clipboard_text = ""

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_clipboard)
        self.timer.start(1000)

    def to_punycode(self, domain):
        try:
            return idna.encode(domain).decode('ascii')
        except idna.core.IDNAError:
            return None

    def check_homographs(self, domain):
        for char in domain.lower():
            for key, homographs in HOMOGRAPHS.items():
                if char in homographs:
                    return True
        return False

    def is_suspicious(self, domain):
        domain = normalize('NFKC', domain)
        punycode = self.to_punycode(domain)
        return self.check_homographs(domain) or (punycode and punycode.startswith('xn--'))

    def extract_domain(self, text):
        domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9а-яА-Я.-]+\.[a-zA-Z]{2,6})'
        match = re.search(domain_pattern, text)
        if match:
            domain = match.group(1)
            tld = domain.split('.')[-1].lower()
            if tld in VALID_TLDS:
                return domain
        return None

    def check_clipboard(self):
        clipboard_text = pyperclip.paste()
        if clipboard_text and clipboard_text != self.last_clipboard_text:
            self.last_clipboard_text = clipboard_text
            domain = self.extract_domain(clipboard_text)

            if domain:
                if self.is_suspicious(domain):
                    self.label.setText(f"<b style='color:red;'>Suspicious domain:</b> {domain}")
                else:
                    self.label.setText(f"<a href='https://{domain}' style='color:green;'>{domain}</a> - Safe")

    def manual_check(self):
        domain, ok = QInputDialog.getText(self, "Manual Check", "Enter a domain:")
        if ok and domain:
            if self.is_suspicious(domain):
                self.label.setText(f"<b style='color:red;'>Suspicious domain:</b> {domain}")
            else:
                self.label.setText(f"<a href='https://{domain}' style='color:green;'>{domain}</a> - Safe")

    def mousePressEvent(self, event):
        url = self.label.text()
        match = re.search(r'<a href=\'(https://[^\']+)\'', url)
        if match:
            domain = match.group(1)
            if "Suspicious domain" not in url:
                QDesktopServices.openUrl(QUrl(domain))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DomainChecker()
    window.show()
    sys.exit(app.exec_())
