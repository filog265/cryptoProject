from PyQt5 import QtWidgets, QtCore, QtGui
import socket
import sys
import struct
from threading import Thread


class CryptoGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.initial_connection = True
        self.setWindowTitle("Crypto Client")
        self.setGeometry(100, 100, 1000, 800)

        # Protocol state
        self.task_active = False
        self.expected_msg = None
        self.expected_key = None
        self.current_task = None


        self.init_ui()

        # Socket connection
        self.host = "vlbelintrocrypto.hevs.ch"
        self.port = 6000
        self.sock = self.connect_to_server()

        # Start receiver thread
        if self.sock:
            self.receiver = ReceiverThread(self.sock)
            self.receiver.message_received.connect(self.handle_server_message)
            self.receiver.start()

        # Initialize UI
        self.init_ui()

    def init_ui(self):
        # Main container
        main_widget = QtWidgets.QWidget()
        self.setCentralWidget(main_widget)
        layout = QtWidgets.QHBoxLayout(main_widget)
        layout.setContentsMargins(15, 15, 15, 15)

        # Left panel - Controls
        left_panel = QtWidgets.QWidget()
        left_panel.setContentsMargins(10, 10, 10, 10)
        left_layout = QtWidgets.QVBoxLayout(left_panel)
        left_layout.setSpacing(15)
        # Task controls
        self.task_group = QtWidgets.QGroupBox("Server Task Setup")
        self.task_group.setStyleSheet("QGroupBox { margin-top: 10px; }")
        task_layout = QtWidgets.QVBoxLayout()
        task_layout.setContentsMargins(10, 15, 10, 15)

        self.encryption_combo = QtWidgets.QComboBox()
        self.encryption_combo.addItems(["Shift Cipher", "Vigenère", "RSA"])

        self.message_size = QtWidgets.QSpinBox()
        self.message_size.setRange(1, 1024)
        self.message_size.setValue(128)

        self.start_task_btn = QtWidgets.QPushButton("Start Encryption Task")
        self.start_task_btn.clicked.connect(self.start_encryption_task)

        task_layout.addWidget(QtWidgets.QLabel("Encryption Method:"))
        task_layout.addWidget(self.encryption_combo)
        task_layout.addWidget(QtWidgets.QLabel("Message Size:"))
        task_layout.addWidget(self.message_size)
        task_layout.addWidget(self.start_task_btn)
        self.task_group.setLayout(task_layout)

        # Add horizontal line separators between groups
        separator = QtWidgets.QFrame()
        separator.setFrameShape(QtWidgets.QFrame.HLine)
        separator.setFrameShadow(QtWidgets.QFrame.Sunken)
        left_layout.addWidget(separator)

        # Encryption status
        self.status_group = QtWidgets.QGroupBox("Task Status")
        self.status_group.setStyleSheet("QGroupBox { margin-top: 10px; }")
        status_layout = QtWidgets.QVBoxLayout()
        status_layout.setContentsMargins(10, 15, 10, 15)

        self.status_label = QtWidgets.QLabel("No active task")
        # In init_ui() for both received_msg and received_key:
        self.received_msg = QtWidgets.QTextEdit()
        self.received_msg.setReadOnly(True)
        self.received_msg.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)

        self.received_key = QtWidgets.QTextEdit()
        self.received_key.setReadOnly(True)
        self.received_key.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.received_key.setMaximumHeight(100)  # Limit height for keys

        status_layout.addWidget(self.status_label)
        status_layout.addWidget(QtWidgets.QLabel("Received Message:"))
        status_layout.addWidget(self.received_msg)
        status_layout.addWidget(QtWidgets.QLabel("Received Key:"))
        status_layout.addWidget(self.received_key)
        self.status_group.setLayout(status_layout)

        # Custom message sending group
        self.message_group = QtWidgets.QGroupBox("Send Custom Message")
        self.message_group.setStyleSheet("QGroupBox { margin-top: 10px; }")
        message_layout = QtWidgets.QVBoxLayout()
        message_layout.setContentsMargins(10, 15, 10, 15)

        # Add stretch between groups for better spacing
        left_layout.addWidget(self.task_group)
        left_layout.addSpacing(15)  # Add extra space between sections
        left_layout.addWidget(self.status_group)
        left_layout.addSpacing(15)
        left_layout.addWidget(self.message_group)
        left_layout.addStretch(1)

        # Text area for custom message
        self.custom_message = QtWidgets.QTextEdit()
        self.custom_message.setPlaceholderText("Enter your message here...")

        # Message encryption controls
        message_control_layout = QtWidgets.QHBoxLayout()

        self.encrypt_checkbox = QtWidgets.QCheckBox("Encrypt before sending")
        self.encrypt_checkbox.setChecked(True)

        self.custom_key_input = QtWidgets.QLineEdit()
        self.custom_key_input.setPlaceholderText("Encryption key (if needed)")

        message_control_layout.addWidget(self.encrypt_checkbox)
        message_control_layout.addWidget(self.custom_key_input)

        # Send button
        self.send_message_btn = QtWidgets.QPushButton("Send Message")
        self.send_message_btn.clicked.connect(self.send_custom_message)
        self.send_message_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")

        message_layout.addWidget(QtWidgets.QLabel("Message:"))
        message_layout.addWidget(self.custom_message)
        message_layout.addLayout(message_control_layout)
        message_layout.addWidget(self.send_message_btn)
        self.message_group.setLayout(message_layout)

        # Add all control groups to left panel
        left_layout.addWidget(self.task_group)
        left_layout.addWidget(self.status_group)
        left_layout.addWidget(self.message_group)

        # Right panel - Logs
        self.log_panel = QtWidgets.QTextEdit()
        self.log_panel.setStyleSheet("margin-left: 10px;")
        self.log_panel.setReadOnly(True)

        # Add to main layout
        layout.addWidget(left_panel, stretch=1)
        layout.addWidget(self.log_panel, stretch=2)

        # Set style
        self.setStyleSheet("""
            QMainWindow { background-color: #2b2b2b; }
            QGroupBox { 
                color: #ffffff;
                border: 1px solid #3a3a3a;
                margin-top: 1ex;
            }
            QTextEdit, QLineEdit { 
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #3a3a3a;
                min-height: 100px;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: #ffffff;
                border: 1px solid #505050;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #505050;
            }
            QCheckBox {
                color: #ffffff;
            }
        """)

    def connect_to_server(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            self.log("Connected to server successfully", "success")
            return sock
        except Exception as e:
            self.show_error(f"Connection failed: {str(e)}")
            return None

    def start_encryption_task(self):
        if not self.sock:
            self.show_error("Not connected to server!")
            return

        # Reset message state
        self.expected_msg = None
        self.expected_key = None

        method_map = {
            "Shift Cipher": "shift",
            "Vigenère": "vigenere",
            "RSA": "rsa"
        }
        method = method_map[self.encryption_combo.currentText()]
        size = self.message_size.value()

        task_cmd = f"task {method} encode {size}"
        self.send_message_to_server('s', task_cmd)

        self.task_active = True
        self.current_task = method
        self.status_label.setText(f"Active Task: {method.upper()} encoding")
        self.log(f"Started {method} encryption task", "info")

    def handle_server_message(self, msg_type, data):
        # Handle initial connection message
        if self.initial_connection:
            decoded = decode_4byte_message(data)
            self.log(f"Server connected: {decoded}", "success")
            self.initial_connection = False
            return

        # Only process messages after task starts
        if not self.task_active:
            return

        try:
            if not self.expected_msg:
                decoded_msg = decode_4byte_message(data)
                self.expected_msg = decoded_msg
                # Display full message in text box
                self.received_msg.setPlainText(decoded_msg)
                # Log with limited length for readability
                self.log(f"Received message to encrypt: {decoded_msg[:50]}...", "server")
            else:
                # Store raw key data
                self.expected_key = data
                # Show decoded version for user
                key_display = decode_4byte_message(data)
                self.received_key.setPlainText(key_display)
                self.log(f"Received encryption key: {key_display}", "server")
                self.process_encryption()
        except Exception as e:
            self.log(f"Error processing message: {str(e)}", "error")

    def process_encryption(self):
        try:
            if self.current_task == "shift":
                # Pass raw key string to shiftEncode
                encrypted = shiftEncode(self.expected_msg, self.expected_key)
                self.log(f"Using shift value: {hash(self.expected_key) % 256} from key '{self.expected_key}'", "info")

            self.send_message_to_server('s', encrypted)
            self.log(f"Sent encrypted message: {encrypted[:50]}...", "client")

            # Reset for next task
            self.task_active = False
            self.expected_msg = None
            self.expected_key = None
            self.status_label.setText("Encryption completed - awaiting result")
            self.received_key.clear()
            self.received_msg.clear()

        except Exception as e:
            self.log(f"Encryption failed: {str(e)}", "error")
            self.task_active = False

    def send_custom_message(self):
        if not self.sock:
            self.show_error("Not connected to server!")
            return

        message = self.custom_message.toPlainText()
        if not message:
            self.show_error("Please enter a message to send")
            return

        # Check if we need to encrypt the message
        if self.encrypt_checkbox.isChecked():
            method = self.encryption_combo.currentText()
            key = self.custom_key_input.text()

            if not key:
                self.show_error("Please enter an encryption key")
                return

            try:
                if method == "Shift Cipher":
                    try:
                        key_int = int(key)
                        encrypted = shiftEncode(message, key_int)
                    except ValueError:
                        self.show_error("Shift cipher requires an integer key")
                        return
                elif method == "Vigenère":
                    encrypted = encrypt_vigenere(message, key)
                elif method == "RSA":
                    encrypted = rsa_encrypt(message, key)

                self.log(f"Message encrypted using {method}", "info")
                message = encrypted
            except Exception as e:
                self.log(f"Encryption failed: {str(e)}", "error")
                return

        # Send the message
        self.send_message_to_server('s', message)
        self.log(f"Sent custom message: {message[:50]}...", "client")

        # Clear the message area
        self.custom_message.clear()

    def send_message_to_server(self, msg_type, message):
        try:
            # Convert message to bytes following protocol (4 bytes per character)
            if isinstance(message, str):
                # Convert each character to 4 bytes (UTF-32BE without BOM)
                msg_bytes = b""
                for char in message:
                    code_point = ord(char)
                    char_bytes = code_point.to_bytes(4, byteorder='big')
                    msg_bytes += char_bytes
            elif isinstance(message, bytes):
                # Directly use bytes (assumed pre-formatted correctly)
                msg_bytes = message
            else:
                raise ValueError("Message must be a string or bytes")

            # Validate message length is multiple of 4
            if len(msg_bytes) % 4 != 0:
                raise ValueError("Message bytes must be in 4-byte character format")

            # Prepare header
            header = b"ISC" + msg_type.encode()
            num_chars = len(msg_bytes) // 4
            header += struct.pack("!H", num_chars)

            # Send the message
            self.sock.sendall(header + msg_bytes)
            self.log(f"Sent {msg_type} message ({num_chars} chars)", "client")

        except Exception as e:
            self.show_error(f"Failed to send message: {str(e)}")

    def log(self, message, msg_type):
        color_map = {
            "client": "#4CAF50",
            "server": "#2196F3",
            "error": "#F44336",
            "info": "#FFC107",
            "success": "#00BCD4"
        }
        html = f'<span style="color:{color_map[msg_type]}">[{msg_type.upper()}]</span> {message}'
        self.log_panel.append(html)

    def show_error(self, message):
        QtWidgets.QMessageBox.critical(self, "Error", message)

    def closeEvent(self, event):
        if self.sock:
            self.sock.close()
        self.receiver.running = False
        event.accept()


class ReceiverThread(QtCore.QThread):
    message_received = QtCore.pyqtSignal(str, bytes)

    def __init__(self, sock):
        super().__init__()
        self.sock = sock
        self.running = True

    def run(self):
        while self.running:
            try:
                header = self.sock.recv(6)
                if len(header) < 6:
                    continue

                msg_type = header[3:4].decode()
                size = struct.unpack("!H", header[4:6])[0] * 4

                data = b''
                while len(data) < size:
                    chunk = self.sock.recv(size - len(data))
                    if not chunk:
                        break
                    data += chunk

                self.message_received.emit(msg_type, data)

            except Exception as e:
                if self.running:
                    print(f"Receive error: {str(e)}")
                break


def decode_4byte_message(data: bytes) -> str:
    """Convert 4-byte chunks by extracting the last byte and decoding as UTF-8."""
    byte_buffer = bytearray()

    # Process each 4-byte chunk
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        if len(chunk) != 4:
            continue  # Skip incomplete chunks

        # Convert 4-byte chunk to integer (big-endian)
        num = int.from_bytes(chunk, byteorder='big')

        # Convert back to original UTF-8 bytes (trim leading zeros)
        num_bytes = []
        while num > 0:
            num_bytes.append(num & 0xFF)
            num = num >> 8
        utf8_bytes = bytes(reversed(num_bytes))

        byte_buffer.extend(utf8_bytes)

    # Decode the full UTF-8 byte sequence
    try:
        return byte_buffer.decode('utf-8')
    except UnicodeDecodeError:
        return byte_buffer.decode('utf-8', errors='replace')


# Encryption function implementations
def shiftEncode(msg, key):
    """Handle full Unicode character set including special characters"""
    # If key is a string, hash it to get a numeric value
    if isinstance(key, str):
        shift = hash(key) % 256  # Use a reasonable shift range
    else:
        # If already numeric, use directly
        shift = int(key) % 256

    encodedMsg = b""
    for char in msg:
        try:
            # Get Unicode code point and apply shift
            code_point = ord(char)
            shifted_code = (code_point + shift) % 0x10FFFF
            # Ensure valid Unicode code point
            if shifted_code == 0:  # Avoid null character
                shifted_code = shift
            encodedMsg += shifted_code.to_bytes(4, byteorder='big')
        except Exception as e:
            self.log(f"Failed to encode character '{char}': {str(e)}", "error")
            # Use replacement character if encoding fails
            encodedMsg += (0xFFFD).to_bytes(4, byteorder='big')
    return encodedMsg

def encrypt_vigenere(message, key):
    # Vigenère cipher implementation
    result = ""
    key = key.upper()  # Ensure key is uppercase for consistent calculations
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]  # Convert key to 0-25 values

    for i, char in enumerate(message):
        if char.isalpha():
            # Determine if the character is uppercase or lowercase
            is_upper = char.isupper()
            char = char.upper()

            # Get the shift value from the key (cycling through key if needed)
            key_index = i % key_length
            shift = key_as_int[key_index]

            # Apply the shift
            char_code = ord(char) - ord('A')
            encrypted_code = (char_code + shift) % 26
            encrypted_char = chr(encrypted_code + ord('A'))

            # Restore the original case
            if not is_upper:
                encrypted_char = encrypted_char.lower()

            result += encrypted_char
        else:
            result += char

    return result


def rsa_encrypt(message, key):
    # Simple RSA encryption (simplified for demonstration)
    # In a real implementation, this would use proper RSA libraries
    try:
        # Parse the key string as "n,e" (modulus and exponent)
        if ',' not in key:
            return "Invalid RSA key format. Expected 'n,e'"

        parts = key.split(',')
        if len(parts) != 2:
            return "Invalid RSA key format. Expected 'n,e'"

        n = int(parts[0])
        e = int(parts[1])

        # Very simple RSA implementation - not secure for real usage
        result = []
        for char in message:
            # Convert each character to its numerical value
            m = ord(char)
            # Apply RSA encryption formula: c = m^e mod n
            c = pow(m, e, n)
            result.append(str(c))

        return ",".join(result)
    except Exception as e:
        return f"RSA encryption error: {str(e)}"


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = CryptoGUI()
    window.show()
    sys.exit(app.exec_())