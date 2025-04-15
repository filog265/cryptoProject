import random
import socket
import sys
from PyQt5 import QtWidgets, QtCore, QtGui
import struct
from threading import Thread


class CryptoClientGUI(QtWidgets.QMainWindow):
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

    def init_ui(self):
        # Main container
        main_widget = QtWidgets.QWidget()
        self.setCentralWidget(main_widget)
        layout = QtWidgets.QVBoxLayout(main_widget)
        layout.setContentsMargins(15, 15, 15, 15)

        # Message type selector
        msg_type_layout = QtWidgets.QHBoxLayout()
        msg_type_label = QtWidgets.QLabel("Message Type:")
        self.msg_type_combo = QtWidgets.QComboBox()
        self.msg_type_combo.addItems(["S - Task", "T - Chat", "I - Info"])
        self.msg_type_combo.currentIndexChanged.connect(self.update_ui_for_message_type)
        msg_type_layout.addWidget(msg_type_label)
        msg_type_layout.addWidget(self.msg_type_combo)
        msg_type_layout.addStretch(1)
        layout.addLayout(msg_type_layout)

        # Tab widget for different message types
        self.tab_widget = QtWidgets.QTabWidget()

        # S-type (Task) tab
        self.task_tab = QtWidgets.QWidget()
        self.init_task_tab()
        self.tab_widget.addTab(self.task_tab, "S - Task")

        # T-type (Chat) tab
        self.chat_tab = QtWidgets.QWidget()
        self.init_chat_tab()
        self.tab_widget.addTab(self.chat_tab, "T - Chat")

        # Connect tab changes to message type combo
        self.tab_widget.currentChanged.connect(self.sync_tab_with_combo)

        layout.addWidget(self.tab_widget)

        # Log panel
        log_label = QtWidgets.QLabel("Communication Log:")
        layout.addWidget(log_label)

        self.log_panel = QtWidgets.QTextEdit()
        self.log_panel.setReadOnly(True)
        self.log_panel.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        layout.addWidget(self.log_panel)

        # Apply style
        self.apply_style()

    def init_task_tab(self):
        task_layout = QtWidgets.QVBoxLayout(self.task_tab)

        # Task controls
        self.task_group = QtWidgets.QGroupBox("Server Task Setup")
        task_ctrl_layout = QtWidgets.QFormLayout()

        # Task selection
        self.task_combo = QtWidgets.QComboBox()
        self.task_combo.addItems(
            ["shift encode", "shift decode", "vigenere encode", "vigenere decode", "rsa encode", "rsa decode",
             "DifHel"])
        task_ctrl_layout.addRow("Task:", self.task_combo)

        # Message size (for encryption tasks)
        self.message_size = QtWidgets.QSpinBox()
        self.message_size.setRange(1, 1024)
        self.message_size.setValue(128)
        task_ctrl_layout.addRow("Message Size:", self.message_size)

        # Start task button
        self.start_task_btn = QtWidgets.QPushButton("Start Task")
        self.start_task_btn.clicked.connect(self.start_task)
        task_ctrl_layout.addRow("", self.start_task_btn)

        self.task_group.setLayout(task_ctrl_layout)
        task_layout.addWidget(self.task_group)

        # Task response area
        self.response_group = QtWidgets.QGroupBox("Task Response")
        response_layout = QtWidgets.QVBoxLayout()

        self.task_status = QtWidgets.QLabel("No active task")
        response_layout.addWidget(self.task_status)

        self.received_message = QtWidgets.QTextEdit()
        self.received_message.setReadOnly(True)
        self.received_message.setPlaceholderText("Received message will appear here...")
        response_layout.addWidget(QtWidgets.QLabel("Received Message:"))
        response_layout.addWidget(self.received_message)

        self.received_key = QtWidgets.QTextEdit()
        self.received_key.setReadOnly(True)
        self.received_key.setPlaceholderText("Encryption key will appear here...")
        self.received_key.setMaximumHeight(100)
        response_layout.addWidget(QtWidgets.QLabel("Received Key:"))
        response_layout.addWidget(self.received_key)

        # Manual message input area
        self.manual_response = QtWidgets.QTextEdit()
        self.manual_response.setPlaceholderText("Enter manual response if needed...")
        response_layout.addWidget(QtWidgets.QLabel("Manual Response:"))
        response_layout.addWidget(self.manual_response)

        self.send_response_btn = QtWidgets.QPushButton("Send Response")
        self.send_response_btn.clicked.connect(self.send_task_response)
        response_layout.addWidget(self.send_response_btn)

        self.response_group.setLayout(response_layout)
        task_layout.addWidget(self.response_group)

    def init_chat_tab(self):
        chat_layout = QtWidgets.QVBoxLayout(self.chat_tab)

        # Message composition area
        self.chat_group = QtWidgets.QGroupBox("Send Message")
        chat_compose_layout = QtWidgets.QVBoxLayout()

        self.message_input = QtWidgets.QTextEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        chat_compose_layout.addWidget(QtWidgets.QLabel("Message:"))
        chat_compose_layout.addWidget(self.message_input)

        # Encryption options
        encryption_layout = QtWidgets.QHBoxLayout()

        self.encrypt_check = QtWidgets.QCheckBox("Encrypt Message")
        self.encrypt_check.setChecked(True)
        encryption_layout.addWidget(self.encrypt_check)

        self.encryption_method = QtWidgets.QComboBox()
        self.encryption_method.addItems(["Shift", "Vigenere", "RSA"])
        encryption_layout.addWidget(QtWidgets.QLabel("Method:"))
        encryption_layout.addWidget(self.encryption_method)

        self.encryption_key = QtWidgets.QLineEdit()
        self.encryption_key.setPlaceholderText("Encryption key")
        encryption_layout.addWidget(QtWidgets.QLabel("Key:"))
        encryption_layout.addWidget(self.encryption_key)

        chat_compose_layout.addLayout(encryption_layout)

        # Send button
        self.send_message_btn = QtWidgets.QPushButton("Send Message")
        self.send_message_btn.clicked.connect(self.send_chat_message)
        self.send_message_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        chat_compose_layout.addWidget(self.send_message_btn)

        self.chat_group.setLayout(chat_compose_layout)
        chat_layout.addWidget(self.chat_group)

        # Chat history
        self.chat_history_group = QtWidgets.QGroupBox("Chat History")
        chat_history_layout = QtWidgets.QVBoxLayout()

        self.chat_history = QtWidgets.QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setPlaceholderText("Messages will appear here...")
        chat_history_layout.addWidget(self.chat_history)

        self.chat_history_group.setLayout(chat_history_layout)
        chat_layout.addWidget(self.chat_history_group)

    def update_ui_for_message_type(self, index):
        self.tab_widget.setCurrentIndex(index)

    def sync_tab_with_combo(self, index):
        self.msg_type_combo.setCurrentIndex(index)

    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #2b2b2b; }
            QWidget { color: #ffffff; }
            QGroupBox { 
                border: 1px solid #3a3a3a;
                margin-top: 1ex;
                padding: 10px;
            }
            QTextEdit, QLineEdit { 
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #3a3a3a;
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
            QComboBox {
                background-color: #3a3a3a;
                color: #ffffff;
                border: 1px solid #505050;
                padding: 3px;
            }
            QLabel, QCheckBox {
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

    def start_task(self):
        if not self.sock:
            self.show_error("Not connected to server!")
            return

        # Reset state
        self.task_active = True
        self.expected_msg = None
        self.expected_key = None

        # Get task details
        task = self.task_combo.currentText()
        message_size = self.message_size.value()

        # Prepare and send command
        task_cmd = f"task {task} {message_size}"
        self.send_message_to_server('s', task_cmd)

        self.current_task = task
        self.task_status.setText(f"Active Task: {task}")
        self.log(f"Started task: {task_cmd}", "info")

    def send_task_response(self):
        if not self.sock:
            self.show_error("Not connected to server!")
            return

        response = self.manual_response.toPlainText()
        if not response:
            self.show_error("Please enter a response")
            return

        self.send_message_to_server('s', response)
        self.log(f"Sent task response: {response[:50]}...", "client")
        self.manual_response.clear()

    def send_chat_message(self):
        if not self.sock:
            self.show_error("Not connected to server!")
            return

        message = self.message_input.toPlainText()
        if not message:
            self.show_error("Please enter a message")
            return

        # Check if encryption is requested
        if self.encrypt_check.isChecked():
            method = self.encryption_method.currentText()
            key = self.encryption_key.text()

            if not key:
                self.show_error("Please enter an encryption key")
                return

            try:
                if method == "Shift":
                    encrypted = self.shift_encode(message, key)
                elif method == "Vigenere":
                    encrypted = self.vigenere_encode(message, key)
                elif method == "RSA":
                    self.show_error("RSA encryption not fully implemented in this version")
                    return

                self.log(f"Message encrypted using {method}", "info")
                self.chat_history.append(f"<b>You (encrypted with {method}):</b> {message}")
                message = encrypted
            except Exception as e:
                self.log(f"Encryption failed: {str(e)}", "error")
                return
        else:
            self.chat_history.append(f"<b>You:</b> {message}")

        # Send the message
        self.send_message_to_server('t', message)
        self.log(f"Sent chat message", "client")

        # Clear the message area
        self.message_input.clear()

    def handle_server_message(self, msg_type, data):
        # Handle initial connection message
        if self.initial_connection:
            decoded = self.decode_message(data)
            self.log(f"Server connected: {decoded}", "success")
            self.initial_connection = False
            return

        decoded_msg = self.decode_message(data)

        # Handle based on message type
        if msg_type == 's':
            if self.task_active:
                if not self.expected_msg:
                    # This is the first message (usually the task description or message to encrypt)
                    self.expected_msg = decoded_msg
                    self.received_message.setPlainText(decoded_msg)
                    self.log(f"Received task message: {decoded_msg[:50]}...", "server")
                elif not self.expected_key:
                    # This is the second message (usually the key)
                    self.expected_key = decoded_msg
                    self.received_key.setPlainText(decoded_msg)
                    self.log(f"Received key: {decoded_msg}", "server")
                    self.process_encryption()
                else:
                    # This is probably a response to our encryption
                    self.task_status.setText(f"Task response: {decoded_msg}")
                    self.log(f"Task result: {decoded_msg}", "server")
                    # Reset for next task
                    self.task_active = False
            else:
                # Generic S message
                self.log(f"Server message (S): {decoded_msg}", "server")

        elif msg_type == 't':
            # Chat message
            self.chat_history.append(f"<b>Server:</b> {decoded_msg}")
            self.log(f"Chat message: {decoded_msg[:50]}...", "server")

        elif msg_type == 'i':
            # Info message
            self.log(f"Server info: {decoded_msg}", "server")

    def process_encryption(self):
        try:
            task = self.current_task.lower()

            if "shift encode" in task:
                key = self.expected_key
                msg = self.expected_msg
                encrypted = self.shift_encode(msg, key)
                self.send_message_to_server('s', encrypted)
                self.log("Sent shift-encrypted message", "client")

            elif "vigenere encode" in task:
                key = self.expected_key
                msg = self.expected_msg
                encrypted = self.vigenere_encode(msg, key)
                self.send_message_to_server('s', encrypted)
                self.log("Sent vigenere-encrypted message", "client")

            elif "rsa encode" in task:
                self.log("RSA encryption requested - use manual response", "info")
                # RSA requires more complex handling

            elif "difhel" in task:
                # Handle Diffie-Hellman key exchange
                self.log("Diffie-Hellman requested - use manual responses", "info")

        except Exception as e:
            self.log(f"Encryption processing failed: {str(e)}", "error")

    def shift_encode(self, msg, key):
        try:
            # Convert key to integer if it's a string
            if isinstance(key, str):
                try:
                    shift = int(key)
                except ValueError:
                    # If key is not a number, use a hash of the string
                    shift = sum(ord(c) for c in key) % 256
            else:
                shift = int(key)

            encoded_msg = b""
            for char in msg:
                char_int = ord(char)
                char_int += shift
                char_bytes = char_int.to_bytes(4, byteorder="big")
                encoded_msg += char_bytes

            return encoded_msg
        except Exception as e:
            self.log(f"Shift encoding error: {str(e)}", "error")
            raise

    def vigenere_encode(self, msg, key):
        try:
            encoded_msg = b""
            key_length = len(key)

            for i, char in enumerate(msg):
                m = ord(char)
                k = ord(key[i % key_length])
                c = m + k
                encoded_msg += c.to_bytes(4, byteorder="big")

            return encoded_msg
        except Exception as e:
            self.log(f"Vigenere encoding error: {str(e)}", "error")
            raise

    def send_message_to_server(self, msg_type, message):
        try:
            # Convert message to bytes following protocol (4 bytes per character)
            if isinstance(message, str):
                msg_bytes = self.convert_message(message)
            elif isinstance(message, bytes):
                msg_bytes = message
            else:
                raise ValueError("Message must be a string or bytes")

            # Prepare header
            header = b"ISC" + msg_type.encode()
            num_chars = len(msg_bytes) // 4
            header += struct.pack("!H", num_chars)

            # Send the message
            self.sock.sendall(header + msg_bytes)
            self.log(f"Sent {msg_type} message ({num_chars} chars)", "client")

        except Exception as e:
            self.show_error(f"Failed to send message: {str(e)}")

    def convert_message(self, msg):
        final_message = b""
        for x in msg:
            char_int = ord(x)
            char_byte = char_int.to_bytes(4, byteorder="big")
            final_message += char_byte
        return final_message

    def decode_message(self, data):
        try:
            result = ""
            i = 0
            while i < len(data):
                # Take 4 bytes at a time
                char_bytes = data[i:i + 4]
                if len(char_bytes) == 4:
                    # Convert to integer
                    code_point = int.from_bytes(char_bytes, byteorder='big')
                    # Convert to character
                    try:
                        char = code_point.encode('utf-8')
                        result += char
                    except ValueError:
                        # If code point is invalid, use replacement character
                        result += '�'
                i += 4
            return result
        except Exception as e:
            self.log(f"Error decoding message: {str(e)}", "error")
            return data.decode('utf-8', errors='replace')

    def log(self, message, msg_type):
        color_map = {
            "client": "#4CAF50",  # Green
            "server": "#2196F3",  # Blue
            "error": "#F44336",  # Red
            "info": "#FFC107",  # Yellow
            "success": "#00BCD4"  # Cyan
        }
        html = f'<span style="color:{color_map[msg_type]}">[{msg_type.upper()}]</span> {message}'
        self.log_panel.append(html)

    def show_error(self, message):
        QtWidgets.QMessageBox.critical(self, "Error", message)

    def closeEvent(self, event):
        if hasattr(self, 'sock') and self.sock:
            self.sock.close()
        if hasattr(self, 'receiver') and self.receiver:
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
                # Receive header (6 bytes)
                header = self.sock.recv(6)
                if len(header) < 6:
                    continue

                # Parse header
                msg_type = chr(header[3])
                size = int.from_bytes(header[4:6], byteorder='big') * 4

                # Receive data
                data = b''
                while len(data) < size:
                    chunk = self.sock.recv(size - len(data))
                    if not chunk:
                        break
                    data += chunk

                # Emit signal with received data
                self.message_received.emit(msg_type, data)

            except Exception as e:
                if self.running:
                    print(f"Receive error: {str(e)}")
                break


# Cryptography helper functions
def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True


def generate_prime(bits=512):
    """Generate a probable prime number with specified bit length"""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= 1  # Force odd
        candidate |= (1 << (bits - 1))  # Force high bit
        if is_prime(candidate):
            return candidate


def generate_generator(p):
    """Find a generator for the multiplicative group Z_p"""
    for g in range(2, p):
        if pow(g, 2, p) != 1 and pow(g, (p - 1) // 2, p) != 1:
            return g
    raise ValueError("No generator found")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = CryptoClientGUI()
    window.show()
    sys.exit(app.exec_())
