import random
import socket
import sys
import traceback
from PyQt5 import QtWidgets, QtCore, QtGui
import struct
from threading import Thread

# Your existing functions from paste-2.txt - Unchanged
host = "vlbelintrocrypto.hevs.ch"  # Le nom du serveur
port = 6000  # Le numéro de port du serveur
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
print(host, port)


def isPrime(n, k=5):
    if n < 2:
        return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True


def generatePrime(bits=512):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= 1  # Force impair
        candidate |= (1 << (bits - 1))  # Force bit de poids fort
        if isPrime(candidate):
            return candidate


def generateGenerator(p):
    # Essaie de petits nombres jusqu'à trouver un générateur probable
    for g in range(2, p):
        if pow(g, 2, p) != 1 and pow(g, (p - 1) // 2, p) != 1:
            return g
    raise ValueError("Aucun générateur trouvé")


def privAndPubKey(g, p):
    privateKey = random.randint(2, p - 2)

    # Étape 2 : calculer clé publique
    publicKey = pow(g, privateKey, p)
    return privateKey, publicKey


def secretKey(othKey, privKey, p):
    sharedSecret = pow(othKey, privKey, p)

    return sharedSecret


def diffieHellmanExchange(g, p):
    # Étape 1 : choisir une clé privée (aléatoire)
    privateKey = random.randint(2, p - 2)

    # Étape 2 : calculer clé publique
    publicKey = pow(g, privateKey, p)

    # Étape 3 : envoyer clé publique au serveur
    pubKeyBytes = publicKey.to_bytes((publicKey.bit_length() + 7) // 8, byteorder='big')
    pubKeySize = len(pubKeyBytes)

    message = addMessageHeader("s") + addMessageSize(pubKeySize) + pubKeyBytes
    s.sendall(message)

    # Étape 4 : recevoir la clé publique de l'autre personne
    otherPublicKey = reception(b"s")

    # Étape 5 : calcul de la clé secrète partagée
    sharedSecret = pow(otherPublicKey, privateKey, p)

    return sharedSecret


def lastWord(t):  # Fonction qui retourne le dernier mot d'un str
    return t.rpartition(" ")[2]


def sizeOfMessage(b):
    result = b[4:]
    result = result[:2]
    return result


def reception(type):
    returnRecep = ""
    test = True
    while test:
        x = s.recv(6)
        l = (int.from_bytes(x[-2:], byteorder='big')) * 4
        mType = chr(x[3]).encode("utf-8")
        if mType == type:
            returnRecep += giveOriginalMessage(s.recv(l))
            test = False
        else:
            s.recv(l)

    return returnRecep


def shiftEncode(msg, key):
    encodedMsg = b""
    shift = int(key)

    for x in msg:
        charInt = int.from_bytes(x.encode("utf-8"), byteorder="big")
        charInt += shift
        charByte = charInt.to_bytes(4, byteorder="big")
        encodedMsg += charByte

    return encodedMsg


def shiftDecode(encodedMsg, key):  # Fonction qui decode un message encodé avec shift
    decodedMsg = b""
    shift = int(key)

    for x in encodedMsg:
        charInt = int.from_bytes(x.encode("utf-8"), byteorder="big")
        charInt -= shift
        charByte = charInt.to_bytes(4, byteorder="big")
        decodedMsg += charByte

    return decodedMsg


def vigenereEncode(msg, key):
    encodedMsg = b""
    keyLength = len(key)

    for i, char in enumerate(msg):
        m = int.from_bytes(char.encode("utf-8"), byteorder="big")
        k = int.from_bytes(key[i % keyLength].encode("utf-8"), byteorder="big")
        c = m + k
        encodedMsg += c.to_bytes(4, byteorder="big")

    return encodedMsg


def rsaEncode(msg, n, e):
    encodedMsg = b""
    for char in msg:
        m = int.from_bytes(char.encode("utf-8"), byteorder="big")
        c = pow(m, e, n)
        encodedMsg += c.to_bytes(4, byteorder="big")
    return encodedMsg


def addMessageHeader(msgType):  # Renvoie le header du message
    header = b"ISC"

    if msgType == "t" or msgType == "T":
        header += b"t"
    elif msgType == "s" or msgType == "S":
        header += b"s"
    elif msgType == "i" or msgType == "I":
        header += b"i"

    return header


def addMessageSize(n):  # Renvoie la taille du message dans le bon format
    size = b""
    size += n.to_bytes(2, byteorder="big")

    return size


def convertMessage(msg):
    finalMessage = b""
    for x in msg:
        if isinstance(x, int):
            finalMessage += x.to_bytes(4, byteorder="big")
        else:
            # x est un caractère (str)
            charInt = int.from_bytes(x.encode("utf-8"), byteorder="big")
            charByte = charInt.to_bytes(4, byteorder="big")
            finalMessage += charByte
    return finalMessage


def giveOriginalMessage(convertedMsg):
    res = ""
    conM = convertedMsg
    while conM != b"":
        charB = conM[:4]
        conM = conM[4:]
        a = charB.split(b"\x00")
        num = a[len(a) - 1]
        res += num.decode("utf-8")

    return res


def removeHeader(msg):
    return msg[6:]


# GUI Code
class CryptoClientGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Crypto Client")
        self.setGeometry(100, 100, 900, 700)

        # Main central widget
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        # Main layout
        self.main_layout = QtWidgets.QVBoxLayout(self.central_widget)

        # Create tabs for different message types
        self.tabs = QtWidgets.QTabWidget()

        # Create the tabs
        self.task_tab = QtWidgets.QWidget()
        self.chat_tab = QtWidgets.QWidget()
        self.info_tab = QtWidgets.QWidget()

        # Setup each tab
        self.setup_task_tab()
        self.setup_chat_tab()
        self.setup_info_tab()

        # Add tabs to the tab widget
        self.tabs.addTab(self.task_tab, "S - Task")
        self.tabs.addTab(self.chat_tab, "T - Chat")
        self.tabs.addTab(self.info_tab, "I - Info")

        # Add tab widget to main layout
        self.main_layout.addWidget(self.tabs)

        # Add log panel
        self.log_label = QtWidgets.QLabel("Communication Log:")
        self.log_text = QtWidgets.QTextEdit()
        self.log_text.setReadOnly(True)

        self.main_layout.addWidget(self.log_label)
        self.main_layout.addWidget(self.log_text)

        # Network thread setup
        self.receiver_thread = ReceiverThread(s)
        self.receiver_thread.message_received.connect(self.handle_received_message)
        self.receiver_thread.start()

        # Initialize variables
        self.current_task = None
        self.task_active = False
        self.current_key = None
        self.current_message = None
        self.prime = None
        self.generator = None
        self.private_key = None
        self.public_key = None
        self.dh_shared_secret = None
        self.chat_partner_public_key = None
        self.dh_setup_complete = False

        # Log that we're connected
        self.log_message("Connected to server", "system")

    def setup_task_tab(self):
        layout = QtWidgets.QVBoxLayout(self.task_tab)

        # Task selection group
        task_group = QtWidgets.QGroupBox("Task Selection")
        task_layout = QtWidgets.QFormLayout()

        self.task_combo = QtWidgets.QComboBox()
        self.task_combo.addItems([
            "shift encode",
            "vigenere encode",
            "rsa encode",
            "DifHel"
        ])

        self.msg_size_spin = QtWidgets.QSpinBox()
        self.msg_size_spin.setRange(1, 1000)
        self.msg_size_spin.setValue(128)

        self.start_task_btn = QtWidgets.QPushButton("Start Task")
        self.start_task_btn.clicked.connect(self.start_task)

        task_layout.addRow("Task:", self.task_combo)
        task_layout.addRow("Message Size:", self.msg_size_spin)
        task_layout.addRow("", self.start_task_btn)

        task_group.setLayout(task_layout)
        layout.addWidget(task_group)

        # Task response group
        response_group = QtWidgets.QGroupBox("Task Response")
        response_layout = QtWidgets.QVBoxLayout()

        self.task_status = QtWidgets.QLabel("No active task")

        self.received_message_label = QtWidgets.QLabel("Received Message:")
        self.received_message = QtWidgets.QTextEdit()
        self.received_message.setReadOnly(True)

        self.key_label = QtWidgets.QLabel("Key:")
        self.key_text = QtWidgets.QLineEdit()
        self.key_text.setReadOnly(True)

        self.auto_respond_btn = QtWidgets.QPushButton("Auto Process Task")
        self.auto_respond_btn.clicked.connect(self.process_task_automatically)

        response_layout.addWidget(self.task_status)
        response_layout.addWidget(self.received_message_label)
        response_layout.addWidget(self.received_message)
        response_layout.addWidget(self.key_label)
        response_layout.addWidget(self.key_text)
        response_layout.addWidget(self.auto_respond_btn)

        response_group.setLayout(response_layout)
        layout.addWidget(response_group)

    def setup_chat_tab(self):
        layout = QtWidgets.QVBoxLayout(self.chat_tab)

        # Chat history
        history_group = QtWidgets.QGroupBox("Chat History")
        history_layout = QtWidgets.QVBoxLayout()

        self.chat_history = QtWidgets.QTextEdit()
        self.chat_history.setReadOnly(True)

        history_layout.addWidget(self.chat_history)
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)

        # Message composition
        compose_group = QtWidgets.QGroupBox("Send Message")
        compose_layout = QtWidgets.QVBoxLayout()

        self.message_input = QtWidgets.QTextEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.setMaximumHeight(100)

        # Encryption options
        encrypt_layout = QtWidgets.QHBoxLayout()

        self.encrypt_checkbox = QtWidgets.QCheckBox("Encrypt Message")
        self.encrypt_checkbox.setChecked(True)

        self.encryption_combo = QtWidgets.QComboBox()
        self.encryption_combo.addItems(["Shift", "Vigenere", "RSA", "Diffie-Hellman"])
        self.encryption_combo.currentTextChanged.connect(self.encryption_method_changed)

        self.encryption_key = QtWidgets.QLineEdit()
        self.encryption_key.setPlaceholderText("Encryption key")

        encrypt_layout.addWidget(self.encrypt_checkbox)
        encrypt_layout.addWidget(QtWidgets.QLabel("Method:"))
        encrypt_layout.addWidget(self.encryption_combo)
        encrypt_layout.addWidget(QtWidgets.QLabel("Key:"))
        encrypt_layout.addWidget(self.encryption_key)

        # Add Diffie-Hellman setup group
        self.dh_group = QtWidgets.QGroupBox("Diffie-Hellman Setup")
        self.dh_group.setVisible(False)
        dh_layout = QtWidgets.QVBoxLayout()

        # DH Parameters section
        params_layout = QtWidgets.QFormLayout()

        self.prime_input = QtWidgets.QLineEdit()
        self.prime_input.setPlaceholderText("Prime (p)")

        self.generator_input = QtWidgets.QLineEdit()
        self.generator_input.setPlaceholderText("Generator (g)")

        self.gen_params_btn = QtWidgets.QPushButton("Generate Parameters")
        self.gen_params_btn.clicked.connect(self.generate_dh_parameters)

        params_layout.addRow("Prime (p):", self.prime_input)
        params_layout.addRow("Generator (g):", self.generator_input)
        params_layout.addRow("", self.gen_params_btn)

        # Keys section
        keys_layout = QtWidgets.QFormLayout()

        self.private_key_input = QtWidgets.QLineEdit()
        self.private_key_input.setPlaceholderText("Your private key")
        self.private_key_input.setReadOnly(True)

        self.public_key_input = QtWidgets.QLineEdit()
        self.public_key_input.setPlaceholderText("Your public key")
        self.public_key_input.setReadOnly(True)

        self.gen_keys_btn = QtWidgets.QPushButton("Generate Keys")
        self.gen_keys_btn.clicked.connect(self.generate_dh_keys)

        keys_layout.addRow("Your Private Key:", self.private_key_input)
        keys_layout.addRow("Your Public Key:", self.public_key_input)
        keys_layout.addRow("", self.gen_keys_btn)

        # Partner key section
        partner_layout = QtWidgets.QFormLayout()

        self.partner_key_input = QtWidgets.QLineEdit()
        self.partner_key_input.setPlaceholderText("Partner's public key")

        self.compute_secret_btn = QtWidgets.QPushButton("Compute Shared Secret")
        self.compute_secret_btn.clicked.connect(self.compute_dh_secret)

        partner_layout.addRow("Partner's Public Key:", self.partner_key_input)
        partner_layout.addRow("", self.compute_secret_btn)

        # Shared secret display
        self.shared_secret_input = QtWidgets.QLineEdit()
        self.shared_secret_input.setPlaceholderText("Shared secret will appear here")
        self.shared_secret_input.setReadOnly(True)

        # Assemble DH layout
        dh_layout.addLayout(params_layout)
        dh_layout.addLayout(keys_layout)
        dh_layout.addLayout(partner_layout)
        dh_layout.addWidget(QtWidgets.QLabel("Shared Secret:"))
        dh_layout.addWidget(self.shared_secret_input)

        self.dh_group.setLayout(dh_layout)

        # Add send button
        self.send_message_btn = QtWidgets.QPushButton("Send Message")
        self.send_message_btn.clicked.connect(self.send_chat_message)

        # Assemble main layout
        compose_layout.addWidget(self.message_input)
        compose_layout.addLayout(encrypt_layout)
        compose_layout.addWidget(self.dh_group)
        compose_layout.addWidget(self.send_message_btn)

        compose_group.setLayout(compose_layout)
        layout.addWidget(compose_group)

    def setup_info_tab(self):
        layout = QtWidgets.QVBoxLayout(self.info_tab)

        info_group = QtWidgets.QGroupBox("Info Request")
        info_layout = QtWidgets.QVBoxLayout()

        self.info_request = QtWidgets.QLineEdit()
        self.info_request.setPlaceholderText("Enter info request...")

        self.send_info_btn = QtWidgets.QPushButton("Send Info Request")
        self.send_info_btn.clicked.connect(self.send_info_request)

        info_layout.addWidget(self.info_request)
        info_layout.addWidget(self.send_info_btn)

        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # Info response area
        response_group = QtWidgets.QGroupBox("Info Response")
        response_layout = QtWidgets.QVBoxLayout()

        self.info_response = QtWidgets.QTextEdit()
        self.info_response.setReadOnly(True)

        response_layout.addWidget(self.info_response)

        response_group.setLayout(response_layout)
        layout.addWidget(response_group)

    def encryption_method_changed(self, method):
        if method == "Diffie-Hellman":
            self.dh_group.setVisible(True)
            if self.dh_shared_secret:
                self.encryption_key.setText(str(self.dh_shared_secret))
                self.encryption_key.setReadOnly(True)
            else:
                self.encryption_key.clear()
                self.encryption_key.setReadOnly(True)
                self.encryption_key.setPlaceholderText("Set up Diffie-Hellman first")
        else:
            self.dh_group.setVisible(False)
            self.encryption_key.setReadOnly(False)
            self.encryption_key.setPlaceholderText("Encryption key")
            self.encryption_key.clear()

    def generate_dh_parameters(self):
        try:
            # Generate a prime number (using a smaller bit size for faster execution)
            self.prime = generatePrime(bits=32)  # Use a larger value like 512 for production
            self.generator = generateGenerator(self.prime)

            self.prime_input.setText(str(self.prime))
            self.generator_input.setText(str(self.generator))

            self.log_message(f"Generated DH parameters: p={self.prime}, g={self.generator}", "system")
        except Exception as e:
            self.show_error(f"Error generating DH parameters: {str(e)}")

    def generate_dh_keys(self):
        try:
            if not self.prime or not self.generator:
                # Try to read from inputs
                try:
                    self.prime = int(self.prime_input.text())
                    self.generator = int(self.generator_input.text())
                except ValueError:
                    self.show_error("Please generate or enter valid prime and generator values first!")
                    return

            # Generate private and public keys
            self.private_key, self.public_key = privAndPubKey(self.generator, self.prime)

            self.private_key_input.setText(str(self.private_key))
            self.public_key_input.setText(str(self.public_key))

            self.log_message(f"Generated DH keys: private={self.private_key}, public={self.public_key}", "system")
        except Exception as e:
            self.show_error(f"Error generating DH keys: {str(e)}")

    def compute_dh_secret(self):
        try:
            partner_key_text = self.partner_key_input.text()
            if not partner_key_text:
                self.show_error("Please enter partner's public key!")
                return

            if not self.prime or not self.private_key:
                self.show_error("Please generate your keys first!")
                return

            partner_key = int(partner_key_text)
            self.chat_partner_public_key = partner_key

            # Calculate shared secret
            self.dh_shared_secret = secretKey(partner_key, self.private_key, self.prime)

            self.shared_secret_input.setText(str(self.dh_shared_secret))
            self.encryption_key.setText(str(self.dh_shared_secret))

            self.dh_setup_complete = True
            self.log_message(f"Computed shared secret: {self.dh_shared_secret}", "system")

            # Create instructions for the chat partner
            instructions = (
                f"--- DIFFIE-HELLMAN KEY EXCHANGE PARAMETERS ---\n"
                f"To decrypt my messages, please:\n"
                f"1. Use prime (p): {self.prime}\n"
                f"2. Use generator (g): {self.generator}\n"
                f"3. Generate your own private key\n"
                f"4. Calculate your public key = g^(your private key) mod p\n"
                f"5. My public key is: {self.public_key}\n"
                f"6. Calculate shared secret = (my public key)^(your private key) mod p\n"
                f"7. Use the shared secret as the encryption key\n"
                f"-------------------------------------------"
            )

            # Add instructions to chat history
            self.chat_history.append(f"<b>System:</b> <pre>{instructions}</pre>")

        except ValueError:
            self.show_error("Please enter a valid numeric public key!")
        except Exception as e:
            self.show_error(f"Error computing shared secret: {str(e)}")

    # Find the start_task method in your code and replace it with this:
    def start_task(self):
        task = self.task_combo.currentText()
        msg_size = self.msg_size_spin.value()

        self.current_task = task
        self.task_active = True

        # Prepare task command
        task_cmd = ""

        # Special case for DifHel - doesn't need message size
        if "DifHel" in task:
            task_cmd = "task DifHel"
        # Special case for RSA - needs uppercase
        elif "rsa encode" in task.lower():
            task_cmd = f"task RSA encode {msg_size}"
        # Default case for other tasks
        else:
            task_cmd = f"task {task} {msg_size}"

        # Send task command to server
        self.send_protocol_message('s', task_cmd)
        self.log_message(f"Starting task: {task_cmd}", "client")
        self.task_status.setText(f"Active Task: {task}")

        # Reset fields
        self.received_message.clear()
        self.key_text.clear()

    def process_task_automatically(self):
        if not self.task_active:
            self.show_error("No active task!")
            return

        if self.current_message is None:
            self.show_error("No message received from server!")
            return

        task = self.current_task.lower()
        message = self.current_message

        try:
            if "shift encode" in task:
                if self.current_key:
                    result = shiftEncode(message, self.current_key)
                    size = len(result) // 4
                    mess = addMessageHeader("s") + addMessageSize(size) + result
                    s.sendall(mess)
                    self.log_message("Sent shift-encoded message", "client")
                else:
                    self.show_error("No key received!")

            elif "shift decode" in task:
                if self.current_key:
                    result = shiftDecode(message, self.current_key)
                    size = len(result) // 4
                    mess = addMessageHeader("s") + addMessageSize(size) + result
                    s.sendall(mess)
                    self.log_message("Sent shift-decoded message", "client")
                else:
                    self.show_error("No key received!")

            elif "vigenere encode" in task:
                if self.current_key:
                    result = vigenereEncode(message, self.current_key)
                    size = len(result) // 4
                    mess = addMessageHeader("s") + addMessageSize(size) + result
                    s.sendall(mess)
                    self.log_message("Sent vigenere-encoded message", "client")
                else:
                    self.show_error("No key received!")

            elif "rsa encode" in task:
                if self.current_key:
                    # Parse the key more robustly
                    try:
                        # Extract n and e values from the key string
                        n_val = None
                        e_val = None
                        if "n=" in self.current_key and "e=" in self.current_key:
                            n_part = self.current_key.split("n=")[1].split(",")[0].strip()
                            e_part = self.current_key.split("e=")[1].strip()
                            n_val = int(n_part)
                            e_val = int(e_part)
                            result = rsaEncode(message, n_val, e_val)
                            size = len(result) // 4
                            mess = addMessageHeader("s") + addMessageSize(size) + result
                            s.sendall(mess)
                            self.log_message(f"Sent RSA-encoded message with n={n_val}, e={e_val}", "client")
                        else:
                            self.show_error("Invalid RSA key format!")
                    except Exception as e:
                        self.show_error(f"Error parsing RSA key: {str(e)}")
                else:
                    self.show_error("No key received!")

            elif "difhel" in task:
                # This requires a multi-step process
                self.process_diffie_hellman()

            else:
                self.show_error(f"Automatic processing not implemented for {task}")

        except Exception as e:
            self.show_error(f"Error processing task: {str(e)}")

    def process_diffie_hellman(self):   
        try:
            # Step 1: Generate small prime and generator for test
            prime = generatePrime(10)
            generator = generateGenerator(prime)
            self.prime = prime
            self.generator = generator

            self.log_message(f"Generated prime: {prime}, generator: {generator}", "system")
            self.prime_input.setText(str(prime))
            self.generator_input.setText(str(generator))

            # Step 2: Send prime and generator to server (proper size calculation)
            prime_gen_str = f"{prime}, {generator}"
            msg_bytes = convertMessage(prime_gen_str)
            msg_size = len(msg_bytes) // 4
            msg = addMessageHeader('s') + addMessageSize(msg_size) + msg_bytes
            s.sendall(msg)

            # Step 3: Wait for server confirmation
            header = s.recv(6)
            size = int.from_bytes(header[4:6], byteorder='big') * 4
            data = s.recv(size)
            response = giveOriginalMessage(data)
            self.log_message(f"Server response: {response}", "server")

            if response.strip().lower() != "y":
                self.show_error("Server did not accept DH parameters")
                return

            # Step 4: Receive server public key
            header = s.recv(6)
            size = int.from_bytes(header[4:6], byteorder='big') * 4
            data = s.recv(size)
            server_key = int(giveOriginalMessage(data))
            self.partner_key_input.setText(str(server_key))
            self.log_message(f"Received server public key: {server_key}", "server")

            # Step 5: Generate and send own public key
            priv, pub = privAndPubKey(generator, prime)
            self.private_key = priv
            self.public_key = pub
            self.private_key_input.setText(str(priv))
            self.public_key_input.setText(str(pub))

            self.send_protocol_message('s', str(pub))

            # Step 6: Receive ack
            header = s.recv(6)
            size = int.from_bytes(header[4:6], byteorder='big') * 4
            data = s.recv(size)
            ack = giveOriginalMessage(data)
            self.log_message(f"Server acknowledgment: {ack}", "server")

            # Step 7: Compute and send shared secret
            shared = secretKey(server_key, priv, prime)
            self.dh_shared_secret = shared
            self.shared_secret_input.setText(str(shared))
            self.send_protocol_message('s', str(shared))

            # Step 8: Receive final validation
            header = s.recv(6)
            size = int.from_bytes(header[4:6], byteorder='big') * 4
            data = s.recv(size)
            validation = giveOriginalMessage(data)
            self.log_message(f"Server validation: {validation}", "server")

            self.dh_setup_complete = True
            if self.encryption_combo.currentText() == "Diffie-Hellman":
                self.encryption_key.setText(str(shared))

            self.log_message("Diffie-Hellman exchange completed successfully!", "system")

        except Exception as e:
            self.show_error(f"Error in Diffie-Hellman process: {str(e)}")
            traceback.print_exc()

    def send_chat_message(self):
        message = self.message_input.toPlainText()
        if not message:
            self.show_error("Please enter a message!")
            return

        if self.encrypt_checkbox.isChecked():
            method = self.encryption_combo.currentText()

            if method == "Diffie-Hellman":
                if not self.dh_setup_complete or not self.dh_shared_secret:
                    self.show_error("Please complete the Diffie-Hellman setup first!")
                    return
                key = str(self.dh_shared_secret)
            else:
                key = self.encryption_key.text()
                if not key:
                    self.show_error("Please enter an encryption key!")
                    return

            try:
                if method == "Shift" or method == "Diffie-Hellman":
                    # For Diffie-Hellman, we'll use the shared secret as a shift key
                    encoded_message = shiftEncode(message, key)
                    size = len(encoded_message) // 4
                    mess = addMessageHeader("t") + addMessageSize(size) + encoded_message
                    s.sendall(mess)
                    encryption_display = "Diffie-Hellman (shift)" if method == "Diffie-Hellman" else "Shift"

                elif method == "Vigenere":
                    encoded_message = vigenereEncode(message, key)
                    size = len(encoded_message) // 4
                    mess = addMessageHeader("t") + addMessageSize(size) + encoded_message
                    s.sendall(mess)
                    encryption_display = "Vigenere"

                elif method == "RSA":
                    self.show_error(
                        "RSA encryption requires additional parameters. Not fully implemented in the chat tab.")
                    return
                    encryption_display = "RSA"

                self.chat_history.append(f"<b>You (encrypted with {encryption_display}):</b> {message}")
                self.log_message(f"Sent encrypted chat message using {encryption_display}", "client")

            except Exception as e:
                self.show_error(f"Encryption error: {str(e)}")
                return
        else:
            # Send plaintext
            self.send_protocol_message('t', message)
            self.chat_history.append(f"<b>You:</b> {message}")
            self.log_message("Sent chat message", "client")

        self.message_input.clear()

    def send_info_request(self):
        request = self.info_request.text()
        if not request:
            self.show_error("Please enter an info request!")
            return

        self.send_protocol_message('i', request)
        self.log_message(f"Sent info request: {request}", "client")
        self.info_request.clear()

    def send_protocol_message(self, msg_type, message):
        try:
            msg_bytes = convertMessage(message)
            size = len(msg_bytes) // 4

            header = addMessageHeader(msg_type)
            size_bytes = addMessageSize(size)

            full_message = header + size_bytes + msg_bytes
            s.sendall(full_message)

        except Exception as e:
            self.show_error(f"Error sending message: {str(e)}")

    def handle_received_message(self, msg_type, data):
        msg_text = giveOriginalMessage(data)

        if msg_type == b"s" and self.task_active:
            self.received_message.setPlainText(msg_text)
            self.log_message(f"Received task response: {msg_text}", "server")

            # Check if there's a key in the message
            if "-key " in msg_text:
                key_part = msg_text.split("-key ")
                if len(key_part) > 1:
                    self.current_key = key_part[1].strip()
                    self.key_text.setText(self.current_key)
                    self.log_message(f"Extracted key: {self.current_key}", "system")
            # Special handling for RSA keys
            elif "n=" in msg_text and "e=" in msg_text:
                # Try to extract n and e parameters
                try:
                    n_start = msg_text.find("n=")
                    e_start = msg_text.find("e=")

                    if n_start != -1 and e_start != -1:
                        # Extract n value (assumes n comes before e)
                        n_end = msg_text.find(",", n_start) if msg_text.find(",", n_start) != -1 else e_start
                        n_value = msg_text[n_start:n_end].strip()

                        # Extract e value
                        e_end = msg_text.find(" ", e_start) if msg_text.find(" ", e_start) != -1 else len(msg_text)
                        e_value = msg_text[e_start:e_end].strip()

                        # Create the key string in the expected format
                        self.current_key = f"{n_value}, {e_value}"
                        self.key_text.setText(self.current_key)
                        self.log_message(f"Extracted RSA key: {self.current_key}", "system")
                except Exception as e:
                    self.log_message(f"Error extracting RSA key: {str(e)}", "error")

            # Store the message for processing
            self.current_message = msg_text

            # For debugging
            if "rsa" in self.current_task.lower() and not self.current_key:
                self.log_message("Warning: No RSA key detected in the message", "system")

    def log_message(self, message, source):
        color_map = {
            "client": "#4CAF50",  # Green
            "server": "#2196F3",  # Blue
            "system": "#9C27B0",  # Purple
            "error": "#F44336"  # Red
        }

        timestamp = QtCore.QDateTime.currentDateTime().toString("hh:mm:ss")
        html = f'<span style="color:{color_map[source]}">[{timestamp} {source.upper()}]</span> {message}'
        self.log_text.append(html)

    def show_error(self, message):
        self.log_message(message, "error")
        QtWidgets.QMessageBox.critical(self, "Error", message)


class ReceiverThread(QtCore.QThread):
    message_received = QtCore.pyqtSignal(bytes, bytes)

    def __init__(self, socket):
        super().__init__()
        self.socket = socket
        self.running = True

    def run(self):
        while self.running:
            try:
                # Read header
                header = self.socket.recv(6)
                if not header or len(header) < 6:
                    continue

                # Parse header
                msg_type = header[3:4]  # 's', 't', or 'i'
                size = int.from_bytes(header[4:6], byteorder='big') * 4

                # Read data
                data = b''
                bytes_received = 0

                while bytes_received < size:
                    chunk = self.socket.recv(min(4096, size - bytes_received))
                    if not chunk:
                        break
                    data += chunk
                    bytes_received += len(chunk)

                # Emit the signal with the received data
                self.message_received.emit(msg_type, data)

            except Exception as e:
                print(f"Receiver error: {str(e)}")
                traceback.print_exc()
                if not self.running:
                    break

    def stop(self):
        self.running = False
        self.terminate()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = CryptoClientGUI()
    window.show()
    sys.exit(app.exec_())
