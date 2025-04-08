import socket
host = "vlbelintrocrypto.hevs.ch"  # Le nom du serveur
port = 6000  # Le numéro de port du serveur
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
print(host, port)

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

def toHex(number):  # Fonction qui convertit un numéro en hexadecimal (utilisé pour la taille du message envoyé)
    msb = (number >> 8) & 0xFF
    lsb = number & 0xFF
    return bytes([msb, lsb])

def shiftEncode(msg, key):
    encodedMsg = b""
    shift = int(key)

    for x in msg:
        if isinstance(x, str):  # Si c'est une string
            val = ord(x)
        else:  # Si c'est déjà un byte (ex : après un décodage UTF-8 partiel)
            val = x

        shifted = (val + shift) % 256  # reste dans la plage d'1 byte
        encodedMsg += bytes([shifted])

    return encodedMsg

def shiftDecode(encodedMsg, key):  # Fonction qui decode un message encodé avec shift
    decodedMsg = ""
    for x in encodedMsg:
        y = ord(x) - int(key)
        decodedMsg += chr(y).encode("utf-8")
    return decodedMsg

def vigenereEncode(msg, key):  # Fonction qui encode un message avec l'encodage vigenere
    position = 0
    newKey = ""

    for x in msg:
        newKey += key[position]
        if position == len(key):
            position = 0
        else:
            position += 1

    encryptedText = []

    for i in range(len(msg)):
        char = ord(msg[i])
        keyCode = ord(newKey[i])
        encryptedChar = chr(char + keyCode % 0xffff).encode("utf-8")
        encryptedText.append(encryptedChar)
    return "".join(encryptedText)

#def vigenereDecode(encodedMsg, key):  # Fonction qui decode un message encodé avec vigenere

def sTypeMessage(mT):  # Fonction qui s'occupe des messages de type 's'
    task = input("Enter task: ")
    s.sendall(addMessageHeader(mT) + addMessageSize(task) + convertMessage(task))
    taskMessage = ""
    f = True
    while f:
        taskMessage = reception(b"s")

        if taskMessage == "Unknown command or no task running" or taskMessage == "Wrong task parameters":
            print(taskMessage)
            task = input("Enter task: ")
            s.sendall(addMessageHeader(mT) + addMessageSize(task) + convertMessage(task))
        else:
            f = False

    print(taskMessage)
    taskKey = taskMessage.split("-key ")

    messageToEncodeDecode = reception(b"s")

    print("Message: " + messageToEncodeDecode)

    if "shift" in task:
        if "encode" in task:
            encodedResult = shiftEncode(messageToEncodeDecode, taskKey[1])
            s.sendall(addMessageHeader("s") + addMessageSize(encodedResult) + convertMessage(encodedResult))
        elif "decode" in task:
            decodedResult = shiftDecode(messageToEncodeDecode.decode(), taskKey[1])
            print("Your decoding gave this result: " + decodedResult)
            s.sendall(addMessageHeader(mT) + addMessageSize(decodedResult) + convertMessage(decodedResult))

    #result = reception2(b"s")

    print(reception(b"s"))

def tTypeMessage(mT):  # Fonction qui s'occupe des messages de type 't'
    message = input("Enter message: ")

    encryption = input("Choose Encryption type (Shift, Vigenere, RSA): ")

    t = True
    while t:
        if encryption.upper() != "RSA" and encryption.upper() != "VIGENERE" and encryption.upper() != "SHIFT":
            print("Invalid input!")
            encryption = input("Choose Encryption type (Shift, Vigenere, RSA): ")
        else:
            t = False

    if encryption.upper() == "SHIFT":
        shiftKey = input("Enter your shift encoding key: ")
        sEncodedMessage = shiftEncode(message, shiftKey)
        s.sendall(addMessageHeader(mT) + addMessageSize(sEncodedMessage) + convertMessage(sEncodedMessage))
        print("Your message has been sent!")
    elif encryption.upper() == "VIGENERE":
        vigenereKey = input("Enter your vigenere encoding key: ")
        vEncodedMessage = vigenereEncode(message, vigenereKey)
        s.sendall(addMessageHeader(mT) + addMessageSize(vEncodedMessage) + convertMessage(vEncodedMessage))
        print("Your message has been sent!")

def addMessageHeader(msgType):  # Renvoie le header du message
    header = b"ISC"

    if msgType == "t" or msgType == "T":
        header += b"t"
    elif msgType == "s" or msgType == "S":
        header += b"s"
    elif msgType == "i" or msgType == "I":
        header += b"i"

    return header

def addMessageSize(msg):  # Renvoie la taille du message
    size = b""
    a = len(msg)
    size += toHex(a)

    return size

def convertMessage(msg):
    finalMessage = b""
    for x in msg:
        if isinstance(x, int):
            # Direct byte
            if x <= 0x7f:
                finalMessage += b"\x00\x00\x00" + bytes([x])
            else:
                finalMessage += b"\x00\x00" + bytes([x])
        else:
            # x est un caractère (str)
            charBytes = x.encode("utf-8")
            if len(charBytes) == 1 and charBytes <= b"\x7f":
                finalMessage += b"\x00\x00\x00" + charBytes
            else:
                finalMessage += b"\x00\x00" + charBytes
    return finalMessage

def giveOriginalMessage(convertedMsg):
    original_bytes = bytearray()
    i = 0
    length = len(convertedMsg)

    while i < length:
        # Cas ASCII : préfixe \x00\x00\x00 suivi d'1 octet
        if i + 3 < length and convertedMsg[i:i + 3] == b"\x00\x00\x00":
            original_bytes.append(convertedMsg[i + 3])
            i += 4

        # Cas UTF-8 : préfixe \x00\x00 suivi d'1 ou plusieurs octets
        elif i + 2 < length and convertedMsg[i:i + 2] == b"\x00\x00":
            i += 2
            # Lire les bytes suivants jusqu’au prochain préfixe ou fin
            while i < length and not (
                convertedMsg[i:i + 3] == b"\x00\x00\x00" or
                convertedMsg[i:i + 2] == b"\x00\x00"
            ):
                original_bytes.append(convertedMsg[i])
                i += 1

        else:
            # Saut de sécurité si on tombe sur un format inattendu
            i += 1

    try:
        return original_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        print("⚠️ Erreur de décodage UTF-8, message tronqué.")
        return original_bytes.decode("utf-8", errors="replace")

def removeHeader(msg):
    return msg[6:]

#---------------------------------------------------------------------------------------------------------------------

messageType = input("Enter message type ('t', 'i' or 's'): ")
t = True
while t:
    if messageType != "t" and messageType != "s" and messageType != "i" and messageType != "T" and messageType != "I" and messageType != "S":
        print("Invalid input!")
        messageType = input("Enter message type ('t', 'i' or 's'): ")
    else:
        t = False

if messageType == "s" or messageType == "S":
    sTypeMessage(messageType)
elif messageType == "t" or messageType == "T":
    tTypeMessage(messageType)
