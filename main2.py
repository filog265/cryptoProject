import random
import socket
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
        if pow(a, n-1, n) != 1:
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
    # Lire le header et taille
    """header = s.recv(6)
    if not header.startswith(b"ISCs"):
        raise ValueError("Réponse du serveur invalide")

    size = int.from_bytes(header[4:6], byteorder='big')
    otherPubKeyBytes = s.recv(size)

    otherPublicKey = int.from_bytes(otherPubKeyBytes, byteorder='big')"""
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

    for x in msg:
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

#def vigenereDecode(encodedMsg, key):  # Fonction qui decode un message encodé avec vigenere

def rsaEncode(msg, n, e):
    encodedMsg = b""
    for char in msg:
        m = int.from_bytes(char.encode("utf-8"), byteorder="big")
        c = pow(m, e, n)
        encodedMsg += c.to_bytes(4, byteorder="big")
    return encodedMsg


def sTypeMessage(mT):  # Fonction qui s'occupe des messages de type 's'
    task = input("Enter task: ")
    taskSize = len(task)
    s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))
    taskMessage = ""
    f = True
    while f:
        taskMessage = reception(b"s")

        if taskMessage == "Unknown command or no task running" or taskMessage == "Wrong task parameters":
            print(taskMessage)
            task = input("Enter task: ")
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))
        else:
            f = False

    if "shift" in task:
        if "encode" in task:
            print(taskMessage)
            taskKey = taskMessage.split("-key ")[1]

            messageToEncodeDecode = reception(b"s")
            print("Message: " + messageToEncodeDecode)

            encodedResult = shiftEncode(messageToEncodeDecode, taskKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            print(reception(b"s"))

        elif "decode" in task:
            print(taskMessage)
            #taskKey = taskMessage.split("-key ")

            #messageToEncodeDecode = reception(b"s")
            messageToEncodeDecode = s.recv(1024)
            print(b"Message: " + messageToEncodeDecode)

            """decodedResult = shiftDecode(messageToEncodeDecode, taskKey[1])
            size = len(decodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + decodedResult
            s.sendall(mess)"""
            print(reception(b"s"))

    elif "vigenere" in task:
        if "encode" in task:
            print(taskMessage)
            taskKey = taskMessage.split("-key ")[1]

            messageToEncodeDecode = reception(b"s")
            print("Message: " + messageToEncodeDecode)

            encodedResult = vigenereEncode(messageToEncodeDecode, taskKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            print(reception(b"s"))

        elif "decode" in task:
            print(reception(b"s"))
            print(reception(b"s"))

    elif "rsa" in task.lower():
        if "encode" in task:
            print(taskMessage)
            nKey = int(taskMessage.split("=")[1][:-3])
            eKey = int(taskMessage.split("=")[2])

            messageToEncodeDecode = reception(b"s")
            print("Message: " + messageToEncodeDecode)

            encodedResult = rsaEncode(messageToEncodeDecode, nKey, eKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            print(reception(b"s"))

        elif "decode" in task:
            print(reception(b"s"))
            print(reception(b"s"))

    elif "DifHel" in task:
        print(taskMessage)
        prime = generatePrime(10)
        generator = generateGenerator(prime)
        primeAndGen = str(prime) + ", " + str(generator)

        print("prime: " + str(prime) + ", generator: " + str(generator))
        mess = addMessageHeader(mT) + addMessageSize(len(primeAndGen)) + convertMessage(primeAndGen)
        s.sendall(mess)
        print(reception(b"s"))
        otherPubKey = int(reception(b"s"))
        print(otherPubKey)

        privateKey, publicKey = privAndPubKey(generator, prime)
        mess2 = addMessageHeader(mT) + addMessageSize(len(str(publicKey))) + convertMessage(str(publicKey))
        s.sendall(mess2)
        print(reception(b"s"))

        sharedKey = secretKey(otherPubKey, privateKey, prime)
        mess3 = addMessageHeader(mT) + addMessageSize(len(str(sharedKey))) + convertMessage(str(sharedKey))
        s.sendall(mess3)
        print("shared key: " + str(sharedKey))
        print(reception(b"s"))

    elif "hash" in task:
        if "verify" in task:
            print(reception(b"s"))
            print(reception(b"s"))
            print(reception(b"s"))

        else:
            print(reception(b"s"))
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

def addMessageSize(n):  # Renvoie la taille du message dans le bon format
    size = b""
    size += n.to_bytes(2, byteorder="big")

    return size

def convertMessage(msg):
    finalMessage = b""
    for x in msg:
        if isinstance(x, int):
            finalMessage += x.to_bytes(4, byteorder = "big")
        else:
            # x est un caractère (str)
            charInt = int.from_bytes(x.encode("utf-8"), byteorder="big")
            charByte = charInt.to_bytes(4, byteorder = "big")
            finalMessage += charByte
    return finalMessage

def giveOriginalMessage(convertedMsg):
    res = ""
    conM = convertedMsg
    while conM != b"":
        charB = conM[:4]
        conM = conM[4:]
        a = charB.split(b"\x00")
        num = a[len(a)-1]
        res += num.decode("utf-8")

    return res


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
