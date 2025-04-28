import random
import hashlib
import os
import math
import socket

def connectSocket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

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

def receptionDecode(type, s, index=-1, sKey=0, vKey="", nKey=0, eKey=0):
    returnRecep = ""
    try:
        if index == 0:
            test = True
            while test:
                header = s.recv(6)
                l = (int.from_bytes(header[-2:], byteorder='big')) * 4
                mType = chr(header[3]).encode("utf-8")
                if mType == type:
                    returnRecep += shiftDecode(s.recv(l), sKey)
                    test = False
                else:
                    s.recv(l)

        elif index == 1:
            test = True
            while test:
                header = s.recv(6)
                l = (int.from_bytes(header[-2:], byteorder='big')) * 4
                mType = chr(header[3]).encode("utf-8")
                if mType == type:
                    returnRecep += vigenereDecode(s.recv(l), vKey)
                    test = False
                else:
                    s.recv(l)

        elif index == 2:
            test = True
            while test:
                header = s.recv(6)
                l = (int.from_bytes(header[-2:], byteorder='big')) * 4
                mType = chr(header[3]).encode("utf-8")
                if mType == type:
                    returnRecep += rsaDecode(s.recv(l), eKey, nKey)
                    test = False
                else:
                    s.recv(l)
    except socket.error as e:
        print(f"Socket error occurred: {e}")

    return returnRecep

def reception(type, s):
    returnRecep = ""
    test = True
    try:
        while test:
            header = s.recv(6)
            l = (int.from_bytes(header[-2:], byteorder='big')) * 4
            mType = chr(header[3]).encode("utf-8")
            if mType == type:
                returnRecep += giveOriginalMessage(s.recv(l))
                test = False
            else:
                s.recv(l)
    except socket.error as e:
        print(f"Socket error occurred: {e}")

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

def shiftDecode(encodedMsg, key):
    decodedMsg = ""
    shift = int(key)

    while encodedMsg:
        charB = encodedMsg[:4]
        encodedMsg = encodedMsg[4:]
        charInt = int.from_bytes(charB, byteorder="big")
        charInt -= shift
        decodedMsg += charInt.to_bytes(4, byteorder="big").lstrip(b"\x00").decode("utf-8")

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

def vigenereDecode(encodedMsg, key):
    decodedMsg = ""
    keyLength = len(key)
    index = 0

    while encodedMsg:
        charB = encodedMsg[:4]
        encodedMsg = encodedMsg[4:]

        c = int.from_bytes(charB, byteorder="big")
        k = int.from_bytes(key[index % keyLength].encode("utf-8"), byteorder="big")
        m = c - k
        decodedMsg += m.to_bytes(4, byteorder="big").lstrip(b"\x00").decode("utf-8")
        index += 1

    return decodedMsg


def generateRSAKeyPair(bits=512):
    # Génère deux grands nombres premiers distincts
    p = generatePrime(bits)
    q = generatePrime(bits)
    while q == p:
        q = generatePrime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    return p, q, n, phi

def generateE(phi):
    e = 65537  # Valeur classique et efficace
    if math.gcd(e, phi) == 1:
        return e

    # Sinon on en cherche un autre
    e = 3
    while math.gcd(e, phi) != 1:
        e += 2  # On saute les pairs

    return e

def rsaEncode(msg, n, e):
    encodedMsg = b""
    for char in msg:
        m = int.from_bytes(char.encode("utf-8"), byteorder="big")
        c = pow(m, e, n)
        encodedMsg += c.to_bytes(4, byteorder="big")
    return encodedMsg

def moduloInv(a, m):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Pas d’inverse modulaire')
    return x % m

def rsaDecode(encodedMsg, d, n):
    decodedMsg = ""
    while encodedMsg:
        charB = encodedMsg[:4]
        encodedMsg = encodedMsg[4:]
        c = int.from_bytes(charB, byteorder="big")
        m = pow(c, d, n)
        decodedMsg += m.to_bytes(4, byteorder="big").lstrip(b"\x00").decode("utf-8")

    return decodedMsg


def hashing(message):
    # Hash un message avec SHA-256 et retourne le hash hexadécimal.
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

def message_en_attente(sock):
    import select
    ready, _, _ = select.select([sock], [], [], 0)
    return bool(ready)

#----------------------------------------------------------------------------------------------------------------------

def sTypeMessage(mT, taskIndex, taskLen, s):# Fonction qui s'occupe des messages de type 's'
    taskMessage = ""
    messageToEncodeDecode = ""
    verdict = ""

    try:
        if taskIndex == 0:
            task = "task shift encode " + str(taskLen)
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = reception(b"s", s)
            taskKey = taskMessage.split("-key ")[1]

            messageToEncodeDecode = reception(b"s", s)

            encodedResult = shiftEncode(messageToEncodeDecode, taskKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            verdict = reception(b"s", s)

        elif taskIndex == 1:
            task = "task vigenere encode " + str(taskLen)
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = reception(b"s", s)
            taskKey = taskMessage.split("-key ")[1]

            messageToEncodeDecode = reception(b"s", s)

            encodedResult = vigenereEncode(messageToEncodeDecode, taskKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            verdict = reception(b"s", s)

        elif taskIndex == 2:
            task = "task RSA encode " + str(taskLen)
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = reception(b"s", s)
            nKey = int(taskMessage.split("=")[1][:-3])
            eKey = int(taskMessage.split("=")[2])

            messageToEncodeDecode = reception(b"s", s)

            encodedResult = rsaEncode(messageToEncodeDecode, nKey, eKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            verdict = reception(b"s", s)

        elif taskIndex == 3:
            task = "task DifHel"
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage += reception(b"s", s)

            prime = generatePrime(10)
            generator = generateGenerator(prime)
            primeAndGen = str(prime) + ", " + str(generator)

            addPrimeAndGen = "prime: " + str(prime) + ", generator: " + str(generator)
            messageToEncodeDecode += addPrimeAndGen
            mess = addMessageHeader(mT) + addMessageSize(len(primeAndGen)) + convertMessage(primeAndGen)
            s.sendall(mess)

            taskMessage += "\n" + reception(b"s", s)
            otherPubKey = int(reception(b"s", s))
            taskMessage += "\n" + "server half-key: " + str(otherPubKey)

            privateKey, publicKey = privAndPubKey(generator, prime)
            messageToEncodeDecode += "\n" + "my half-key: " + str(publicKey)
            mess2 = addMessageHeader(mT) + addMessageSize(len(str(publicKey))) + convertMessage(str(publicKey))
            s.sendall(mess2)

            taskMessage += "\n" + reception(b"s", s)

            sharedKey = secretKey(otherPubKey, privateKey, prime)
            mess3 = addMessageHeader(mT) + addMessageSize(len(str(sharedKey))) + convertMessage(str(sharedKey))
            s.sendall(mess3)
            messageToEncodeDecode += "\n" + "shared key: " + str(sharedKey)
            verdict = reception(b"s", s)

        elif taskIndex == 4:
            task = "task hash hash"
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = reception(b"s", s)
            messageToEncodeDecode = reception(b"s", s)
            hashMess = hashing(messageToEncodeDecode)
            mess = addMessageHeader(mT) + addMessageSize(len(hashMess)) + convertMessage(hashMess)
            s.sendall(mess)
            verdict = reception(b"s", s)

        elif taskIndex == 5:
            task = "task hash verify"
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = reception(b"s", s)
            recMess = reception(b"s", s)
            recHash = reception(b"s", s)
            messageToEncodeDecode = recMess + "\n" + recHash
            myHash = hashing(recMess)
            if myHash == recHash:
                s.sendall(addMessageHeader(mT) + addMessageSize(len("true")) + convertMessage("true"))
                verdict = reception(b"s", s)
            else:
                s.sendall(addMessageHeader(mT) + addMessageSize(len("false")) + convertMessage("false"))
                verdict = reception(b"s", s)
    except socket.error as e:
        print(f"Socket error occurred: {e}")

    return taskMessage, messageToEncodeDecode, verdict


def tTypeMessage(mT, encryptIndex, messToSend, sKey, vKey, nKey, eKey, s):  # Fonction qui s'occupe des messages de type 't'

    try:
        if encryptIndex == 0:
            sEncodedMessage = shiftEncode(messToSend, sKey)
            size = len(sEncodedMessage) // 4
            s.sendall(addMessageHeader(mT) + addMessageSize(size) + sEncodedMessage)

        if encryptIndex == 1:
            if vKey == "":
                size = len(messToSend)
                s.sendall(addMessageHeader(mT) + addMessageSize(size) + convertMessage(messToSend))
            else:
                vEncodedMessage = vigenereEncode(messToSend, vKey)
                size = len(vEncodedMessage) // 4
                s.sendall(addMessageHeader(mT) + addMessageSize(size) + vEncodedMessage)

        if encryptIndex == 2:
            rsaEncodedMessage = rsaEncode(messToSend, nKey, eKey)
            size = len(rsaEncodedMessage) // 4
            s.sendall(addMessageHeader(mT) + addMessageSize(size) + rsaEncodedMessage)
    except socket.error as e:
        print(f"Socket error occurred: {e}")

    return messToSend

#---------------------------------------------------------------------------------------------------------------------
