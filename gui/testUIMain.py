import random
import hashlib
import os
import math
import socket
import time

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

def reception(type, s):
    returnRecep = b""
    test = True
    try:
        while test:
            header = s.recv(6)
            if header:
                l = (int.from_bytes(header[-2:], byteorder='big')) * 4
                mType = chr(header[3]).encode("utf-8")
                if mType == type:
                    x = s.recv(l)
                    print(x)
                    returnRecep += x
                    test = False
                else:
                    s.recv(l)
            else:
                test = False
    except socket.error as e:
        print(f"Socket error occurred: {e}")

    return returnRecep

def receptionString(type, s):
    returnRecep = ""
    test = True
    try:
        while test:
            header = s.recv(6)
            l = (int.from_bytes(header[-2:], byteorder='big')) * 4
            mType = chr(header[3]).encode("utf-8")
            if mType == type:
                x = s.recv(l)
                print(x)
                returnRecep += giveOriginalMessage(x)
                test = False
            else:
                s.recv(l)
    except socket.error as e:
        print(f"Socket error occurred: {e}")

    return returnRecep

def shiftEncode(msg, key):
    encodedMsg = b""
    shift = int(key)

    for char in msg:
        charByte = char.encode("utf-8")
        charInt = int.from_bytes(charByte, byteorder="big")
        charInt += shift
        encodedByte = charInt.to_bytes(4, byteorder="big")
        encodedMsg += encodedByte

    return encodedMsg

def shiftDecode(encodedMsg, key):
    decodedMsg = ""
    shift = int(key)

    for i in range(0, len(encodedMsg), 4):
        charInt = int.from_bytes(encodedMsg[i:i + 4], byteorder="big")
        charInt -= shift
        decodedByte = charInt.to_bytes(4, byteorder="big")
        decodedMsg += decodedByte.lstrip(b"\x00").decode("utf-8")

    return decodedMsg


def vigenereEncode(msg, key):
    encodedMsg = b""
    keyLength = len(key)
    index = 0

    for char in msg:
        charByte = char.encode("utf-8")
        charInt = int.from_bytes(charByte, byteorder="big")
        k = int.from_bytes(key[index % keyLength].encode("utf-8"), byteorder="big")
        c = charInt + k
        encodedMsg += c.to_bytes(4, byteorder="big")
        index += 1

    return encodedMsg

def vigenereDecode(encodedMsg, key):
    decodedMsg = ""
    keyLength = len(key)
    index = 0

    for i in range(0, len(encodedMsg), 4):
        charInt = int.from_bytes(encodedMsg[i:i + 4], byteorder="big")
        k = int.from_bytes(key[index % keyLength].encode("utf-8"), byteorder="big")
        m = charInt - k
        decodedByte = m.to_bytes(4, byteorder="big")
        decodedMsg += decodedByte.lstrip(b"\x00").decode("utf-8")
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
        charByte = char.encode("utf-8")
        charInt = int.from_bytes(charByte, byteorder="big")
        c = pow(charInt, e, n)
        encodedMsg += c.to_bytes(4, byteorder="big")
    return encodedMsg

def moduloInv(e, phi):
    def egcd(e, b):
        if e == 0:
            return b, 0, 1
        g, y, x = egcd(b % e, e)
        return g, x - (b // e) * y, y

    g, x, _ = egcd(e, phi)
    if g != 1:
        raise Exception('Pas d’inverse modulaire')
    return x % phi

def rsaDecode(encodedMsg, d, n):
    decodedMsg = ""
    for i in range(0, len(encodedMsg), 4):
        charInt = int.from_bytes(encodedMsg[i:i + 4], byteorder="big")
        m = pow(charInt, d, n)
        decodedByte = m.to_bytes(4, byteorder="big")
        decodedMsg += decodedByte.lstrip(b"\x00").decode("utf-8")

    return decodedMsg

def decode(messToDecode, index, sKey, vKey, nKey, dKey):
    res = ""
    if index == 0:
        res = shiftDecode(messToDecode, sKey)
    elif index == 1:
        res = vigenereDecode(messToDecode, vKey)
    elif index == 2:
        res = rsaDecode(messToDecode, dKey, nKey)
    elif index == 3:
        res = shiftDecode(messToDecode, 0)

    return res


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
            print(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            time.sleep(0.1)

            taskMessage = giveOriginalMessage(reception(b"s", s))
            print(taskMessage)
            taskKey = taskMessage.split("-key ")[1]

            messageToEncodeDecode = giveOriginalMessage(reception(b"s", s))

            encodedResult = shiftEncode(messageToEncodeDecode, taskKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            verdict = giveOriginalMessage(reception(b"s", s))

        elif taskIndex == 1:
            task = "task vigenere encode " + str(taskLen)
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = giveOriginalMessage(reception(b"s", s))
            taskKey = taskMessage.split("-key ")[1]

            messageToEncodeDecode = giveOriginalMessage(reception(b"s", s))

            encodedResult = vigenereEncode(messageToEncodeDecode, taskKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            verdict = giveOriginalMessage(reception(b"s", s))

        elif taskIndex == 2:
            task = "task RSA encode " + str(taskLen)
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = giveOriginalMessage(reception(b"s", s))
            nKey = int(taskMessage.split("=")[1][:-3])
            eKey = int(taskMessage.split("=")[2])

            messageToEncodeDecode = giveOriginalMessage(reception(b"s", s))

            encodedResult = rsaEncode(messageToEncodeDecode, nKey, eKey)
            size = len(encodedResult) // 4
            mess = addMessageHeader(mT) + addMessageSize(size) + encodedResult
            s.sendall(mess)
            verdict = giveOriginalMessage(reception(b"s", s))

        elif taskIndex == 3:
            task = "task DifHel"
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage += giveOriginalMessage(reception(b"s", s))

            prime = generatePrime(10)
            generator = generateGenerator(prime)
            primeAndGen = str(prime) + ", " + str(generator)

            addPrimeAndGen = "prime: " + str(prime) + ", generator: " + str(generator)
            messageToEncodeDecode += addPrimeAndGen
            mess = addMessageHeader(mT) + addMessageSize(len(primeAndGen)) + convertMessage(primeAndGen)
            s.sendall(mess)

            taskMessage += "\n" + giveOriginalMessage(reception(b"s", s))
            otherPubKey = int(giveOriginalMessage(reception(b"s", s)))
            taskMessage += "\n" + "server half-key: " + str(otherPubKey)

            privateKey, publicKey = privAndPubKey(generator, prime)
            messageToEncodeDecode += "\n" + "my half-key: " + str(publicKey)
            mess2 = addMessageHeader(mT) + addMessageSize(len(str(publicKey))) + convertMessage(str(publicKey))
            s.sendall(mess2)

            taskMessage += "\n" + giveOriginalMessage(reception(b"s", s))

            sharedKey = secretKey(otherPubKey, privateKey, prime)
            mess3 = addMessageHeader(mT) + addMessageSize(len(str(sharedKey))) + convertMessage(str(sharedKey))
            s.sendall(mess3)
            messageToEncodeDecode += "\n" + "shared key: " + str(sharedKey)
            verdict = giveOriginalMessage(reception(b"s", s))

        elif taskIndex == 4:
            task = "task hash hash"
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = giveOriginalMessage(reception(b"s", s))
            messageToEncodeDecode = giveOriginalMessage(reception(b"s", s))
            hashMess = hashing(messageToEncodeDecode)
            mess = addMessageHeader(mT) + addMessageSize(len(hashMess)) + convertMessage(hashMess)
            s.sendall(mess)
            verdict = giveOriginalMessage(reception(b"s", s))

        elif taskIndex == 5:
            task = "task hash verify"
            taskSize = len(task)
            s.sendall(addMessageHeader(mT) + addMessageSize(taskSize) + convertMessage(task))

            taskMessage = giveOriginalMessage(reception(b"s", s))
            recMess = giveOriginalMessage(reception(b"s", s))
            recHash = giveOriginalMessage(reception(b"s", s))
            messageToEncodeDecode = recMess + "\n" + recHash
            myHash = hashing(recMess)
            if myHash == recHash:
                s.sendall(addMessageHeader(mT) + addMessageSize(len("true")) + convertMessage("true"))
                verdict = giveOriginalMessage(reception(b"s", s))
            else:
                s.sendall(addMessageHeader(mT) + addMessageSize(len("false")) + convertMessage("false"))
                verdict = giveOriginalMessage(reception(b"s", s))
    except socket.error as e:
        print(f"Socket error occurred: {e}")

    return taskMessage, messageToEncodeDecode, verdict


def tTypeMessage(mT, encryptIndex, messToSend, sKey, vKey, nKey, eKey, s):  # Fonction qui s'occupe des messages de type 't'
    mess = messToSend
    try:
        if encryptIndex == 0:
            mess = shiftEncode(messToSend, sKey)
            size = len(mess) // 4
            s.sendall(addMessageHeader(mT) + addMessageSize(size) + mess)

        elif encryptIndex == 1:
            if vKey == "":
                size = len(mess)
                s.sendall(addMessageHeader(mT) + addMessageSize(size) + convertMessage(mess))
            else:
                mess = vigenereEncode(messToSend, vKey)
                size = len(mess) // 4
                s.sendall(addMessageHeader(mT) + addMessageSize(size) + mess)

        elif encryptIndex == 2:
            mess = rsaEncode(messToSend, nKey, eKey)
            size = len(mess) // 4
            s.sendall(addMessageHeader(mT) + addMessageSize(size) + mess)

        elif encryptIndex == 3:
            mess = shiftEncode(messToSend, 0)
            size = len(mess) // 4
            s.sendall(addMessageHeader(mT) + addMessageSize(size) + mess)


    except socket.error as e:
        print(f"Socket error occurred: {e}")

    return mess


#---------------------------------------------------------------------------------------------------------------------
