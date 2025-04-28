import sys

from PyQt5.QtWidgets import ( QApplication, QMainWindow )
from PyQt5.uic import loadUi
from PyQt5.QtCore import *

from interface import Ui_MainWindow
import testUIMain
import socket

class MsgHandler(QObject):
    # Signals (need to be Class attributes!)
    newMsgSignal = pyqtSignal(object)

    @pyqtSlot(socket.socket)
    def run(self, socket):
        self.socket = socket
        test = True
        while test:
            if (self.socket != None):
                encodedMessage = testUIMain.reception(b"t", self.socket)

                if encodedMessage:
                    self.newMsgSignal.emit(encodedMessage)
                else:
                    test = False

class Window(QMainWindow, Ui_MainWindow):
    # Signals (need to be Class attributes!)
    startMsgHandlerSignal = pyqtSignal(socket.socket)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.msgHandler = MsgHandler()
        self.msgHandlerThread = QThread()
        self.connectSignalsSlots()
        self.msgHandler.moveToThread(self.msgHandlerThread)
        self.msgHandlerThread.start()
        self.setupDecodeParameters()
        self.mySentMessages = []

        host = "vlbelintrocrypto.hevs.ch"  # Le nom du serveur
        port = 6000  # Le numéro de port du serveur
        self.startMsgHandler(host, port)

    def closeEvent(self, a0):
        self.stopMsgHandler()
        self.msgHandlerThread.quit()
        self.msgHandlerThread.wait()
        return super().closeEvent(a0)

# Actions ---> EDIT HERE
    def connectSignalsSlots(self):
        # GUI signals
        self.StartTaskButton.pressed.connect(self.StartButtonPressed)
        self.EncryptionSelector.currentIndexChanged.connect(self.onPageChanged)
        self.rsaKeysButton.pressed.connect(self.RsaGenerateButton)
        self.DHStartButton.pressed.connect(self.DifHelStartButton)
        self.DHKeysCalculator.pressed.connect(self.DifHelKeysCalculator)
        self.DHSharedKeyCalculator.pressed.connect(self.DifHelSharedKeyCalculator)
        self.messageInput.returnPressed.connect(self.SendMessage)
        self.TaskSelector.currentIndexChanged.connect(self.selectionChangedTask)
        self.EncryptionSelector.currentIndexChanged.connect(self.setupDecodeParameters)
        self.shiftKeyBox.valueChanged.connect(self.setupDecodeParameters)
        self.vigKeyBox.textChanged.connect(self.setupDecodeParameters)
        self.nKeyBox.valueChanged.connect(self.setupDecodeParameters)
        self.eKeyBox.valueChanged.connect(self.setupDecodeParameters)
        self.dKeyBox.valueChanged.connect(self.setupDecodeParameters)
        # Thread signals
        self.startMsgHandlerSignal.connect(self.msgHandler.run)
        self.msgHandler.newMsgSignal.connect(self.newRcvMessage)

    def onPageChanged(self, index):
        self.stackedWidget.setCurrentIndex(index)
        self.stackedWidget.adjustSize()

    def setupDecodeParameters(self):
        self.EncryptionType = self.EncryptionSelector.currentIndex()
        self.ShiftKey = str(self.shiftKeyBox.value())
        self.VigenereKey = self.vigKeyBox.text()
        self.nKeyRSA = self.nKeyBox.value()
        self.eKeyRSA = self.eKeyBox.value()
        self.dKeyRSA = self.dKeyBox.value()

    def newRcvMessage(self, msg):
        if msg in self.mySentMessages:
            self.mySentMessages.remove(msg)
        else:
            decodedMessage = testUIMain.decode(msg, self.EncryptionType, self.ShiftKey, self.VigenereKey,
                                               self.nKeyRSA, self.dKeyRSA)
            msgReceived = "<span style='color:blue'>[Received] </span>" + decodedMessage
            self.ChatMessageField.append(msgReceived)

    def selectionChangedTask(self, index):
        self.EncodeMessageField.clear()
        self.TaskMessageField.clear()
        self.VerdictField.clear()

        if index == 3:
            self.label_2.setText("Server Messages")
            self.label_3.setText("My Messages")
        else:
            self.label_2.setText("Task Message")
            self.label_3.setText("Message to encode")

    def StartButtonPressed(self):
        optionEncryption = self.TaskSelector.currentIndex()
        charNum = self.MessageLength.value()
        firstField, secondField, thirdField = testUIMain.sTypeMessage("s", optionEncryption, charNum, self.socket)
        self.TaskMessageField.setPlainText(firstField)
        self.EncodeMessageField.setPlainText(secondField)
        self.VerdictField.setPlainText(thirdField)

    def RsaGenerateButton(self):
        p, q, n, phi = testUIMain.generateRSAKeyPair(10)
        e = testUIMain.generateE(phi)
        d = testUIMain.moduloInv(e, phi)
        self.nKeyBox.setValue(n)
        self.eKeyBox.setValue(e)
        self.dKeyBox.setValue(d)

    def DifHelStartButton(self):
        prime = testUIMain.generatePrime(10)
        generator = testUIMain.generateGenerator(prime)
        self.DHPrime.setText(str(prime))
        self.DHGenerator.setText(str(generator))

    def DifHelKeysCalculator(self):
        prime = self.DHPrime.text()
        generator = self.DHGenerator.text()
        privateKey, myHalfKey = testUIMain.privAndPubKey(int(generator), int(prime))
        self.DHPrivKey.setText(str(privateKey))
        self.DHMyHKey.setText(str(myHalfKey))

    def DifHelSharedKeyCalculator(self):
        otherHalfKey = self.DHOtherHKey.text()
        prime = self.DHPrime.text()
        privateKey = self.DHPrivKey.text()
        sharedKey = testUIMain.secretKey(int(otherHalfKey), int(privateKey), int(prime))
        self.DHSharedKey.setText(str(sharedKey))

    mySentMessages = []

    def SendMessage(self):
        message = self.messageInput.text()
        EncryptionType = self.EncryptionSelector.currentIndex()
        ShiftKey = str(self.shiftKeyBox.value())
        VigenereKey = self.vigKeyBox.text()
        receiverNKeyRSA = self.receiverNKeyBox.value()
        receiverEKeyRSA = self.receiverEKeyBox.value()
        mess = testUIMain.tTypeMessage("t", EncryptionType, message, ShiftKey, VigenereKey, receiverNKeyRSA, receiverEKeyRSA, self.socket)
        self.mySentMessages.append(mess)
        messToSend = "<span style='color:green'>[You] </span>" + self.messageInput.text()
        self.ChatMessageField.append(messToSend)
        self.messageInput.clear()

    def stopMsgHandler(self):
        self.socket.close()

    def socketReconnect(self):
        self.messageInput.clear()
        self.ChatMessageField.clear()
        self.stopMsgHandler()
        port = self.PortBox.value()
        host = "vlbelintrocrypto.hevs.ch"
        self.startMsgHandler(host, port)
        print("Message Handler Restarted")

    def startMsgHandler(self, host, port):
        self.socket = testUIMain.connectSocket(host, port)
        self.startMsgHandlerSignal.emit(self.socket)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec())

