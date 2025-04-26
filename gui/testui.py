import sys

from PyQt5.QtWidgets import ( QApplication, QMainWindow )
from PyQt5.uic import loadUi
from PyQt5.QtCore import *

from interface import Ui_MainWindow
import testUIMain
import socket

class MsgHandler(QObject):
    # Signals (need to be Class attributes!)
    newMsgSignal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._isRunning = True
        self.msgCount = 1

    @pyqtSlot(str, int)
    def connectSocket(self, host, port):
        self.socket = testUIMain.connectSocket(host, port)

    @pyqtSlot()
    def run(self):
        self._isRunning = True
        while (self._isRunning):
            message = testUIMain.reception(b"t", self.socket)
            self.newMsgSignal.emit(message)

    def stop(self):
        self._isRunning = False

class Window(QMainWindow, Ui_MainWindow):
    # Signals (need to be Class attributes!)
    msgHandlerConnect = pyqtSignal(str, int)
    startMsgHandler = pyqtSignal()
    stopMsgHandler = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.msgHandler = MsgHandler()
        self.msgHandlerThread = QThread()
        self.connectSignalsSlots()
        self.msgHandler.moveToThread(self.msgHandlerThread)
        self.msgHandlerThread.start()

        host = "vlbelintrocrypto.hevs.ch"  # Le nom du serveur
        port = 6000  # Le numéro de port du serveur
        self.socket = testUIMain.connectSocket(host, port)
        self.msgHandlerConnect.emit(host, port)
        self.startMsgHandler.emit()

    def closeEvent(self, a0):
        self.stopMsgHandler.emit()
        self.msgHandlerThread.quit()
        self.msgHandlerThread.wait()
        return super().closeEvent(a0)

# Actions ---> EDIT HERE
    def connectSignalsSlots(self):
        self.StartTaskButton.pressed.connect(self.StartButtonPressed)
        self.messageInput.returnPressed.connect(self.SendMessage)
        self.TaskSelector.currentIndexChanged.connect(self.selectionChangedTask)
        self.ServerConnectButton.pressed.connect(self.SocketReconnect)
        self.msgHandler.newMsgSignal.connect(self.newRcvMessage)
        self.msgHandlerConnect.connect(self.msgHandler.connectSocket)
        self.startMsgHandler.connect(self.msgHandler.run)
        self.stopMsgHandler.connect(self.msgHandler.stop)

    def newRcvMessage(self, msg):
        msgReceived = "<span style='color:blue'>[Received] </span>" + msg
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

    def SendMessage(self):
        try:
            # Get message and encryption parameters
            message = self.messageInput.text()
            if not message:
                return

            # Get encryption parameters
            EncryptionType = self.EncryptionSelector.currentIndex()
            ShiftKey = str(self.shiftKeyBox.value())
            VigenereKey = self.vigKeyBox.text()
            nKeyRSA = self.nKeyBox.value()
            eKeyRSA = self.eKeyBox.value()

            # Encrypt the message based on selected method
            if EncryptionType == 0:  # Shift
                encoded = testUIMain.shiftEncode(message, ShiftKey)
            elif EncryptionType == 1:  # Vigenere
                encoded = testUIMain.vigenereEncode(message, VigenereKey)
            elif EncryptionType == 2:  # RSA
                encoded = testUIMain.rsaEncode(message, nKeyRSA, eKeyRSA)
            else:  # Plain text
                encoded = testUIMain.convertMessage(message)

            # Create protocol-compliant message
            header = testUIMain.addMessageHeader("t")
            msg_size = len(encoded) // 4  # Each character is 4 bytes
            size_bytes = testUIMain.addMessageSize(msg_size)
            full_message = header + size_bytes + encoded

            # Send the message
            self.socket.sendall(full_message)

            # Update UI
            messToSend = f"<span style='color:green'>[You] </span>{message}"
            self.ChatMessageField.append(messToSend)
            self.messageInput.clear()

        except Exception as e:
            print(f"Error sending message: {str(e)}")
            self.ChatMessageField.append(f"<span style='color:red'>[Error] Failed to send message</span>")

    def SocketReconnect(self):
        port = self.PortBox.value()
        host = "vlbelintrocrypto.hevs.ch"
        self.socket.close()
        self.messageInput.clear()
        self.ChatMessageField.clear()
        self.socket = testUIMain.connectSocket(host, port)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec())

