from PyQt5.QtWidgets import QApplication, QWidget, QTextEdit, QGridLayout, QLabel, QGroupBox, QVBoxLayout, QLineEdit, QRadioButton, QHBoxLayout, QPushButton
from PyQt5.QtCore import Qt
from aesCrypto import AESCipher
from textparser import TextParser
from PyQt5.QtGui import QIcon
import sys

class AESCryptoGui(QWidget):
    textParser = TextParser()
    def __init__(self):
        super().__init__()
        self.initUI()
    def initUI(self):
        self.setGeometry(100, 50, 1000, 800)
        self.setWindowTitle('AESCryptoGui')
        self.setGuiLayout()
        self.show()
    def setGuiLayout(self):
        gridLayout = QGridLayout()
        gridLayout.setSpacing(10)
        descriptionLabels = ['Base64', 'Base64url', 'Hex', 'Java Bytearray', 'Python Bytes', 'Plaintext']
        titlePlaintext = QLabel('Plaintext')
        titleCiphertext = QLabel('CipherText')
        self.textEditPlaintextArray = [QTextEdit() for i in range(6)]
        self.textEditCiphertextArray = [QTextEdit() for i in range(6)]

        settingsBox = self.initSettingsGroupBox()
        decryptButton = QPushButton('Decrypt')
        encryptButton = QPushButton('Encrypt')
        encryptButton.clicked.connect(self.encryptAction)
        decryptButton.clicked.connect(self.decryptAction)


        gridLayout.addWidget(settingsBox, 0, 0, 1, 4)
        gridLayout.addWidget(titlePlaintext, 1, 1, Qt.AlignTop | Qt.AlignHCenter)
        gridLayout.addWidget(titleCiphertext, 1, 3, Qt.AlignTop | Qt.AlignHCenter)
        for pt, ct, i, lbl in zip(self.textEditPlaintextArray, self.textEditCiphertextArray, range(2, len(self.textEditPlaintextArray)+2), descriptionLabels):
            gridLayout.addWidget(QLabel(lbl), i+1, 0)
            pt.textMode = lbl
            ct.textMode = lbl
            gridLayout.addWidget(pt, i+1, 1)
            gridLayout.addWidget(QLabel(lbl), i+1, 2)
            gridLayout.addWidget(ct, i+1, 3)

        gridLayout.addWidget(encryptButton, gridLayout.rowCount(), 0, 1, 2)
        gridLayout.addWidget(decryptButton, gridLayout.rowCount()-1, 2, 1, 2)
        self.setLayout(gridLayout)
    def initSettingsGroupBox(self):
        settingsBox = QGroupBox('Settings')
        settingsLayout = QVBoxLayout()
        settingsBox.setLayout(settingsLayout)
        settingsLabel = ['Key', 'IV', 'Nonce', 'Tag']
        modes = ['ECB', 'CBC', 'CTR', 'GCM', 'CCM']
        radioButtonsSettings = self.initRadioButtons(modes, 'CipherModes', self.checkCipherMode)
        self.keyLine = QLineEdit()
        self.ivLine = QLineEdit()
        self.ivLine.setEnabled(False)
        self.nonceLine = QLineEdit()
        self.nonceLine.setEnabled(False)
        self.tagLine = QLineEdit()
        self.tagLine.setEnabled(False)
        linesSettings = [self.keyLine, self.ivLine, self.nonceLine, self.tagLine]
        descriptionLabels = ['Base64', 'Base64url', 'Hex', 'Java Bytearray', 'Python Bytes', 'Plaintext']
        cipherModesWidget = QWidget()
        cipherModesWidget.setLayout(QHBoxLayout())
        for radiobutton in radioButtonsSettings:
            cipherModesWidget.layout().addWidget(radiobutton)
        settingsLayout.addWidget(cipherModesWidget)
        self.textModes = []
        for lbl, wdgt, i in zip(settingsLabel, linesSettings, range(len(settingsLabel))):
            settingsLayout.addWidget(QLabel(lbl))
            # if lbl != 'Key':
            #     settingsLayout.itemAt(3*i).widget().setEnabled()
            settingsLayout.addWidget(QWidget())
            settingsLayout.itemAt(2 + 3 * i).widget().setLayout(QHBoxLayout())
            # self.initRadioButtons(descriptionLabels, 'TextMode')
            self.textModes.append(self.initRadioButtons(descriptionLabels, 'TextMode'))
            for textRadioButton in self.textModes[-1]:
                if lbl != 'Key':
                    textRadioButton.setEnabled(False)
                settingsLayout.itemAt(2 + 3 * i).widget().layout().addWidget(textRadioButton)
            settingsLayout.addWidget(wdgt)
        return settingsBox
    def initRadioButtons(self, names, mode, toggleAction = None):
        radioButtons = []

        for i in names:
            radioButtons.append(QRadioButton(i))
            radioButtons[-1].mode = mode
            radioButtons[-1].name = i
            if toggleAction != None:
                radioButtons[-1].toggled.connect(toggleAction)
        return radioButtons



    def checkCipherMode(self):
        radiobutton = self.sender()
        if radiobutton.name == 'ECB':
            self.ivLine.setEnabled(False)
            self.nonceLine.setEnabled(False)
            self.tagLine.setEnabled(False)
            self.setTextModeDisabled()

        elif radiobutton.name == 'CBC':
            self.ivLine.setEnabled(True)
            self.nonceLine.setEnabled(False)
            self.tagLine.setEnabled(False)
            self.setTextModeDisabled()
            for i in self.textModes[1]:
                i.setEnabled(True)


        elif radiobutton.name == 'CTR':
            self.ivLine.setEnabled(False)
            self.nonceLine.setEnabled(True)
            self.tagLine.setEnabled(False)
            self.setTextModeDisabled()
            for i in self.textModes[2]:
                i.setEnabled(True)

        elif radiobutton.name == 'GCM':
            self.ivLine.setEnabled(True)
            self.nonceLine.setEnabled(False)
            self.tagLine.setEnabled(True)
            self.setTextModeDisabled()
            for i in self.textModes[1]:
                i.setEnabled(True)
            for i in self.textModes[3]:
                i.setEnabled(True)
        elif radiobutton.name == 'CCM':
            self.ivLine.setEnabled(False)
            self.nonceLine.setEnabled(False)
            self.tagLine.setEnabled(True)
            self.setTextModeDisabled()
            for i in self.textModes[3]:
                i.setEnabled(True)


        self.cipherMode = radiobutton.name

    def setTextModeDisabled(self):
        for textModeButtons in self.textModes[1:]:
            for textMode in textModeButtons:
                textMode.setEnabled(False)

    def checkTextModeToggle(self, radiobuttons):
        print('checkTextMode')
        for i in radiobuttons:
            if i.isChecked():
                return i.text()
    def encryptAction(self):
        key = self.preparsingTextMode(self.keyLine)
        if key != None:
            for i in self.textEditPlaintextArray:
                if i.toPlainText() != '':
                    if self.cipherMode == 'ECB':
                        # read only key
                        cipher = AESCipher(key, self.cipherMode)
                        pass
                    elif self.cipherMode == 'CBC':
                        # key and iv
                        iv = self.preparsingTextMode(self.ivLine)
                        if iv != None:
                            cipher = AESCipher(key, self.cipherMode, iv = iv)
                    elif self.cipherMode == 'CTR':
                        nonce = self.preparsingTextMode(self.nonceLine)
                        if nonce != None:
                            cipher = AESCipher(key, self.cipherMode, nonce = nonce)
                        # key and nonce
                    elif self.cipherMode == 'GCM':
                        iv = self.preparsingTextMode(self.ivLine)
                        if iv != None:
                            cipher = AESCipher(key, self.cipherMode, iv = iv)
                        # key, iv and tag
                        pass
                    elif self.cipherMode == 'CCM':
                        tag = self.preparsingTextMode(self.tagLine)
                        if tag != None:
                            cipher = AESCipher(key, self.cipherMode, tag = tag)
                        # key and tag
                        pass
                    text = i.toPlainText()
                    text = self.textParser.parse(text, 'Plaintext')
                    print(i.toPlainText())
                    ciphertext = cipher.encrypt(text)
                    print(ciphertext)
                    # cipher = AESCipher()
                    print(self.cipherMode)
                    encryptedTexts = self.textParser.convert(ciphertext)
                    for textEdit, ciphertext in zip(self.textEditCiphertextArray, encryptedTexts):
                        print(textEdit, ciphertext)
                        textEdit.setPlainText(ciphertext)

    def decryptAction(self):
        # try:
            key = self.preparsingTextMode(self.keyLine)
            if key != None:
                for i in self.textEditCiphertextArray:
                    if i.toPlainText() != '':
                        if self.cipherMode == 'ECB':
                            # read only key
                            cipher = AESCipher(key, self.cipherMode)
                            pass
                        elif self.cipherMode == 'CBC':
                            # key and iv
                            iv = self.preparsingTextMode(self.ivLine, 1)
                            if iv != None:
                                cipher = AESCipher(key, self.cipherMode, iv=iv)
                        elif self.cipherMode == 'CTR':
                            nonce = self.preparsingTextMode(self.nonceLine, 2)
                            if nonce != None:
                                cipher = AESCipher(key, self.cipherMode, nonce=nonce)
                            # key and nonce
                        elif self.cipherMode == 'GCM':
                            iv = self.preparsingTextMode(self.ivLine, 1)
                            tag = self.preparsingTextMode(self.tagLine, 3)
                            if iv != None and tag != None:
                                cipher = AESCipher(key, self.cipherMode, iv=iv, tag=tag)

                            # key, iv and tag
                            pass
                        elif self.cipherMode == 'CCM':
                            tag = self.preparsingTextMode(self.tagLine, 3)
                            if tag != None:
                                cipher = AESCipher(key, self.cipherMode, tag=tag)
                            # key and tag
                            pass
                        text = i.toPlainText()
                        text = self.textParser.parse(text, i.textMode)
                        print(i.toPlainText())
                        plaintext = cipher.decrypt(text)
                        print('Plaintext', plaintext)
                        # cipher = AESCipher()
                        print(self.cipherMode)
                        decryptedTexts = self.textParser.convert(plaintext)
                        for textEdit, ciphertext in zip(self.textEditPlaintextArray, decryptedTexts):
                            print(textEdit, ciphertext)
                            textEdit.setPlainText(ciphertext)
                        break
        # except Exception as e:
        #     print(e)
    def preparsingTextMode(self, textLine, textModeIndex = 0):
        if textLine.text() != '':
            text = textLine.text()
            keyTextMode = self.checkTextModeToggle(self.textModes[textModeIndex])
            return self.textParser.parse(text, keyTextMode)


def main():
    app = QApplication(["MyApplication"])
    appGui = AESCryptoGui()
    sys.exit(app.exec_())
    pass

if __name__ == '__main__':
    main()