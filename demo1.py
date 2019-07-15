# Demo which uses the PyQt5 GUI to form a textbox
from PyQt5.QtWidgets import (QApplication,
                             QMainWindow,
                             QMessageBox,
                             QWidget,
                             QComboBox,
                             QLabel,
                             QDialog,
                             QDialogButtonBox,
                             QVBoxLayout,
                             QErrorMessage,
                             QGridLayout
                             )
from PyQt5.QtCore import Qt, QCoreApplication
import sys
import logging
#import PyRP1210
from PyRP1210.RP1210 import *
from PyRP1210.RP1210Select import *
from PyRP1210.RP1210Functions import *

from PyQt5.QtCore import QCoreApplication


class ExampleGUI(QMainWindow):
    def __init__(self):
        super(ExampleGUI, self).__init__()
        app.aboutToQuit.connect(self.closeEvent)
        self.show()
        selection = SelectRP1210("Select RP1210 Test")
        dll_name = selection.dll_name
        protocol = selection.protocol
        deviceID = selection.deviceID
        speed    = selection.speed

        # Once an RP1210 DLL is selected, we can connect to it using the RP1210 helper file.
        self.RP1210 = RP1210Class(dll_name) 
        client_id = self.RP1210.get_client_id("J1939", deviceID, "{}".format(speed))
        self.CCVS = SimulateJ1939Signal(self.RP1210, client_id, 65265, 3, 100)
        self.data_label = QLabel("CCVS Data")

        self.statusBar().showMessage("Welcome to RP1210Demo")

        self.grid_layout = QGridLayout()
        self.grid_layout.addWidget(self.data_label,0,0,1,1)

        main_widget = QWidget()
        main_widget.setLayout(self.grid_layout)
        self.setCentralWidget(main_widget)

        self.run()
    
    def closeEvent(self, event):
        """
        """
        print("Quitting.")
        app.quit() 
        sys.exit(0)

    def run(self):
        for v in range(256):
            start_time = time.time()
            while time.time() - start_time < 0.10:
                QCoreApplication.processEvents()
                time.sleep(0.001)
            self.CCVS.data[2] = v & 0xFF
            self.data_label.setText("Updated speed to {} kph".format(v))

class SimulateJ1939Signal(QWidget):
    def __init__(self, RP1210, client_id, pgn, sa, update_rate, priority=6, da=0xFF, BAM = True):
        super(SimulateJ1939Signal, self).__init__()
        self.RP1210 = RP1210
        self.client_id = client_id
        self.pgn = pgn
        self.sa = sa
        self.da = da
        self.BAM = BAM
        self.priority = priority
        self.data = [0xFF for i in range(8)]
        
        tx_timer = QTimer(self)
        tx_timer.timeout.connect(self.send_j1939_message)
        tx_timer.start(update_rate) #milliseconds
    
   


    def send_j1939_message(self):
        print("Sent: {} {}: {}".format(self.pgn,self.sa,self.data))
        return
        #initialize the buffer
        pri = self.priority
        b0 =  self.pgn & 0xff
        b1 = (self.pgn & 0xff00) >> 8
        b2 = (self.pgn & 0xff0000) >> 16
        if BAM and len(self.data) > 8:
            self.pri |= 0x80
        message_bytes = bytes([b0, b1, b2, pri, self.sa, self.da])
        message_bytes += bytes(self.data)
        self.RP1210.send_message(self.client_id, message_bytes)
        print("Sent: {:X} {}: {}".format(self.pgn,self.sa, self.data))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    execute = ExampleGUI()
    sys.exit(app.exec_())
