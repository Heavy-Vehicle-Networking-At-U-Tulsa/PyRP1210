# Demo which uses the PyQt5 GUI to form a textbox

import PyRP1210
from PyRP1210.RP1210 import RP1210Class
from PyQt5.QtCore import QCoreApplication


class ExampleGUI(PyRP1210.RP1210.RP1210Class):
    def __init__(self):
        super(ExampleGUI, self).__init__("PyRP1210")


app = QCoreApplication(sys.argv)
execute = ExampleGUI
sys.exit(app.exec_())
