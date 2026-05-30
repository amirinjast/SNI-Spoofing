import sys
from abc import ABC, abstractmethod

from pydivert import Packet, WinDivert


class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        self.filter = w_filter
        self.w: WinDivert = WinDivert(w_filter)

    @abstractmethod
    def inject(self, packet: Packet):
        sys.exit("Not implemented")

    def run(self):
        try:
            with self.w:
                print("WinDivert capture started.")
                while True:
                    packet = self.w.recv(65575)
                    self.inject(packet)
        except PermissionError:
            print("\nERROR: WinDivert could not start: access denied.")
            print("Run PowerShell or CMD as Administrator, then run `python main.py` again.")
            print("Without Administrator privileges, capture-only and wrong_seq diagnostics cannot observe packets.")
            print(f"WinDivert filter: {self.filter}\n")
        except OSError as exc:
            print("\nERROR: WinDivert could not start or stopped unexpectedly.")
            print(f"Reason: {exc!r}")
            print("Check that WinDivert is allowed by Windows Security/antivirus and that no conflicting driver is blocking it.")
            print(f"WinDivert filter: {self.filter}\n")
