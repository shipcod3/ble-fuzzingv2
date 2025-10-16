from sys import version_info

import constant
from fuzzing.FuzzingBLESUL import FuzzingBLESUL, FuzzedParam
import time
import random

from FailSafeLearning.Errors import ConnectionError
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from colorama import Fore


class FuzzingBLESULConnectingStart(FuzzingBLESUL):
    """
    Fuzzing interface for the interaction with a BLE peripheral. Commands to the peripheral are sent via a central device. This interface always establishes a connection before the execution of an input sequence.
    """

    def __init__(self, serial_port, advertiser_address):
        super().__init__(serial_port, advertiser_address)
    
    MAX_PHYSICAL_RESET = 10
        
    def pre(self):
        """
        resets the peripheral to the connecting state including a keep alive message to avoid that 
        peripheral enters standby state
        """
        rand_hex_str = hex(random.getrandbits(48))[2:]
        self.master_address = ':'.join(a+b for a,b in zip(rand_hex_str[::2], rand_hex_str[1::2])) 
        self.access_address = int(hex(random.getrandbits(32)),0)
        scan_rsp = self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
        conn_rsp = self.connection_request()
        physical_reset_attempts = 0
        while physical_reset_attempts < self.MAX_PHYSICAL_RESET:
            if scan_rsp == constant.ERROR or conn_rsp == constant.ERROR:
                self.termination_indication()
                scan_rsp = self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
                conn_rsp = self.connection_request()
                physical_reset_attempts += 1
                if scan_rsp != constant.ERROR and conn_rsp != constant.ERROR:
                    break
                else: 
                    if constant.PHYSICAL_RESET:
                        start_interrupt = time.time()
                        input(Fore.RED + "SUL might have crashed. Physical reset the device and press any key to continue...")
                        end_interrupt = time.time()
                        self.waiting_time += end_interrupt - start_interrupt
            else:
                break 
        if physical_reset_attempts >= self.MAX_PHYSICAL_RESET:
            raise ConnectionError()
            



    