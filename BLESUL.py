import constant
import colorama
import random
from time import sleep
from colorama import Fore
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *

from FailSafeLearning.FailSafeSUL import FailSafeSUL
from FailSafeLearning.Errors import ConnectionError
from FailSafeLearning.FailSafeSUL import FailSafeSUL
from BLEAdapter.NRF52_Driver import NRF52



class BLESUL(FailSafeSUL):
    """
    Interface for the interaction with a BLE peripheral. Commands to the peripheral are sent via a central device.
    """
    EMPTY = 'Empty'
    
    def __init__(self, serial_port, advertiser_address):
        super().__init__()
        self.driver = NRF52(serial_port, debug=False, logs_pcap=constant.LOG_PCAP)
        self.slave_addr_type = 0
        rand_hex_str = hex(random.getrandbits(48))[2:]
        self.master_address = ':'.join(a+b for a,b in zip(rand_hex_str[::2], rand_hex_str[1::2]))
        self.access_address = int(hex(random.getrandbits(32)),0) 
        self.advertiser_address = advertiser_address
        self.connection_error_counter = 0
        colorama.init(autoreset=True)
    
    def scan_request(self):
        """performs a scan request with general response attempts"""
        # 'faster' learning parameter setup
        return self.scan_req(min_attempts=constant.MIN_ATTEMPTS, max_attempts=constant.MAX_ATTEMPTS)

    def scan_req(self, min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS):
        """
        sends a scan request and tries to receive a response

        Args:
            min_attempts: minimum number of attempts to receive a response
            max_attempts: maximum number of attempts to receive a response

        Returns: 
            'Adv' if a valid scan response was received or an error, if no 
            response was received
        """
        self.encrypted = False
        scan_req = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=self.master_address,
        AdvA=self.advertiser_address)
        self.driver.send(scan_req)
        pkt = None
        received_data = set()
        attempt = 0
        while len(received_data) == 0 and attempt < min_attempts or (len(received_data) == 0 and attempt < max_attempts):
            # Receive packet from the NRF52 Dongle
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                if pkt is not None and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and hasattr(pkt, 'AdvA') and hasattr(pkt.AdvA, 'upper') and self.advertiser_address.upper() == pkt.AdvA.upper():
                    self.slave_addr_type = pkt.TxAdd
                    summary = pkt.summary()
                    print(Fore.MAGENTA + "RX <--- " + summary)
                    received_data.update(summary.split(" / "))
            attempt = attempt + 1
            sleep(0.01)
        
        if len(received_data) > 0:
            return "Adv"
        else:
            return constant.ERROR
    
    def contains_more_data(self, received_data): 
        """
        method to check if received data contains any package and more  
        packages than BTLE_DATA

        Args:
            received_data: received data from the peripheral

        Returns: 
            True if a package that contains more than BTLE_DATA has been received, otherwise False
        """
        base_data = {"BTLE", "BTLE_DATA"}
        return len(received_data) > 0 and (base_data != received_data)

    def send_pkt(self, pkt):
        """
        sends a packet via the dongle

        Args: 
            btle packet
        """
        self.driver.send(pkt)
    
    def receive_data(self, min_attempts=constant.MIN_ATTEMPTS, max_attempts=constant.MAX_ATTEMPTS):
        """
        Central receives data from peripheral. The attempts to receive data 
        is repeated at least min_attempts, but at maximum max_attempts

        Args:
            min_attempts: minimum number of attempts to receive a response
            max_attempts: maximum number of attempts to receive a response

        Returns: 
            set of received packages in alphabetical order, if no packages is 
            received empty is returned
        """
        pkt = None
        attempts = 0
        received_data = set()
        while attempts < min_attempts or (not self.contains_more_data(received_data) and attempts < max_attempts):
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                if pkt is not None:
                    if BTLE_DATA in pkt:
                        summary = pkt.summary()
                        print(Fore.MAGENTA + "RX <--- " + summary)
                        received_data.update(summary.split(" / "))
            attempts = attempts + 1
            sleep(0.01)
        return "|".join(sorted(received_data)) if len(received_data) > 0 else self.EMPTY

    def connection_request_pkt(self):
        """
        creates a valid connection request

        Returns: 
            connection request packet
        """
        return BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.advertiser_address,
            AA=self.access_address,  # Access address (any)
            crc_init=0x179a9c,  # CRC init (any)
            win_size=2,  # 2.5 of windows size (anchor connection window size)
            win_offset=1,  # 1.25ms windows offset (anchor connection point)
            interval=16,  # 20ms connection interval
            latency=0,  # Slave latency (any)
            timeout=50,  # Supervision timeout, 500ms (any)
            chM=0x1FFFFFFFFF,  # Any
            hop=5,  # Hop increment (any)
            SCA=0,  # Clock tolerance
        )

    def connection_request(self):
        """
        sends a connection request and tries to receive a response

        Returns: 
            received response or an error, if no response was received
        """
        conn_request = self.connection_request_pkt()
        self.driver.send(conn_request)
        received_data = self.receive_data(min_attempts=constant.CONNECT_MIN_ATTEMPTS, max_attempts=constant.CONNECT_MAX_ATTEMPTS)
        if received_data == self.EMPTY:
            return constant.ERROR
        else:
            return received_data

    def length_request_pkt(self):
        """
        creates a valid length request packet

        Returns: 
            length request packet
        """
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_REQ(max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
    
    def length_request(self):
        """
        sends a length request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        length_req = self.length_request_pkt()
        self.send_pkt(length_req)
        return self.receive_data()

    def length_response_pkt(self):
        """
        creates a valid length response packet

        Returns: 
            length response packet
        """
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_RSP(max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)

    def length_response(self):
        """
        sends a length response and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        length_rsp = self.length_response_pkt()
        self.send_pkt(length_rsp)
        return self.receive_data()

    def feature_request_pkt(self):
        """
        creates a valid feature request packet

        Returns: 
            feature request packet
        """
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_REQ(
                    feature_set='le_encryption+le_data_len_ext')
    
    def feature_request(self):
        """
        sends a feature request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        feature_req = self.feature_request_pkt()
        self.send_pkt(feature_req)
        return self.receive_data()
    
    def feature_response_pkt(self):
        """
        creates a valid feature response packet

        Returns: 
            feature response packet
        """
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_RSP(
                    feature_set='le_encryption+le_data_len_ext')

    def feature_response(self):
        """
        sends a feature response and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        feature_rsp = self.feature_response_pkt()
        self.send_pkt(feature_rsp)
        return self.receive_data()
    
    def mtu_request_pkt(self):
        """
        creates a valid mtu request packet

        Returns: 
            mtu request packet
        """
        return BTLE(access_addr=self.access_address) / \
                    BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
    
    def mtu_request(self):
        """
        sends mtu request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        mtu_req = self.mtu_request_pkt()
        self.send_pkt(mtu_req)
        return self.receive_data()
    
    def version_request_pkt(self):
        """
        creates a valid version request packet

        Returns: 
            version request packet
        """
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_VERSION_IND(version='5.0')
    
    def version_request(self):
        """
        sends version request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        version_req = self.version_request_pkt()
        self.send_pkt(version_req)
        return self.receive_data()
    
    def termination_indication_pkt(self):
        """
        creates a termination indication packet

        Returns: 
            length request packet
        """
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_TERMINATE_IND()
    
    def termination_indication(self):
        """
        send a termination packet

        Returns: 
            response to termination packet
        """
        termination_ind = self.termination_indication_pkt()
        self.driver.send(termination_ind)
        return self.receive_data(min_attempts=constant.TERMINATE_MIN_ATTEMPTS,max_attempts=constant.TERMINATE_MAX_ATTEMPTS)
    
    def pairing_request_pkt(self, authentication):
        """
        creates a valid pairing request packet

        Returns: 
            length request packet
        """
        pairing_req = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(iocap=0x04, oob=0, authentication=authentication, max_key_size=16, initiator_key_distribution=0x07, responder_key_distribution=0x07)

        return pairing_req

    def pairing_request(self, authentication = 0x01):
        """
        sends pairing request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        pairing_req = self.pairing_request_pkt(authentication)
        self.driver.send(pairing_req)
        return self.receive_data()
    
    def reconnect(self):
        self.termination_indication()
        self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)

    def keep_alive_connection(self):
        """
        sends a connection request to avoid that peripheral enters a standby 
        state. The connection is reset afterwards by a scan request.
        In case of a connection error, the procedure is repeated.
        """
        error_counter = 0
        output = constant.ERROR
        while output == constant.ERROR and error_counter < constant.CONNECTION_ERROR_ATTEMPTS:
            output_con = self.connection_request()
            output_scan = self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
            if (output_con == constant.ERROR or output_scan == constant.ERROR):
                self.reconnect()
                output = constant.ERROR
            else:
                output = ''
            error_counter += 1
            self.connection_error_counter += 1
        
        if error_counter >= constant.CONNECTION_ERROR_ATTEMPTS and output == constant.ERROR:
            raise ConnectionError()

    def default(self):
        return "invalid input provided"
        
    def pre(self):
        """
        resets the peripheral including a keep alive message to avoid that 
        peripheral enters standby state
        """
        rand_hex_str = hex(random.getrandbits(48))[2:]
        # always select new random master and access address
        self.master_address = ':'.join(a+b for a,b in zip(rand_hex_str[::2], rand_hex_str[1::2])) 
        self.access_address = int(hex(random.getrandbits(32)),0)
        # check if connection can be established
        self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
        self.keep_alive_connection()

    def post(self):
        """
        terminates connection after performing an input sequence
        """
        self.termination_indication()

    def step(self, letter):
        """
        performs a step in the output query. Abstract inputs are mapped
        to concrete methods
        """
        requests = {
            "scan_req": {"method": self.scan_request, "params": {}},
            "connection_req": {"method": self.connection_request, "params": {}},
            "version_req": {"method": self.version_request, "params": {}},
            "length_req": {"method": self.length_request, "params": {}},
            "length_rsp": {"method": self.length_response, "params": {}},
            "mtu_req": {"method": self.mtu_request, "params": {}},
            "feature_req": {"method": self.feature_request, "params": {}},
            "feature_rsp": {"method": self.feature_response, "params": {}},
            "pairing_req": {"method": self.pairing_request, "params": {}},
        }
        request = requests.get(letter, {"method": self.default})
        output = request["method"](**request.get("params", {}))
        return output
    
    def query(self, word):
        """
        Performs an output query on the SUL.
        Before the query, pre() method is called and after the query post()
        method is called. Each letter in the word (input in the input sequence) 
        is executed using the step method. If the step method returns an error, 
        the query gets repeated.

        Args:

            word: output query (word consisting of inputs)

        Returns:

            list of observed outputs, where the i-th output corresponds to the output of the system after the i-th input

        """
        self.performed_steps_in_query = 0
        out = constant.ERROR
        error_counter = 0
        while out == constant.ERROR and error_counter < constant.CONNECTION_ERROR_ATTEMPTS:
            self.pre()
            outputs = []
            num_steps = 0
            for letter in word:
                out = self.step(letter)
                num_steps += 1
                if out == constant.ERROR:
                    print(Fore.RED + "ERROR reported")
                    self.connection_error_counter += 1
                    self.post()
                    self.num_queries += 1
                    self.performed_steps_in_query += num_steps
                    self.num_steps += num_steps
                    break
                outputs.append(out)
            if out == constant.ERROR:
                error_counter += 1
                continue
            self.post()
            self.num_queries += 1
            self.performed_steps_in_query += len(word)
            self.num_steps += len(word)
            return outputs

        raise ConnectionError()
    
    def save_pcap(self, pcap_filename):
        self.driver.save_pcap(pcap_filename)
