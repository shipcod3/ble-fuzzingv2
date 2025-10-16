from sys import version_info

import random
import constant
from random import choice, randint, sample, randbytes
from BLESUL import BLESUL

from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.fields import RawVal
from colorama import Fore
from fuzzing.Utils import min_max_rdm
from FailSafeLearning.Errors import ConnectionError

class FuzzedParam():
    """
    Fuzzed param class. Defines a helper class for an easy definition and printing of fuzzed parameters.
    """

    NO_FUZZ = 'noFuzz'

    def __init__(self, name, val, valText = None):
        self.name = name
        self.val = val
        self.valText = valText

    def __str__(self):
        if self.name == self.NO_FUZZ:
            return 'no fuzzing'
        else:
            if self.valText == None:
                return f'{self.name}: {self.val}'
            else:
                return f'{self.name}: {self.valText}({self.val})'
    
    def toMap(self):
        return {self.name: self.val}

class FuzzingBLESUL(BLESUL):
    """
    Fuzzing interface for the interaction with a BLE peripheral. Commands to the peripheral are sent via a central device.
    """

    def __init__(self, serial_port, advertiser_address):
        super().__init__(serial_port, advertiser_address)

    def select_random_fuzzing_method(self, requests):
        """
        Select random method from list of provided requests and sends the selected request via the driver. 

        Args:
            requests: list of request method that a provided in this fuzzing SUL

        Returns:
            received output after sending the selected request

        """
        fuzzed_request_possibilities = [*requests.keys()]
        fuzzed_request = choice(fuzzed_request_possibilities)
        request = requests.get(fuzzed_request, {"method": self.default})
        selected_request = request["method"](**request.get("params", {}))
        print(Fore.YELLOW + f'{self.fuzzed_param}')
        self.driver.send(selected_request, fuzzed=True)
        return self.receive_data()
    
    def select_provided_fuzzing_method(self, requests, fuzzed_param : FuzzedParam):
        """
        Select provided method from list of provided requests and sends the provided request via the driver. 

        Args:

            requests: list of request method that a provided in this fuzzing SUL
            fuzzed_param: fuzzed param that corresponds to one request in the provided request method list

        Returns:
            received output after sending the selected request

        """
        print(Fore.YELLOW + f'{fuzzed_param}')
        request = requests.get(fuzzed_param.name, {"method": self.default})
        selected_request = None
        if fuzzed_param.name == fuzzed_param.NO_FUZZ:
            selected_request = request["method"](**request.get("params", {}))
        else: 
            self.fuzzed_param = fuzzed_param
            selected_request = request["method"](**fuzzed_param.toMap())
        self.driver.send(selected_request, fuzzed=True)
        return self.receive_data()

    def select_fuzzing_method(self, requests, fuzzed_param : FuzzedParam = None):
        """
        If no fuzzed_param is provided a fuzzed param is randomly selected, otherwise the method for the fuzzed param is selected. In case of random select, method that only generate request that are already used during learning are excluded, if others fuzzed params are available.

        Args:
            requests: list of request method that a provided in this fuzzing SUL
            fuzzed_param: fuzzed param that corresponds to one request in the provided request method list

        Returns:
            received output after sending the selected request

        """
        if fuzzed_param == None:
            # do not select no fuzzing
            if len(requests) > 1:
                requests = {i:requests[i] for i in requests if i!=FuzzedParam.NO_FUZZ}
            return self.select_random_fuzzing_method(requests)
        else: 
            return self.select_provided_fuzzing_method(requests,fuzzed_param)

    def connection_request_interval(self,interval = None):
        """
        creates a connection request with a fuzzed interval value

        Args:
            interval: provided interval value that shall be used

        Returns:
            connection packet with fuzzed interval value
        """
        if interval == None:
            min = 0
            max = 0xFFFF
            interval = min_max_rdm(min,max)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("interval", interval)
        conn_request[BTLE_CONNECT_REQ].interval = interval
        return conn_request

    def connection_request_timeout(self, timeout = None):
        """
        creates a connection request with a fuzzed timeout value

        Args:
            timeout: provided timeout value that shall be used

        Returns:
            connection packet with fuzzed timeout value
        """
        if timeout == None:
            min = 0
            max = 0xFFFF
            timeout = min_max_rdm(min,max)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("timeout", timeout)
        conn_request[BTLE_CONNECT_REQ].timeout = timeout
        return conn_request

    def connection_request_latency(self, latency = None):
        """
        creates a connection request with a fuzzed latency value

        Args:
            latency: provided latency value that shall be used

        Returns:
            connection packet with fuzzed latency value
        """
        if latency == None:
            min = 0
            max = 0xFFFF
            latency = min_max_rdm(min,max)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("latency", latency)
        conn_request[BTLE_CONNECT_REQ].latency = latency
        return conn_request
    
    def connection_request_win_size(self, win_size = None):
        """
        creates a connection request with a fuzzed win_size value

        Args:
            win_size: provided win_size value that shall be used

        Returns:
            connection packet with fuzzed win_size value
        """
        if win_size == None:
            min = 0
            max = 0xFF
            win_size = min_max_rdm(min,max)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("win_size", win_size)
        conn_request[BTLE_CONNECT_REQ].win_size = win_size
        return conn_request
    
    def connection_request_win_offset(self, win_offset = None):
        """
        creates a connection request with a fuzzed win_offset value

        Args:
            win_offset: provided win_offset value that shall be used

        Returns:
            connection packet with fuzzed win_offset value
        """
        if win_offset == None:
            min = 0
            max = 0xFFFF
            win_offset = min_max_rdm(min,max)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("win_offset", win_offset)
        conn_request[BTLE_CONNECT_REQ].win_offset = win_offset
        return conn_request

    def connection_request_hop(self, hop = None):
        """
        creates a connection request with a fuzzed hop value

        Args:
            hop: provided hop value that shall be used

        Returns:
            connection packet with fuzzed hop value
        """
        if hop == None:
            min = 0
            max = 0xFF
            hop = min_max_rdm(min,max)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("hop", hop)
        conn_request[BTLE_CONNECT_REQ].hop = hop
        return conn_request
    
    def connection_request_crc_init(self, crc_init = None):
        """
        creates a connection request with a fuzzed crc_init value

        Args:
            crc_init: provided crc_init value that shall be used

        Returns:
            connection packet with fuzzed crc_init value
        """
        if crc_init == None:
            random_hex = "%010x" % randint(0, 0xFFFFFF)
            random_hex_str = "0x" + random_hex
            hex_str_set = ["0xFFFFFF", "0x000000", random_hex_str]
            crc_init = int(choice(hex_str_set), base=16)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("crc_init", crc_init)
        conn_request[BTLE_CONNECT_REQ].crc_init = crc_init
        return conn_request
    
    def connection_request_chM(self, chM = None):
        """
        creates a connection request with a fuzzed channel map value

        Args:
            chM: provided channel map value that shall be used

        Returns:
            connection packet with fuzzed channel map value
        """
        if chM == None:
            random_hex = "%010x" % randint(0, 0xFFFFFFFFFF)
            random_hex_str = "0x" + random_hex
            hex_str_set = ["0x1FFFFFFFFF", "0x0000000001", random_hex_str]
            chM = int(choice(hex_str_set), base=16)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("chM", chM)
        conn_request[BTLE_CONNECT_REQ].chM = chM
        return conn_request

    def connection_request_sca(self, sca = None):
        """
        creates a connection request with a fuzzed sleep clock accuracy (sca) value

        Args:
            sca: provided sca value that shall be used

        Returns:
            connection packet with fuzzed sca value
        """
        if sca == None:
            min = 0
            max = 7
            sca = min_max_rdm(min,max)
        conn_request = self.connection_request_pkt()
        self.fuzzed_param = FuzzedParam("sca", sca)
        conn_request[BTLE_CONNECT_REQ].SCA = sca
        return conn_request
        

    def connection_request_fuzzed(self, fuzzed_param = None):
        """
        sends based on set of possible fuzzing params a fuzzed connection request

        Args:
            fuzzed_param: fuzzed param that should be selected and sent

        Returns: 
            received response or an error, if no response was received
        """
        self.fuzzed_param = FuzzedParam(FuzzedParam.NO_FUZZ, None)
        requests = {
            FuzzedParam.NO_FUZZ: {"method": self.connection_request_pkt, "params": {}},
            "interval": {"method": self.connection_request_interval, "params": {}}, # crash on cyble-416045-02[59190], cc2640r2f[15686], cc2650[0] # [E] no length
            "timeout": {"method": self.connection_request_timeout, "params": {}}, # crash on cc2640r2f[0], cc2650[0] # [E] no length
            "chM": {"method": self.connection_request_chM, "params": {}},
            "crc_init": {"method": self.connection_request_crc_init, "params": {}},
            "win_size": {"method": self.connection_request_win_size, "params": {}}, 
            "win_offset": {"method": self.connection_request_win_offset, "params": {}},
            "hop": {"method": self.connection_request_hop, "params": {}},
            "latency": {"method": self.connection_request_latency, "params": {}}, # crash on cc2640r2f[65535], cc2650[59952] # [E] no length
            "sca": {"method": self.connection_request_sca, "params": {}},
            }
        return self.select_fuzzing_method(requests,fuzzed_param)

    def scan_request_fuzzed(self, fuzzed_param = None):
        """
        sends a valid scan request. We perform no fuzzing on scan requests

        Args:
            fuzzed_param: the value of this param is not used

        Returns: 
            received response or an error, if no response was received
        """
        return super().scan_request()
        
    def length_request_fuzzed(self, fuzzed_param = None):
        """
        sends based on set of possible fuzzing params a fuzzed length request

        Args:
            fuzzed_param: fuzzed param that should be selected and sent

        Returns: 
            received response or an empty indication
        """
        self.fuzzed_param = FuzzedParam(FuzzedParam.NO_FUZZ, None)
        requests = {
            FuzzedParam.NO_FUZZ: {"method": self.length_request_pkt, "params": {}},
            "max_tx_bytes": {"method": self.length_request_max_tx_bytes, "params": {}},
            "max_rx_bytes": {"method": self.length_request_max_rx_bytes, "params": {}}
            }
        return self.select_fuzzing_method(requests,fuzzed_param)
    
    def length_request_max_tx_bytes(self, max_tx_bytes = None):
        """
        creates a length request with a fuzzed max_tx_bytes value

        Args:
            max_tx_bytes: provided max_tx_bytes value that shall be used

        Returns:
            length request packet with fuzzed max_tx_bytes value
        """
        if max_tx_bytes == None:
            min = 0
            max = 0xFF
            max_tx_bytes = min_max_rdm(min,max)
        length_req = self.length_request_pkt()
        self.fuzzed_param = FuzzedParam("max_tx_bytes", max_tx_bytes)
        length_req[LL_LENGTH_REQ].max_tx_bytes = max_tx_bytes
        return length_req

    def length_request_max_rx_bytes(self, max_rx_bytes = None):
        """
        creates a length request with a fuzzed max_rx_bytes value

        Args:
            max_rx_bytes: provided max_rx_bytes value that shall be used

        Returns:
            length request packet with fuzzed max_rx_bytes value
        """
        if max_rx_bytes == None:
            min = 0
            max = 0xFF
            max_rx_bytes = min_max_rdm(min,max)
        length_req = self.length_request_pkt()
        self.fuzzed_param = FuzzedParam("max_rx_bytes", max_rx_bytes)
        length_req[LL_LENGTH_REQ].max_rx_bytes = max_rx_bytes
        return length_req
    
    def length_response_fuzzed(self, fuzzed_param = None):
        """
        sends based on set of possible fuzzing params a fuzzed length response

        Args:
            fuzzed_param: fuzzed param that should be selected and sent

        Returns: 
            received response or an empty indication
        """
        self.fuzzed_param = FuzzedParam(FuzzedParam.NO_FUZZ, None)
        responses = {
            FuzzedParam.NO_FUZZ: {"method": self.length_response_pkt, "params": {}},
            "max_tx_bytes": {"method": self.length_response_max_tx_bytes, "params": {}},
            "max_rx_bytes": {"method": self.length_response_max_rx_bytes, "params": {}}
            }
        return self.select_fuzzing_method(responses,fuzzed_param)

    def length_response_max_tx_bytes(self, max_tx_bytes = None):
        """
        creates a length response with a fuzzed max_tx_bytes value

        Args:
            max_tx_bytes: provided max_tx_bytes value that shall be used

        Returns:
            length response packet with fuzzed max_tx_bytes value
        """
        if max_tx_bytes == None:
            min = 0
            max = 0xFF
            max_tx_bytes = min_max_rdm(min,max)
        length_rsp = self.length_response_pkt()
        self.fuzzed_param = FuzzedParam("max_tx_bytes", max_tx_bytes)
        length_rsp[LL_LENGTH_RSP].max_tx_bytes = max_tx_bytes
        return length_rsp

    def length_response_max_rx_bytes(self, max_rx_bytes = None):
        """
        creates a length response with a fuzzed max_rx_bytes value

        Args:
            max_rx_bytes: provided max_rx_bytes value that shall be used

        Returns:
            length response packet with fuzzed max_rx_bytes value
        """
        if max_rx_bytes == None:
            min = 0
            max = 0xFF
            max_rx_bytes = min_max_rdm(min,max)
        length_rsp = self.length_response_pkt()
        self.fuzzed_param = FuzzedParam('max_rx_bytes', max_rx_bytes)
        length_rsp[LL_LENGTH_RSP].max_rx_bytes = max_rx_bytes
        return length_rsp
    
    def select_random_feature_set(self):
        """
        generates are random set of features

        Returns:
            randomly composed feature set
        """
        features = ['le_encryption',
             'conn_par_req_proc',
             'ext_reject_ind',
             'slave_init_feat_exch',
             'le_ping',
             'le_data_len_ext',
             'll_privacy',
             'ext_scan_filter',
             'le_2m_phy',
             'tx_mod_idx',
             'rx_mod_idx',
             'le_coded_phy',
             'le_ext_adv',
             'le_periodic_adv',
             'ch_sel_alg']
        min = 0
        max = len(features)
        feature_number = min_max_rdm(min,max)
        feature_set = sample(features, feature_number)
        return '+'.join(feature_set)

    def feature_request_fuzzed(self, fuzzed_param = None):
        """
        sends based on set of possible fuzzing params a fuzzed feature request

        Args:
            fuzzed_param: fuzzed param that should be selected and sent

        Returns: 
            received response or an empty indication
        """
        self.fuzzed_param = FuzzedParam(FuzzedParam.NO_FUZZ, None)
        requests = {
            FuzzedParam.NO_FUZZ: {"method": self.feature_request_pkt, "params": {}},
            "feature_set": {"method": self.feature_request_random_feature_set, "params": {}}
            }
        return self.select_fuzzing_method(requests, fuzzed_param)

    def feature_request_random_feature_set(self, feature_set = None):
        """
        creates a feature request with a fuzzed feature_set value

        Args:
            feature_set: provided feature_set value that shall be used

        Returns:
            feature request packet with fuzzed feature_set value
        """
        if feature_set == None:
            feature_set=self.select_random_feature_set()
        feature_req = self.feature_request_pkt()
        self.fuzzed_param = FuzzedParam("feature_set", feature_set)
        feature_req[LL_FEATURE_REQ] = LL_FEATURE_REQ(feature_set=feature_set)
        return feature_req

    def feature_response_fuzzed(self, fuzzed_param = None):
        """
        sends based on set of possible fuzzing params a fuzzed feature response

        Args:
            fuzzed_param: fuzzed param that should be selected and sent

        Returns: 
            received response or an empty indication
        """
        self.fuzzed_param = FuzzedParam(FuzzedParam.NO_FUZZ, None)
        response = {
            FuzzedParam.NO_FUZZ: {"method": self.feature_response_pkt, "params": {}},
            "feature_set": {"method": self.feature_response_random_feature_set, "params": {}}
            }
        return self.select_fuzzing_method(response, fuzzed_param)

    def feature_response_random_feature_set(self, feature_set = None):
        """
        creates a feature response with a fuzzed feature_set value

        Args:
            feature_set: provided feature_set value that shall be used

        Returns:
            feature response packet with fuzzed feature_set value
        """
        if feature_set == None:
            feature_set=self.select_random_feature_set()
        feature_rsp = self.feature_response_pkt()
        self.fuzzed_param = FuzzedParam('feature_set', feature_set)
        feature_rsp[LL_FEATURE_RSP] = LL_FEATURE_RSP(feature_set=feature_set)
        return feature_rsp

    def mtu_request_fuzzed(self, fuzzed_param = None):
        """
        sends based on set of possible fuzzing params a fuzzed mtu response

        Args:
            fuzzed_param: fuzzed param that should be selected and sent

        Returns: 
            received response or an empty indication
        """
        self.fuzzed_param = FuzzedParam(FuzzedParam.NO_FUZZ, None)
        response = {
            FuzzedParam.NO_FUZZ: {"method": self.mtu_request_pkt, "params": {}},
            "mtu": {"method": self.mtu_request_random_mtu, "params": {}}
            }
        return self.select_fuzzing_method(response, fuzzed_param)

    def mtu_request_random_mtu(self, mtu = None):
        """
        creates a mtu request with a fuzzed mtu value

        Args:
            mtu: provided mtu value that shall be used

        Returns:
            mtu request packet with fuzzed mtu value
        """
        if mtu == None:
            min = 0
            max = 0xFFFF
            mtu = min_max_rdm(min,max)
        mtu_req = self.mtu_request_pkt()
        self.fuzzed_param = FuzzedParam('mtu', mtu)
        mtu_req[ATT_Exchange_MTU_Request].mtu = mtu
        return mtu_req

    def version_request_random_version(self, version = None):
        """
        creates a version request with a fuzzed mtu value

        Args:
            version: provided version that shall be used

        Returns:
            version request packet with fuzzed version
        """
        if version == None:
            versions = ['4.0', '4.1', '4.2', '5.0', '5.1', '5.2']
            version = choice(versions)
        self.fuzzed_param = FuzzedParam('version', version)
        version_req = self.version_request_pkt()
        version_req[LL_VERSION_IND].version = version
        return version_req

    def version_request_fuzzed(self, fuzzed_param = None):
        """
        sends based on set of possible fuzzing params a fuzzed version request

        Args:
            fuzzed_param: fuzzed param that should be selected and sent

        Returns: 
            received response or an empty indication
        """
        self.fuzzed_param = FuzzedParam(FuzzedParam.NO_FUZZ, None)
        responses = {
            FuzzedParam.NO_FUZZ: {"method": self.version_request_pkt, "params": {}},
            "version": {"method": self.version_request_random_version, "params": {}}
            }
        return self.select_fuzzing_method(responses, fuzzed_param)

    def pairing_request_fuzzed(self, fuzzed_param = None):
        """
        sends based on set of possible fuzzing params a fuzzed pairing request

        Args:
            fuzzed_param: fuzzed param that should be selected and sent

        Returns: 
            received response or an empty indication
        """
        self.fuzzed_param = FuzzedParam(FuzzedParam.NO_FUZZ, None)
        response = {
            FuzzedParam.NO_FUZZ: {"method": self.pairing_request_pkt, "params": {'authentication': 0x01}},
            "authentication": {"method": self.pairing_request_authentication, "params": {}},
            "iocap": {"method": self.pairing_request_iocap, "params": {}},
            "max_key_size": {"method": self.pairing_request_max_key_size, "params": {}}
            }
        return self.select_fuzzing_method(response, fuzzed_param)

    def pairing_request_max_key_size(self, max_key_size = None):
        """
        creates a pairing request with a fuzzed max_key_size value

        Args:
            max_key_size: provided max_key_size that shall be used

        Returns:
            pairing request packet with fuzzed max_key_size value
        """
        if max_key_size == None:
            min = 0
            max = 17
            max_key_size = min_max_rdm(min,max)
        pairing_req = self.pairing_request_pkt(authentication=0x01)
        self.fuzzed_param = FuzzedParam('max_key_size', max_key_size)
        pairing_req[SM_Pairing_Request].max_key_size = max_key_size
        return pairing_req

    def pairing_request_iocap(self, iocap = None):
        """
        creates a pairing request with a fuzzed iocap value

        Args:
            iocap: provided iocap that shall be used

        Returns:
            pairing request packet with fuzzed iocap value
        """
        iocaps = {
            "displayYesNo": 0x01,
            "NoInputNoOutput": 0x03,
            "KeyboardDisplay": 0x04
        }
        iocap_type = None
        if iocap == None:
            iocap_types = [*iocaps.keys()]
            iocap_type = choice(iocap_types)
            iocap = iocaps[iocap_type]
        else:
            iocap_type = list(iocaps.keys())[list(iocaps.values()).index(iocap)]

        pairing_req = self.pairing_request_pkt(authentication=0x01)
        self.fuzzed_param = FuzzedParam('iocap', iocap, iocap_type)
        pairing_req[SM_Pairing_Request].iocap = iocap
        return pairing_req
    
    def pairing_request_authentication(self, authentication = None):
        """
        creates a pairing request with a fuzzed authentication value

        Args:
            authentication: provided authentication that shall be used

        Returns:
            pairing request packet with fuzzed authentication value
        """
        auth_modes = {
            "no_bounding": 0x00,
            "bounding": 0x01,
            "le_secure_connection_bounding": 0x08 | 0x01,
            "mitm_bounding": 0x04 | 0x01,
            "le_secure_mitm_bounding": 0x08 | 0x40 | 0x01
        }
        auth_mode_type = None
        if authentication == None:
            auth_mode_types = [*auth_modes.keys()]
            auth_mode_type = choice(auth_mode_types)
            authentication = auth_modes[auth_mode_type]

        pairing_req = self.pairing_request_pkt(authentication=authentication)
        self.fuzzed_param = FuzzedParam('authentication', authentication, auth_mode_type)
        return pairing_req


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
            output = constant.ERROR if (output_con == constant.ERROR or output_scan == constant.ERROR) else ''
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
        self.master_address = ':'.join(a+b for a,b in zip(rand_hex_str[::2], rand_hex_str[1::2]))
        self.access_address = int(hex(random.getrandbits(32)),0)
        self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
        self.keep_alive_connection()
        self.sm_hdr_pkt = None
        self.fuzzed_param = ''
        self.reset_pcap()

    def post(self):
        """
        sends keep alive message to avoid that peripheral enters standby state 
        """
        self.termination_indication()


    def step(self, letter, params = {}):
        """
        performs a step in the output query. Abstract inputs are mapped
        to concrete methods
        """

        # mapper
        requests = {
            "scan_req": {"method": self.scan_request, "params": {}},
            "scan_req_fuzzed": {"method": self.scan_request_fuzzed, "params": {}},
            "connection_req": {"method": self.connection_request, "params": {}},
            "connection_req_fuzzed": {"method": self.connection_request_fuzzed, "params": {}},
            "version_req": {"method": self.version_request, "params": {}},
            "version_req_fuzzed": {"method": self.version_request_fuzzed, "params": {}},
            "length_req": {"method": self.length_request, "params": {}},
            "length_req_fuzzed": {"method": self.length_request_fuzzed, "params": {}},
            "length_rsp": {"method": self.length_response, "params": {}},
            "length_rsp_fuzzed": {"method": self.length_response_fuzzed, "params": {}},
            "mtu_req": {"method": self.mtu_request, "params": {}},
            "mtu_req_fuzzed": {"method": self.mtu_request_fuzzed, "params": {}},
            "feature_req": {"method": self.feature_request, "params": {}},
            "feature_req_fuzzed": {"method": self.feature_request_fuzzed, "params": {}},
            "feature_rsp": {"method": self.feature_response, "params": {}},
            "feature_rsp_fuzzed": {"method": self.feature_response_fuzzed, "params": {}},
            "pairing_req": {"method": self.pairing_request, "params": {}},
            "pairing_req_fuzzed": {"method": self.pairing_request_fuzzed, "params": {}},
            "legacy_pairing_req": {"method": self.pairing_request, "params": {}}
            }
        request = requests.get(letter, {"method": self.default})

        if params != {}:
            params = {"fuzzed_param": params}
        else: 
            params = request.get("params", {})

        output = request["method"](**params)
        return output
    
    def reset_pcap(self):
        self.driver.reset_packet_buffer()