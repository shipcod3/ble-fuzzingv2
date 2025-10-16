import sys
import constant
from colorama import Fore
from fuzzing.FuzzingBLESUL import FuzzingBLESUL, FuzzedParam

args_len = len(sys.argv)

if args_len < 3:
    sys.exit("Too few arguments provided.\nUsage: python3 multiple_version_ind_test.py 'serial_port' 'advertiser_address', ['pcap_filename']")

serial_port = sys.argv[1]
advertiser_address = sys.argv[2]

if args_len == 4:
    pcap_filename = sys.argv[3]
else:
    pcap_filename = 'multiple_version_ind_test_log'

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
first_version_rsp = ble_sul.version_request()
second_version_rsp = ble_sul.version_request()

if "LL_VERSION_IND" in first_version_rsp and "LL_VERSION_IND" in second_version_rsp:
    print(Fore.RED + "Multiple responds to version indications.")
elif "LL_VERSION_IND" in first_version_rsp:
    print(Fore.GREEN + "Tested device only once responded to version indication.")
else:
    print(Fore.YELLOW + "Tested device never responded to version indication.")


ble_sul.save_pcap(pcap_filename)

