import sys
from math import ceil

from fuzzing.FuzzingBLESUL import FuzzingBLESUL
from fuzzing.FuzzingEqOracle import FuzzingEqOracle
from fuzzing.Utils import perform_stateful_fuzzing, create_reports
from aalpy.utils import load_automaton_from_file


args_len = len(sys.argv)

if args_len < 5:
    sys.exit("Too few arguments provided.\nUsage: python3 ble_fuzzing.py 'automaton_file_path', 'serial_port' 'advertiser_address', 'data_directory', ['pcap_filename']")

automaton_path = sys.argv[1]
serial_port = sys.argv[2]
advertiser_address = sys.argv[3]

if args_len >= 5:
    data_directory = sys.argv[4]
else:
    data_directory = './'

if args_len == 6:
    pcap_filename = sys.argv[5]
else:
    pcap_filename = 'fuzzing_data'

hypothesis = load_automaton_from_file(automaton_path, 'mealy', compute_prefixes=True)

query_num = 1000

states_num = len(hypothesis.states)

suffix_length = 5 if states_num < 5 else states_num

fuzzing_sul = FuzzingBLESUL(serial_port, advertiser_address)

alphabet = ['scan_req', 'connection_req', 'length_req', 'length_rsp',  'feature_rsp', 'version_req', 'mtu_req', 'pairing_req', 'feature_req']

# no pairing
# alphabet = ['scan_req', 'connection_req', 'length_req', 'length_rsp',  'feature_rsp', 'version_req', 'mtu_req', 'feature_req']

# no feature
# alphabet = ['scan_req', 'connection_req', 'length_req', 'length_rsp',  'feature_rsp', 'version_req', 'mtu_req', 'pairing_req']

# no length
#alphabet = ['scan_req', 'connection_req', 'length_rsp',  'feature_rsp', 'version_req', 'mtu_req', 'pairing_req', 'feature_req']

eq_oracle = FuzzingEqOracle(alphabet, fuzzing_sul, walks_per_state=ceil(query_num / states_num), fuzzing_walk_len=1, walk_len=suffix_length, pcap_file_name=data_directory + pcap_filename, state_analysis = True)

perform_stateful_fuzzing(eq_oracle, hypothesis)

create_reports(data_directory, eq_oracle.fuzzing_report, eq_oracle.fuzzing_overall_report)



