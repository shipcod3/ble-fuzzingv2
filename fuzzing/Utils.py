import random
import time
import constant
from colorama import Fore

from FailSafeLearning.Errors import ConnectionError

def min_max_rdm(min, max):
    rdm = random.randint(min, max)
    min_max_rdm = [min, max, rdm]
    return random.choice(min_max_rdm)

def perform_stateful_fuzzing(eq_oracle,hypothesis):
    cex = None
    fuzzing_time = 0
    try:
        start_time = time.time()
        cex = eq_oracle.find_cex(hypothesis)
        fuzzing_time = time.time() - start_time

        if cex is None and len(eq_oracle.fuzzing_report) == 0:
            no_cex_str = "no CEX found!"
            print(Fore.GREEN + no_cex_str)
            eq_oracle.fuzzing_overall_report += ("\n\n" + no_cex_str)
            eq_oracle.fuzzing_report += ("\n\n" + no_cex_str)

    except ConnectionError:
        fuzzing_time = time.time() - start_time
        eq_oracle.fuzzing_overall_report += "\n\nDevice might have crashed!!!"
        if constant.LOG_PCAP:
            eq_oracle.sul.save_pcap(f'{eq_oracle.pcap_file_name}_crash.pcap')
        print(Fore.RED + "Device might have crashed.")
    
    eq_oracle.fuzzing_overall_report += f'\n\nFuzzing time (seconds):  {fuzzing_time}'
    eq_oracle.fuzzing_overall_report += '\n# Queries: {}'.format(eq_oracle.num_queries)
    eq_oracle.fuzzing_overall_report += '\n# Steps: {}'.format(eq_oracle.num_steps)

def create_reports(path, error_report, general_report):
    if len(error_report) > 0:
        create_error_report(path, error_report)
    create_general_report(path, general_report)
    
def create_error_report(path, error_report):
    f = open(path + "fuzzing_cex_report.txt", "w")
    f.write(error_report)
    f.close()

def create_general_report(path, general_report):
    report = open(path + "fuzzing_report.txt", "w")
    report.write(general_report)
    report.close()