
import random
import constant

from FailSafeLearning.Errors import ConnectionError
from aalpy.base.SUL import SUL
from aalpy.base import Oracle
from colorama import Fore


###
# Part of the code used in this file is copied from the AALpy project:
# https://github.com/DES-Lab/AALpy
#
# Following file/class has been copied:
# -- aalpy/oracles/StatePrefixEqOracle.py
#
# Adaptions to the existing code have been made:
# -- generation of fuzzed input sequences
# -- generated input sequence contain extended suffix
# -- check for non-determinism
# -- check for connection errors
#
#
###

class FuzzingEqOracle(Oracle):
    """
    Equivalence oracle for fuzzing using the fuzzing BLE SUL. This class also includes a state analysis based on an extended characterization set 
    """

    MAX_CEX_REPETITIONS = constant.MAX_FUZZING_CEX_REPETITIONS
    pcap_file_name = ''
    cex_id = 0
    last_input = ''
    fuzzed_inputs = []


    def __init__(self, alphabet: list, sul: SUL, walks_per_state=10, fuzzing_walk_len = 1, walk_len=30, pcap_file_name="./fuzzing_data", state_analysis = True, depth_first=False):

        super().__init__(alphabet, sul)
        self.walks_per_state = walks_per_state
        self.steps_per_walk = walk_len
        self.depth_first = depth_first
        self.freq_dict = dict()

        self.pcap_file_name = pcap_file_name
        self.fuzzing_walk_len = fuzzing_walk_len
        self.fuzzing_report = ''
        self.fuzzing_overall_report = ''
        self.state_analysis = state_analysis
        self.state_characters = {}

    def repeat_query(self, hypothesis, prefix, suffix_fuzzed, suffix_after_fuzzing):
        """
        in case of a found counterexample the query is repeated to see if it reprocable. If this is the case, the reached state by the counterexample is analyzed

        Args:
            hypothesis: provided learned model of the sul
            prefix: non-fuzzed access sequence to a state
            suffix_fuzzed: sequence of fuzzed inputs with fuzzed parameters
            suffix_after_fuzzing: non-fuzzed input sequence that is executed after the fuzzed suffix

        Returns:
            True if the counterexample is reproduceable, otherwise False
        """
        cex_repetitions = 0
        while cex_repetitions < self.MAX_CEX_REPETITIONS:
            self.reset_hyp_and_sul(hypothesis)
            cancel = False
            outputs_sul = []
            outputs_hyp = []
            for p in prefix:
                out_hyp = hypothesis.step(p)
                self.num_steps += 1
                out_sul = self.sul.step(p)
                if out_sul != out_hyp:
                    cancel = True
                    break
                outputs_sul.append(out_sul)
                outputs_hyp.append(out_hyp)
            if not cancel:
                outputs_sul_fuzzed = []
                suffix_appended = False
                for input, param in suffix_fuzzed:
                    out_hyp = hypothesis.step(input)
                    self.num_steps += 1
                    out_sul = self.sul.step(input + "_fuzzed", param)
                    outputs_sul_fuzzed.append(out_sul)
                    outputs_hyp.append(out_hyp)
                    if out_sul != out_hyp:
                        if len(outputs_sul_fuzzed) == len(suffix_fuzzed):
                            suffix_appended = True
                            outputs_sul += outputs_sul_fuzzed
                            print(Fore.RED + "CEX with fuzzing found.")
                            self.fuzzing_report += \
                            f'FUZZING-CEX ({self.cex_id}) detected on {input}[{self.sul.fuzzed_param}] detected:\n'
                            self.fuzzing_report += '-' * 20 + '\n'
                            self.fuzzing_report += f'Error inserting prefix: {prefix} and suffix {self.fuzzed_inputs}\n' \
                            f'Conflict detected: {out_hyp} vs {out_sul}\n' \
                            f'Expected output: {outputs_hyp}\n' \
                            f'Received output: {outputs_sul}\n'
                            self.fuzzing_report += '-' * 20 + '\n'
                            self.sul.save_pcap(f'{self.pcap_file_name}_{self.cex_id}.pcap')
                            self.cex_id += 1
                            if self.state_analysis: 
                                self.target_state(hypothesis, prefix, suffix_fuzzed, [], outputs_sul, hypothesis.current_state)
                            return True
                        else:
                            break
                if not suffix_appended:
                    outputs_sul += outputs_sul_fuzzed
                executed_suffix = []
                outputs_after_fuzzing = []
                for input in suffix_after_fuzzing:
                    out_hyp = hypothesis.step(input)
                    self.num_steps += 1
                    out_sul = self.sul.step(input)
                    outputs_after_fuzzing.append(out_sul)
                    outputs_hyp.append(out_hyp)
                    executed_suffix.append(input)
                    if out_sul != out_hyp:
                        if len(outputs_after_fuzzing) == len(suffix_after_fuzzing):
                            outputs_sul += outputs_after_fuzzing
                            print(Fore.RED + "CEX after fuzzing found.")
                            self.fuzzing_report += \
                            f'FUZZING-CEX ({self.cex_id}) detected on {input} detected:\n'
                            self.fuzzing_report += '-' * 20 + '\n'
                            self.fuzzing_report += f'Error inserting prefix: {prefix} and fuzzed suffix {self.fuzzed_inputs} and suffix {executed_suffix}\n' \
                            f'Conflict detected: {out_hyp} vs {out_sul}\n' \
                            f'Expected output: {outputs_hyp}\n' \
                            f'Received output: {outputs_sul}\n'
                            self.fuzzing_report += '-' * 20 + '\n'
                            self.sul.save_pcap(f'{self.pcap_file_name}_{self.cex_id}.pcap')
                            self.cex_id += 1
                            if self.state_analysis: 
                                self.target_state(hypothesis, prefix, suffix_fuzzed, suffix_after_fuzzing, outputs_sul, hypothesis.current_state)
                            return True
            cex_repetitions += 1
        return False
    
    def reset_sul(self):
        """
        resets the sul
        """
        self.sul.post()
        self.sul.pre()
        self.num_queries += 1
    
    def target_state(self, hypothesis, prefix, suffix, suffix_after_fuzzing, outputs, expected_state):
        """
        calculates the target state information after performing a non-confirming input sequence. the retrieved state information is written to the counterexample report

        Args:
            hypothesis: provided learned model of the sul
            prefix: non-fuzzed access sequence to a state
            suffix_fuzzed: sequence of fuzzed inputs with fuzzed parameters
            suffix_after_fuzzing: non-fuzzed input sequence that is executed after the fuzzed suffix
            outputs: output sequence that should be observable when executing prefix, fuzzed suffix and suffix after fuzzing
            expected_state: state that should be reached on a non-fuzzed input sequence

        """
        characters = []
        state_def = {}
        for input_list in hypothesis.characterization_set: 
            attempts = 0
            while attempts < constant.MAX_FUZZING_CEX_REPETITIONS:
                cancel = False
                self.reset_hyp_and_sul(hypothesis)
                for i in range(len(prefix)):
                    self.num_steps += 1
                    out_sul = self.sul.step(prefix[i])
                    if out_sul != outputs[i]:
                        cancel = True
                        continue
                if cancel:
                    attempts += 1
                    continue
                for i in range(len(suffix)):
                    input = suffix[i][0]
                    param = suffix[i][1]
                    self.num_steps += 1
                    out_sul = self.sul.step(input + "_fuzzed", param)
                    if out_sul != outputs[len(prefix) + i]:
                        cancel = True
                        continue
                if cancel:
                    attempts += 1
                    continue
                for i in range(len(suffix_after_fuzzing)):
                    self.num_steps += 1
                    out_sul = self.sul.step(suffix_after_fuzzing[i])
                    if out_sul != outputs[len(prefix) + len(suffix) + i]:
                        cancel = True
                        continue
                if cancel:
                    attempts += 1
                    continue
                else:
                    break
            if attempts >= constant.MAX_FUZZING_CEX_REPETITIONS:
                self.fuzzing_report += f'state cannot be calculated since outputs cannot reproduced.'
                self.fuzzing_report += "\n" + "-" * 72 + ("\n" * 4)
                raise SystemExit()
            self.num_steps += len(input_list)
            out = tuple(self.sul.step(i) for i in input_list)
            characters.append(out)
            state_def[input_list] = out
        characters.sort()
        state = [k for k,v in self.state_characters.items() if v == characters]
        if len(state) == 0:
            info = f'State is UNKNOWN!\nObserved Outputs: {state_def}'
            self.fuzzing_report += info + ("\n" * 4)
            print(Fore.RED + info)
        else:
            state = state[0]
            info = f'Source state: {self.currently_tested_state.state_id}\nEntered state: {state.state_id}\nExpected state: {expected_state.state_id}\n'
            self.fuzzing_report += info
            print(Fore.YELLOW + info)
            if expected_state != state:
                info = f'Entered state is DIFFERENT. Current state: {state.state_id}, Expected state: {expected_state.state_id}'
                self.fuzzing_report += info
                print(Fore.RED + info)
        self.fuzzing_report += "\n" + "-" * 72 + ("\n" * 4)

    
    def characterizing_outputs(self, hypothesis):
        """
        calculates the characterization of the provided hypothesis. The characterization set is then extended by all inputs from the input alphabet to generate a more accurate state information during testing

        Args:
            hypothesis: provided learned model of the sul

        """
        characterization_set = []
        if not hasattr(hypothesis, 'characterization_set'):
            characterization_set = hypothesis.compute_characterization_set()
        self.state_characters = {}
        for i in self.alphabet:
            characterization_set.append((i,))
        hypothesis.characterization_set = list(set(characterization_set))
        for state in hypothesis.states:
            characters = []
            for input_list in hypothesis.characterization_set:
                # Handle None prefix for initial state by using empty tuple
                prefix = state.prefix if state.prefix is not None else ()
                hypothesis.execute_sequence(hypothesis.initial_state, prefix)
                out = tuple(hypothesis.step(i) for i in input_list)
                characters.append(out)
            characters.sort()
            self.state_characters[state] = characters
            


    def find_cex(self, hypothesis):
        """
        this method tries to find counterexample to the conformance between the provided hypothesis and the SUL. For this, the method uses fuzzing techniques. The counterexample search is based on the StatePrefixEqOracle, where we first navigate to a state via an access sequence and then execute a fuzzed input. To check for any unknown behavior a sequence of non-fuzzed inputs is performed after wards. Every executed fuzzed input sequence is written to a report. Additionally, there is second counterexample report that includes the found counterexamples and the corresponding state information

        Args:
            hypothesis: provided learned model of the sul

        """
        self.characterizing_outputs(hypothesis)        
        states_to_cover = []
        for state in hypothesis.states:
            if state.prefix not in self.freq_dict.keys():
                self.freq_dict[state.prefix] = 0

            states_to_cover.extend([state] * (self.walks_per_state - self.freq_dict[state.prefix]))

        if self.depth_first:
            # reverse sort the states by length of their access sequences
            # first do the random walk on the state with longest access sequence
            states_to_cover.sort(key=lambda x: len(x.prefix), reverse=True)
        else:
            random.shuffle(states_to_cover)
        query_counter = 0
        for state in states_to_cover:
            query_counter += 1
            print(f'query no: {query_counter}')
            self.freq_dict[state.prefix] = self.freq_dict[state.prefix] + 1
            self.currently_tested_state = state
            out_sul = constant.ERROR
            error_counter = 0
            non_det_attempts = 0

            while non_det_attempts < constant.NON_DET_ERROR_ATTEMPTS:
                try:
                    while out_sul == constant.ERROR and error_counter < constant.CONNECTION_ERROR_ATTEMPTS:

                        self.reset_hyp_and_sul(hypothesis)
                        out_sul = ''
                        prefix = state.prefix if state.prefix is not None else ()
                        
                        for p in prefix:
                            out_hyp = hypothesis.step(p)
                            self.num_steps += 1
                            out_sul = self.sul.step(p)
                            if out_sul == constant.ERROR:
                                break
                            if out_sul != out_hyp:
                                non_det_attempts += 1
                                out_sul = constant.ERROR
                                break
                            
                        if out_sul == constant.ERROR:
                            error_counter += 1
                            continue

                        suffix_fuzzed = ()
                        suffix_with_param = []
                        self.fuzzed_inputs = []
                        reproduceable_cex = False
                        # for _ in range(self.steps_per_walk):
                        for _ in range(self.fuzzing_walk_len):
                            suffix_fuzzed += (random.choice(self.alphabet),)
                            curr_suffix = suffix_fuzzed[-1]
                            self.num_steps += 1
                            out_sul = self.sul.step(curr_suffix + "_fuzzed")
                            
                            if out_sul == constant.ERROR:
                                error_counter += 1
                                break
                            out_hyp = hypothesis.step(curr_suffix)
                            
                            self.last_input = curr_suffix 
                            self.fuzzed_inputs.append(f'{curr_suffix}[{self.sul.fuzzed_param}]')
                            suffix_with_param.append((curr_suffix, self.sul.fuzzed_param))

                            if out_sul != out_hyp:
                                print(f'Counterexample found -> repeat query: prefix: {prefix}, suffix: {suffix_fuzzed}')
                                try:
                                    reproduceable_cex = self.repeat_query(hypothesis, prefix, suffix_with_param, [])
                                    if reproduceable_cex:
                                        break
                                except ConnectionError:
                                    self.fuzzing_overall_report += f'prefix: {prefix}, fuzzing inputs: {self.fuzzed_inputs}, after fuzzing suffix: []\n'
                                    raise ConnectionError()
                        suffix_after_fuzzing = ()
                        if not reproduceable_cex:
                            for _ in range(self.steps_per_walk):
                                suffix_after_fuzzing += (random.choice(self.alphabet),)
                                self.num_steps += 1
                                out_sul = self.sul.step(suffix_after_fuzzing[-1])
                                
                                if out_sul == constant.ERROR:
                                    error_counter += 1
                                    break
                                out_hyp = hypothesis.step(suffix_after_fuzzing[-1])

                                if out_sul != out_hyp:
                                    try:
                                        reproduceable_cex = False
                                        if len(suffix_with_param) == 0:
                                            reproduceable_cex = self.repeat_query(hypothesis, prefix, [],suffix_after_fuzzing)
                                        else:
                                            reproduceable_cex = self.repeat_query(hypothesis, prefix, suffix_with_param,suffix_after_fuzzing)
                                        if reproduceable_cex:
                                            break
                                    except ConnectionError:
                                        self.fuzzing_overall_report += f'prefix: {prefix}, fuzzing inputs: {self.fuzzed_inputs}, after fuzzing suffix: {suffix_after_fuzzing}\n'
                                        raise

                        self.fuzzing_overall_report += f'prefix: {prefix}, fuzzing inputs: {self.fuzzed_inputs}, after fuzzing suffix: {suffix_after_fuzzing}\n'
                    if error_counter >= constant.CONNECTION_ERROR_ATTEMPTS and out_sul == constant.ERROR:
                        raise ConnectionError()
                    else:
                        break

                except SystemExit:
                    non_det_attempts += 1
                    if non_det_attempts == constant.NON_DET_ERROR_ATTEMPTS:
                        raise
                except ConnectionError:
                    raise

        return None