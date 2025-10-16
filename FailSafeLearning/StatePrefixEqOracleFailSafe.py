import random
import constant

from FailSafeLearning.Errors import ConnectionError, RepeatedNonDeterministicError
from aalpy.base.SUL import SUL
from aalpy.base import Oracle
from time import sleep

###
# The code used in this file is copied from the AALpy project:
# https://github.com/DES-Lab/AALpy
#
# Following file/class has been copied:
# -- aalpy/oracles/StatePrefixEqOracle.py
#
# Adaptions to the existing code have been made:
# -- check for non-determinism
# -- check for connection errors
#
#
###


class StatePrefixOracleFailSafe(Oracle):

    MAX_CEX_ATTEMPTS = 5

    def __init__(self, alphabet: list, sul: SUL, walks_per_state=10, walk_len=30, depth_first=False):
        #super().__init__(alphabet,sul,walks_per_state,walk_len,depth_first)
        super().__init__(alphabet, sul)
        self.walks_per_state = walks_per_state
        self.steps_per_walk = walk_len
        self.depth_first = depth_first
        self.freq_dict = dict()

    def repeat_query(self, hypothesis, input_sequence):
        
        non_det_attempts = 0
        while non_det_attempts < constant.NON_DET_ERROR_ATTEMPTS:
            self.reset_hyp_and_sul(hypothesis)
            cex_found_counter = 0
            for input in input_sequence:
                out_hyp = hypothesis.step(input)
                self.num_steps += 1
                out_sul = self.sul.step(input)
                if out_sul == constant.ERROR:
                    non_det_attempts += 1
                    break

                if out_sul != out_hyp:
                    cex_found_counter += 1
                    if cex_found_counter == self.MAX_CEX_ATTEMPTS:
                        return True
            if out_sul != constant.ERROR:
                return False
        return True

    def find_cex(self, hypothesis):
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

        for state in states_to_cover:
            self.freq_dict[state.prefix] = self.freq_dict[state.prefix] + 1

            out_sul = constant.ERROR
            error_counter = 0

            non_det_attempts = 0

            while non_det_attempts < constant.NON_DET_ERROR_ATTEMPTS:

                try:
                    while out_sul == constant.ERROR and error_counter < constant.CONNECTION_ERROR_ATTEMPTS:

                        self.reset_hyp_and_sul(hypothesis)
                        out_sul = ''
                        prefix = state.prefix
                        for p in prefix:
                            hypothesis.step(p)
                            self.num_steps += 1
                            out_sul = self.sul.step(p)
                            if out_sul == constant.ERROR:
                                break
                            
                        if out_sul == constant.ERROR:
                            error_counter += 1
                            continue

                        suffix = ()
                        for _ in range(self.steps_per_walk):
                            suffix += (random.choice(self.alphabet),)
                            self.num_steps += 1
                            out_sul = self.sul.step(suffix[-1])
                            #print("sul: " + out_sul)
                            if out_sul == constant.ERROR:
                                error_counter += 1
                                break
                            out_hyp = hypothesis.step(suffix[-1])
                            #print("hyp: " + out_hyp)

                            if out_sul != out_hyp:
                                reproducable_cex = self.repeat_query(hypothesis, prefix + suffix)
                                if reproducable_cex:
                                    return prefix + suffix
                    
                    if error_counter >= constant.CONNECTION_ERROR_ATTEMPTS and out_sul == constant.ERROR:
                        raise ConnectionError()
                    else:
                        break

                except RepeatedNonDeterministicError:
                    non_det_attempts += 1
                    sleep(5)
                    if non_det_attempts == constant.NON_DET_ERROR_ATTEMPTS:
                        raise

        return None