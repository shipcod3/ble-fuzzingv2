# Stateful Black-Box Fuzzing of BLE Devices Using Automata Learning

This fork repository contains the supplemental material to the paper 'Stateful Black-Box Fuzzing of Bluetooth Devices Using Automata Learning' by Andrea Pferscher and Bernhard K. Aichernig (Institute of Software Technology, Graz University of Technology).

<img width="2844" height="942" alt="image" src="https://github.com/user-attachments/assets/80747aeb-2d52-4680-bbba-fc403d45b923" />

This repository provides a learning-based fuzzing framework for Bluetooth Low Energy (BLE) devices. The framework consists of two components. The first component is the learning component, which learns the behavioral models of BLE devices. The second component is the stateful fuzzer, which performs fuzz testing on BLE devices based on the previously learned model.

This repository also contains the learned models used in the presented case study in the paper. Furthermore, some exploits and test scripts for anomalies are provided. We also include a script that tests for a possible key downgrade during the learning process.

**EDIT / UPDATE by @shipcod3 for ble-fuzzingv2:**

I love this project, and I have used it for fuzzing some devices for SPIRITCYBER IoT Hackathon, so I decided to fix some errors, like the script was crashing with the following errors:

1. 
```
TypeError: 'NoneType' object is not iterable
```

Fixed with characterizing_outputs() and find_cex().

2. The issues in the fuzzing time (bembang time) are trying to create an LL_FEATURE_REQ packet with an invalid feature set flag. The error occurs because 'le_pwr_class' is not a valid flag in the LL_FEATURE_REQ packet definition. We tried to fix this with MCP + Claude Desktop.

I have also added a learning model from my favorite device, Xiaomi :)


##  Content
- Xiaomi model
- Firmware ([firmware/](firmware))
    - [Nordic nRF52840 Dongle](firmware/nRF52840_dongle_firmware.hex)
    - Nordic nRF52840 Development Kit: [s140_nrf52_6.1.1_softdevice](firmware/s140_nrf52_6.1.1_softdevice.hex) + [nrf52840_dk_firmware](firmware/nrf52840_dk_firmware.hex)
- Framework
    - learning execution ([ble_learning.py](ble_learning.py))
    - learning execution after establishing connection ([ble_learning_connecting_start.py](ble_learning_connecting_start.py))
    - fuzzing execution ([ble_fuzzing.py](ble_fuzzing.py))
    - fuzzing execution after establishing connection ([ble_fuzzing_connecting_start.py](ble_fuzzing_connecting_start.py))
- BLE Tests
    - Test for key size downgrade ([pairing_max_key_size_test.py](pairing_max_key_size_test.py))
    - Invalid connection request crash ([connection_interval_crash.py](connection_interval_crash.py))
    - Multiple answers to version indication [(multiple_version_ind_test](multiple_version_ind_test.py))
    - Entering unknown state ([length_unexpected_state.py](length_unexpected_state.py))

## Installation

### Prerequisites

1. Nordic nRF52840 Dongle or Development Kit flashed with corresponding firmware

    **Flashing:** You can use the programmer tool of the [nRF Connect for Desktop](https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Connect-for-desktop) application to flash the provided firmware on the [Nordic nRF52840 Dongle](firmware/nRF52840_dongle_firmware.hex) or [Nordic nRF52840 Development Kit](firmware/nrf52840_dk_firmware.hex).

    For the development kit (possibly also for the dongle) you first have to write the [s140_nrf52_6.1.1_softdevice](firmware/s140_nrf52_6.1.1_softdevice.hex) file and then the [nrf52840_dk_firmware](firmware/nrf52840_dk_firmware.hex). 

    The firmware is taken from the [SweynTooth project](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks).

2. Python 3.9

3. Python libraries [pySerial](https://github.com/pyserial/pyserial), [Scapy >=v2.4.5](https://github.com/secdev/scapy), [AALpy >=1.1.7](https://github.com/DES-Lab/AALpy) and [Colorama](https://pypi.org/project/colorama/)

    **Requirements installation:** 

    ```bash
    sudo pip3 install -r requirements.txt
    ```

## Experiment Execution

The learning-based fuzzing framework is a two-step procedure. First, you learn the behavioral model. Second, you execute the fuzzer with the previously learned model.

### Learning Execution (Step 1/2)

The learning procedure of a Bluetooth Low Energy (BLE) device can be executed via ([ble_learning.py](ble_learning.py)). The program requires the serial port name of the nRF52 device and the BLE address of the peripheral device (advertiser) that should be learned. Additionally, a file name for the learned model and the pcap log might be defined.

    python3 ble_learning.py <serial_port> <advertiser_address> [<pcap|dot filename>]

Example:

    python3 ble_learning.py /dev/ttyACM0 00:A0:50:00:00:03 CYBLE-416045-02

The program outputs the learning results after a successful learning procedure and saves the learned model to `learned_model.dot` or to a dot-file with the provided filename. Furthermore, a pcap log with all performed queries is saved to `learned_data.pcap` or to a file with the provided filename.

![Learning output](images/learning-output.png)

### Fuzzing Execution (Step 2/2)

After the learning procedure, the fuzzing procedure of a Bluetooth Low Energy (BLE) device can be executed via ([ble_fuzzing.py](ble_fuzzing.py)). The program requires the serial port name of the nRF52 device and the BLE address of the peripheral device (advertiser) that should be learned. Additionally, a file name for the learned model and the pcap log might be defined.

    python3 ble_fuzzing.py <automaton_file> <serial_port> <advertiser_address> <data_directory> [<pcap_filename>]

Example:

    python3 ble_fuzzing.py automata/cyble-416045-02.dot /dev/ttyACM0 00:A0:50:00:00:03 ./ cyble-416045-02

The fuzzer logs all performed queries in a report called `fuzzing_report.txt`, which is saved in the provided data directory. A second report, `fuzzing_cex_report.txt`, is created that contains all input sequences that led to counterexamples, the corresponding observed outputs, and the performed state analysis. Furthermore, for every found counterexample, a pcap log is created.

<img width="986" height="1212" alt="image" src="https://github.com/user-attachments/assets/e17dffda-99b2-4b38-80c2-dd10dd2f6a97" />

For BLE devices that should be learned/fuzzed after establishing a valid connection, use the [ble_learning_connecting_start.py](ble_learning_connecting_start.py) and [ble_fuzzing_connecting_start.py](ble_fuzzing_connecting_start.py) scripts. 

## BLE Exploits
We provide scripts that enable a simple reproduction of found issues and anomalies.

### (C1) Crash on consecutive connection requests

[Garbelini et al.](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks) presented [CVE-2019-19193](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19193,) which leads to crashes due to invalid values in the connection request.

Execution of exploit:

    python3 consecutive_connection_crash.py <serial_port> <advertiser_address> [<pcap_filename>]

### (C2) Crash on connection request interval field

Execution of exploit:

    python3 connection_interval_crash.py <serial_port> <advertiser_address> [<pcap_filename>]


### (C3) Crash on connection request timeout field

Execution of exploit:

    python3 connection_timeout_crash.py <serial_port> <advertiser_address> [<pcap_filename>]

### (C4) Crash on connection request latency field

Execution of exploit:

    python3 connection_latency_crash.py <serial_port> <advertiser_address> [<pcap_filename>]


### (A1) Multiple responses to version requests
According to the [BLE specification](https://www.bluetooth.com/specifications/specs/core-specification/), an already answered version indication should not be answered again. The following script tests for the behavior on multiple version indications. 

Execution of exploit:

    python3 multiple_version_ind_test.py <serial_port> <advertiser_address> [<pcap_filename>]


### (A2) Accepting pairing key size > 16

Execution of exploit:

    python3 pairing_max_key_size_greater_than_spec.py <serial_port> <advertiser_address> [<pcap_filename>]

### (A3) Connection termination on length response

Execution of exploit:

    python3 length_rsp_terminates_connection.py <serial_port> <advertiser_address> [<pcap_filename>]


### (A4) Unknown behavior on length request/response
The CC2652R1 enters an unknown state if an invalid length request or response is performed. The following script shows the behavior when entering this unknown state.

Execution of exploit:

    python3 length_unexpected_state.py <serial_port> <advertiser_address> [<pcap_filename>]


### (V1) Pairing key size reduction 
[Antonioli et al.](https://dl.acm.org/doi/10.1145/3394497) showed that the possibility of key downgrades enables the exploitation of KNOB attacks.

Execution of exploit:

    python3 pairing_max_key_size_test.py <serial_port> <advertiser_address> [<pcap_filename>]


## Acknowledgement
- [SweynTooth](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks): nRF52 driver, firmware and code snippets for BLE package construction
- [AALpy](https://github.com/DES-Lab/AALpy): active automata learning library
- [Scapy](https://github.com/secdev/scapy): BLE package parsing and composition
- [Colorama](https://github.com/secdev/scapy): colored terminal text
- Andrea Pferscher and Bernhard K. Aichernig (Institute of Software Technology, Graz University of Technology) > OGs of this repo! Hey, I am just a fork with minor additions.
