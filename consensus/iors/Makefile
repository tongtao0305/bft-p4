# SPDX-License-Identifier: Apache-2.0

BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

P4C = p4c-bm2-ss
P4SRC = p4src/iors.p4
P4JSON = $(BUILD_DIR)/iors.json
P4INFO = $(BUILD_DIR)/iors.p4.p4info.txtpb

BMV2_SWITCH_EXE = simple_switch_grpc
RUN_SCRIPT = ../../utils/run_exercise.py
TOPO ?= ../common/topo/single_switch.json

all: run

run: build
	sudo PATH=$(PATH) ${P4_EXTRA_SUDO_OPTS} python3 $(RUN_SCRIPT) -t $(TOPO) -j $(P4JSON) -b $(BMV2_SWITCH_EXE)

build: dirs $(P4JSON)

$(P4JSON): $(P4SRC) ../common/p4src/constants.p4 ../common/p4src/headers.p4
	$(P4C) --p4v 16 --p4runtime-files $(P4INFO) -o $(P4JSON) $(P4SRC)

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

stop:
	sudo PATH=$(PATH) `which mn` -c

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
