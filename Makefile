CPPCHECK := cppcheck
CPPCHECK_FLAGS := --enable=warning,style,performance,portability,unusedFunction --std=c++17 \
	--check-level=exhaustive \
	--suppress=useStlAlgorithm \
	--inline-suppr \
	-DPROGMEM= \
	-DAH_GIT_SHA=\"dev\" \
	-DAH_BUILD_EPOCH=0 \
	--error-exitcode=1

FULL_SRC := Antihunter/full/src
HEADLESS_SRC := Antihunter/headless/src
COMMON_SRC := Antihunter/common/src
TEST_SRC := scripts/test_fleet_sim.cpp
EXCLUDE := -i Antihunter/full/src/wifi.c -i Antihunter/full/src/opendroneid.c \
	-i Antihunter/headless/src/wifi.c -i Antihunter/headless/src/opendroneid.c \
	--suppress=*:*/opendroneid.h --suppress=*:*/odid_wifi.h

.PHONY: lint lint-full lint-headless build build-full build-headless test-ble test-psram-table test-cuckoo test-fleet test-fleet-sim test-scan-names clean

test-fleet:
	c++ -std=c++17 -O1 -Wall -Wextra -I$(COMMON_SRC) scripts/test_fleet.cpp $(COMMON_SRC)/fleet_relay.cpp -o /tmp/test_fleet
	/tmp/test_fleet

test-fleet-sim:
	c++ -std=c++17 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=undefined -I$(COMMON_SRC) scripts/test_fleet_sim.cpp $(COMMON_SRC)/fleet_relay.cpp -o /tmp/test_fleet_sim
	/tmp/test_fleet_sim

test-scan-names:
	c++ -std=c++17 -O1 -Wall -Wextra -I$(COMMON_SRC) scripts/test_scan_names.cpp -o /tmp/test_scan_names
	/tmp/test_scan_names

test-ble:
	c++ -std=c++17 -O1 -I$(FULL_SRC) scripts/test_ble_class.cpp $(FULL_SRC)/ble_class.cpp -o /tmp/test_ble_class
	/tmp/test_ble_class

test-psram-table:
	for v in $(FULL_SRC) $(HEADLESS_SRC); do \
		c++ -std=c++17 -O1 -Iscripts/psram_table_stubs -I$$v -I$(COMMON_SRC) scripts/test_psram_table.cpp $(COMMON_SRC)/cache_heap.cpp -o /tmp/test_psram_table && \
		/tmp/test_psram_table || exit 1; \
	done

test-cuckoo:
	for v in $(FULL_SRC) $(HEADLESS_SRC); do \
		c++ -std=c++17 -O1 -Iscripts/psram_table_stubs -I$$v scripts/test_cuckoo.cpp -o /tmp/test_cuckoo && \
		/tmp/test_cuckoo || exit 1; \
	done

lint: lint-full lint-headless

lint-full:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(EXCLUDE) -I$(FULL_SRC) -I$(COMMON_SRC) $(FULL_SRC)/ $(COMMON_SRC)/ $(TEST_SRC)

lint-headless:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(EXCLUDE) -I$(HEADLESS_SRC) -I$(COMMON_SRC) $(HEADLESS_SRC)/ $(COMMON_SRC)/ $(TEST_SRC)

build: build-full build-headless

build-full:
	pio run -e AntiHunter-full

build-headless:
	pio run -e AntiHunter-headless

clean:
	pio run -t clean
