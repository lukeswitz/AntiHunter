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
EXCLUDE := -i Antihunter/full/src/wifi.c -i Antihunter/full/src/opendroneid.c \
	-i Antihunter/headless/src/wifi.c -i Antihunter/headless/src/opendroneid.c \
	--suppress=*:*/opendroneid.h --suppress=*:*/odid_wifi.h

.PHONY: lint lint-full lint-headless build build-full build-headless test-ble test-psram-table test-cuckoo clean

test-ble:
	c++ -std=c++17 -O1 -I$(FULL_SRC) scripts/test_ble_class.cpp $(FULL_SRC)/ble_class.cpp -o /tmp/test_ble_class
	/tmp/test_ble_class

test-psram-table:
	for v in $(FULL_SRC) $(HEADLESS_SRC); do \
		c++ -std=c++17 -O1 -Iscripts/psram_table_stubs -I$$v scripts/test_psram_table.cpp -o /tmp/test_psram_table && \
		/tmp/test_psram_table || exit 1; \
	done

test-cuckoo:
	for v in $(FULL_SRC) $(HEADLESS_SRC); do \
		c++ -std=c++17 -O1 -Iscripts/psram_table_stubs -I$$v scripts/test_cuckoo.cpp -o /tmp/test_cuckoo && \
		/tmp/test_cuckoo || exit 1; \
	done

lint: lint-full lint-headless

lint-full:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(EXCLUDE) -I$(FULL_SRC) -I$(COMMON_SRC) $(FULL_SRC)/ $(COMMON_SRC)/

lint-headless:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(EXCLUDE) -I$(HEADLESS_SRC) -I$(COMMON_SRC) $(HEADLESS_SRC)/ $(COMMON_SRC)/

build: build-full build-headless

build-full:
	pio run -e AntiHunter-full

build-headless:
	pio run -e AntiHunter-headless

clean:
	pio run -t clean
