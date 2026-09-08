CPPCHECK := cppcheck
CPPCHECK_FLAGS := --enable=warning,style,performance,portability,unusedFunction --std=c++17 \
	--check-level=exhaustive \
	--suppress=useStlAlgorithm \
	--inline-suppr \
	-DPROGMEM= \
	--error-exitcode=1

FULL_SRC := Antihunter/full/src
HEADLESS_SRC := Antihunter/headless/src
TEST_SRC := scripts/test_csi_metric.cpp
EXCLUDE := -i Antihunter/full/src/wifi.c -i Antihunter/full/src/opendroneid.c \
	-i Antihunter/headless/src/wifi.c -i Antihunter/headless/src/opendroneid.c

.PHONY: lint lint-full lint-headless build build-full build-headless test-csi clean

test-csi:
	c++ -std=c++17 -O1 -I$(FULL_SRC) scripts/test_csi_metric.cpp -o /tmp/test_csi_metric
	/tmp/test_csi_metric

lint: lint-full lint-headless

lint-full:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(EXCLUDE) -I$(FULL_SRC) $(FULL_SRC)/ $(TEST_SRC)

lint-headless:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(EXCLUDE) -I$(HEADLESS_SRC) $(HEADLESS_SRC)/ $(TEST_SRC)

build: build-full build-headless

build-full:
	pio run -e AntiHunter-c5-full

build-headless:
	pio run -e AntiHunter-c5-headless

clean:
	pio run -t clean
