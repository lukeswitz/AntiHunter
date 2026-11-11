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
EXCLUDE := -i Antihunter/full/src/wifi.c -i Antihunter/full/src/opendroneid.c \
	-i Antihunter/headless/src/wifi.c -i Antihunter/headless/src/opendroneid.c

.PHONY: lint lint-full lint-headless build build-full build-headless test-csi test-ble test-meshcore clean

test-csi:
	c++ -std=c++17 -O1 -I$(FULL_SRC) scripts/test_csi_metric.cpp -o /tmp/test_csi_metric
	/tmp/test_csi_metric

test-ble:
	c++ -std=c++17 -O1 -I$(FULL_SRC) scripts/test_ble_class.cpp $(FULL_SRC)/ble_class.cpp -o /tmp/test_ble_class
	/tmp/test_ble_class

test-meshcore:
	for v in $(FULL_SRC) $(HEADLESS_SRC); do \
		mkdir -p /tmp/test_meshcore && \
		cp scripts/meshcore_stubs/*.h $$v/meshcore_link.cpp $$v/meshcore_link.h /tmp/test_meshcore/ && \
		c++ -std=c++17 -O1 -I/tmp/test_meshcore scripts/test_meshcore_link.cpp /tmp/test_meshcore/meshcore_link.cpp -o /tmp/test_meshcore/run && \
		/tmp/test_meshcore/run || exit 1; \
	done

lint: lint-full lint-headless

lint-full:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(EXCLUDE) $(FULL_SRC)/

lint-headless:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(EXCLUDE) $(HEADLESS_SRC)/

build: build-full build-headless

build-full:
	pio run -e AntiHunter-full

build-headless:
	pio run -e AntiHunter-headless

clean:
	pio run -t clean
