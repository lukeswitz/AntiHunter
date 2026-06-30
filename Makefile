CPPCHECK := cppcheck
CPPCHECK_FLAGS := --enable=warning,style,performance,portability --std=c++17 \
	--check-level=exhaustive \
	-DPROGMEM= \
	--error-exitcode=1

FULL_SRC := Antihunter/full/src
HEADLESS_SRC := Antihunter/headless/src
EXCLUDE := -i Antihunter/full/src/wifi.c -i Antihunter/full/src/opendroneid.c \
	-i Antihunter/headless/src/wifi.c -i Antihunter/headless/src/opendroneid.c

.PHONY: lint lint-full lint-headless build build-full build-headless clean

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
