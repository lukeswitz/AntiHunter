CPPCHECK := cppcheck
CPPCHECK_FLAGS := --enable=all --std=c++17 \
	--suppress=missingIncludeSystem \
	--suppress=missingInclude \
	--suppress=checkersReport \
	--suppress=unusedFunction \
	--suppress=normalCheckLevelMaxBranches \
	--suppress=checkLevelNormal \
	--suppress=unmatchedSuppression \
	--inline-suppr \
	-DPROGMEM= \
	--error-exitcode=1

FULL_SRC := Antihunter/full/src
HEADLESS_SRC := Antihunter/headless/src
EXCLUDE := -i Antihunter/full/src/wifi.c -i Antihunter/full/src/opendroneid.c \
	-i Antihunter/headless/src/wifi.c -i Antihunter/headless/src/opendroneid.c \
	--suppress=*:*/opendroneid.h --suppress=*:*/odid_wifi.h

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
