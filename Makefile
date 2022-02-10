# Helper Makefile assuming build/ as the build directory, as configure does by default.

all: build

.PHONY: build install test

build:
	@if [ -e build/Makefile ]; then $(MAKE) -j 4 -C build; else true; fi
	@if [ -e build/build.ninja ]; then ninja -C build; else true; fi

install:
	@if [ -e build/Makefile ]; then $(MAKE) -j 4 -C build install; else true; fi
	@if [ -e build/build.ninja ]; then ninja -C build install; else true; fi

test:
	@if command -v zeek >/dev/null 2>&1; then \
		$(MAKE) -C zeek-agent test; \
		$(MAKE) -C tests test; \
	else \
		$(MAKE) -C tests test-no-zeek; \
	fi
