CC        = clang
PYTHON   ?= python3
SANFLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS   := -O1 -Wall -Wextra -Werror -Wno-misleading-indentation $(SANFLAGS)
ASAN_ENV := ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1
BUILD_DIR := build/tests

# Resolve Python + PYTHONPATH capable of importing `unicorn` for optional `make verify-fw`
FW_PYTHON ?= $(shell \
	if [ -x .venv/bin/python ]; then echo .venv/bin/python; \
	elif $(PYTHON) -c "import unicorn" >/dev/null 2>&1; then echo $(PYTHON); \
	elif [ -x ../../work/camera-venv/bin/python ]; then echo ../../work/camera-venv/bin/python; \
	else echo $(PYTHON); fi)

FW_PYTHONPATH := $(shell \
	for d in ../../work/*/audio-arbitration-next/python-deps; do \
		if [ -d "$$d" ]; then cd "$$d" && pwd; break; fi; \
	done)

.PHONY: all test verify-fw clean

all: test

test:
	@mkdir -p $(BUILD_DIR)
	@echo "==> [1/5] Host Clang ASan/UBSan: Autonomous Stock Record Guard r4 policy"
	$(CC) $(CFLAGS) \
		-Icamera-guards/stock-record-guard \
		camera-guards/stock-record-guard/test_policy.c \
		camera-guards/stock-record-guard/guard_policy.c \
		-o $(BUILD_DIR)/test_record_policy
	$(ASAN_ENV) ./$(BUILD_DIR)/test_record_policy
	@echo "==> [2/5] Host Clang ASan/UBSan: Stock Mode 76 Preview Guard & Dial Owner"
	$(CC) $(CFLAGS) \
		-Icamera-guards/stock-preview-guard \
		camera-guards/stock-preview-guard/test_preview_guard.c \
		camera-guards/stock-preview-guard/preview_policy.c \
		camera-guards/stock-preview-guard/dial_owner.c \
		-o $(BUILD_DIR)/test_preview_guard
	$(ASAN_ENV) ./$(BUILD_DIR)/test_preview_guard
	@echo "==> [3/5] Host Clang ASan/UBSan: VCD Bounded Bus Stop Quarantine Contract"
	$(CC) $(CFLAGS) \
		-Iquarantine-gates/vcd-bus-fence \
		tests/test_bounded_stop_contract.c \
		quarantine-gates/vcd-bus-fence/bounded_stop_contract.c \
		-o $(BUILD_DIR)/test_bounded_stop_contract
	$(ASAN_ENV) ./$(BUILD_DIR)/test_bounded_stop_contract
	@echo "==> [4/5] Freestanding ARMv7 .ko builder, ET_REL relocator & quarantine gates check"
	$(PYTHON) tests/test_ko_builder.py
	@echo "==> [5/5] Synthetic video stream auditor (60p / 25p / 29.97->59.94 frame-duplication check)"
	$(PYTHON) video-4k60-verifiers/test_video_auditor.py
	@echo "==> All offline host unit tests passed (zero firmware blobs required)."

verify-fw:
	@if [ -z "$(A7R3_FW_ROOT)" ]; then \
		echo "ERROR: Set A7R3_FW_ROOT=/path/to/verified-3.10/filesystems" >&2; \
		exit 2; \
	fi
	PYTHONPATH="$(FW_PYTHONPATH)$${PYTHONPATH:+:$$PYTHONPATH}" \
		$(FW_PYTHON) tests/verify_firmware.py --fw-root "$(A7R3_FW_ROOT)"

clean:
	rm -rf build dist out *.dSYM
