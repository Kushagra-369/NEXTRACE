PYTHON ?= python3
TARGET ?= 127.0.0.1
PORTS ?= 5432,8000

.PHONY: doctor test check scan-local version clean

doctor:
	PYTHONPATH=src $(PYTHON) -m nextrace.doctor

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

check: doctor test

scan-local:
	PYTHONPATH=src $(PYTHON) -m nextrace.main --target $(TARGET) --ports $(PORTS) --authorized

version:
	PYTHONPATH=src $(PYTHON) -m nextrace.main --version

clean:
	find output -type f ! -name '.gitkeep' -delete
	find reports -type f ! -name '.gitkeep' -delete
	find history -type f ! -name '.gitkeep' -delete
	@echo "Generated files cleaned."
