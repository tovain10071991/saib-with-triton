default: build

build:
	$(MAKE) -C Common
	$(MAKE) -C ELFHelper
	$(MAKE) -C DebugHelper
	$(MAKE) -C SymExecutor
	$(MAKE) -C DisHelper
	$(MAKE) -C MapsHelper

clean:
	$(MAKE) -C Common clean
	$(MAKE) -C ELFHelper clean
	$(MAKE) -C DebugHelper clean
	$(MAKE) -C SymExecutor clean
	$(MAKE) -C DisHelper clean
	$(MAKE) -C MapsHelper clean