default: build

build:
	$(MAKE) -C lib
	$(MAKE) -C tools

clean:
	rm -rf obj/*
	rm -rf bin/saib
	$(MAKE) -C lib clean
	$(MAKE) -C tools clean
