CFLAGS = -g -MMD -MT $@ -MF $@.d
ASFLAGS = $(CFLAGS)

all : minicriu libminicriu-client.a

minicriu : minicriu.o
minicriu : LDFLAGS += -static
minicriu.o : CFLAGS += -fPIE

minicriu-client.o : CFLAGS += -fPIC

libminicriu-client.a : minicriu-client.o
	ar rcs $@ $^

test : test.o libminicriu-client.a libshared.so
test : LDLIBS += -lpthread

shared.o : CFLAGS += -fPIC

libshared.so : shared.o
	$(LD) -shared -o $@ $<

file :
	truncate -s 4K $@

set-core-pattern :
	echo /tmp/core.%p | sudo tee /proc/sys/kernel/core_pattern

core : test file
	grep '^/tmp/core.%p$$' /proc/sys/kernel/core_pattern # assume the specific core_pattern
	export LD_LIBRARY_PATH=$$PWD; ./$< & p=$$!; wait; mv /tmp/core.$$p $@

sim-run : test
	gdb -q -batch -ex 'handle SIGABRT noprint nostop nopass' -ex 'run' ./test

run : minicriu core
	sudo rm -f /tmp/core.*
	sudo bash -c 'ulimit -c unlimited; ./$^; exit $$?' || sudo mv /tmp/core.* core.crash && sudo chmod a+rw core.crash

%.readelf : %
	readelf -a $< > $@

clean :
	rm -f minicriu test file core *.[aod]

-include $(wildcard *.d)
