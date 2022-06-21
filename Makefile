CFLAGS = -g -MMD -MT $@ -MF $@.d
ASFLAGS = $(CFLAGS)

all : minicriu libminicriu-client.a

minicriu : minicriu.o
minicriu : LDFLAGS += -static
minicriu.o : CFLAGS += -fPIE

libminicriu-client.a : minicriu-client.o
	ar rcs $@ $^

test : test.o libminicriu-client.a
test : LDLIBS += -lpthread

file :
	truncate -s 4K $@

set-core-pattern :
	echo /tmp/core.%p | sudo tee /proc/sys/kernel/core_pattern

core : test file
	grep '^/tmp/core.%p$$' /proc/sys/kernel/core_pattern # assume the specific core_pattern
	./$< & p=$$!; wait; mv /tmp/core.$$p $@

sim-run : test
	gdb -q -batch -ex 'handle SIGABRT noprint nostop nopass' -ex 'run' ./test

run : minicriu core
	sudo bash -c 'ulimit -c unlimited; ./$^; exit $?'

%.readelf : %
	readelf -a $< > $@

clean :
	rm -f minicriu test file core *.[aod]

-include $(wildcard *.d)
