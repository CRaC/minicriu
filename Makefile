CFLAGS = -g -MMD -MT $@ -MF $@.d
ASFLAGS = $(CFLAGS)

minicriu : CFLAGS += -static -fPIE

test: LDLIBS += -lpthread

all : run

file :
	truncate -s 4K $@

core : test file
	grep '^core.%p$$' /proc/sys/kernel/core_pattern # assume the specific core_pattern
	./$< & p=$$!; wait; mv core.$$p $@

sim-run : test
	gdb -q -batch -ex 'handle SIGABRT noprint nostop nopass' -ex 'run' ./test

run : minicriu core
	./$^

%.readelf : %
	readelf -a $< > $@

clean :
	rm -f minicriu test file core *.[od]

-include $(wildcard *.d)
