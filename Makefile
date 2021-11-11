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
	rm -f minicriu test file core *.[aod]

-include $(wildcard *.d)
