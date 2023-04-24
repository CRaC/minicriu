#  Copyright 2017-2022 Azul Systems, Inc.
# 
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
# 
#  1. Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the following disclaimer.
# 
#  2. Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
# 
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.

CFLAGS = -g -MMD -MT $@ -MF $@.d
ASFLAGS = $(CFLAGS)

all : minicriu libminicriu-client.a

minicriu : minicriu.o
minicriu : LDFLAGS += -static
minicriu : LDLIBS += -lpthread
minicriu.o : CFLAGS += -fPIE

minicriu-client : LDLIBS += -lpthread
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
	export LD_LIBRARY_PATH=$$PWD; bash -c 'echo $$$$ > /tmp/test.pid; ulimit -c unlimited; exec ./$<'; mv /tmp/core.$$(cat /tmp/test.pid) $@
	rm /tmp/test.pid

sim-run : test
	gdb -q -batch -ex 'handle SIGABRT noprint nostop nopass' -ex 'run' ./test

run : minicriu core
	sudo rm -f /tmp/core.*
	sudo bash -c 'ulimit -c unlimited; ./$^; exit $$?' || sudo mv /tmp/core.* core.crash && sudo chmod a+rw core.crash
	#./$^

%.readelf : %
	readelf -a $< > $@

clean :
	rm -f minicriu test file core *.[aod]

-include $(wildcard *.d)
