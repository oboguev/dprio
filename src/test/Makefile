ifeq ($(KERNEL_ROOT),)
    KERNEL_ROOT = ~/kernel/linux-3.15.2-dprio-nx/include/linux
endif

all: test

test: test.c ../userlib/dprio.c ../userlib/*.h
	gcc -g -DDPRIO_STAT -o test -idirafter $(KERNEL_ROOT) -pthread test.c ../userlib/dprio.c -lrt

clean:
	rm -f test test.o dprio.o

