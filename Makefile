CC = gcc
CFLAGS += -Wall -W -pedantic
CFLAGS += -Wno-unused-function
CFLAGS += -O2

LD = gcc
LDFLAGS =

.c.o:
	$(CC) -o $@ $(CFLAGS) -c $<

all: racoon.conf stage2.bin

stage2.bin: stage2.asm config2.asm rel2.asm rope2.asm stage3.bin stage4.bin
	nasm -o $@ -fbin -O6 $<

rope2.asm: rope2.i
	./ropc -c cache -O2 -g -n $< > $@

rope2.i: rope2.c config.h config2.h
	gcc -o $@ -E $<

rel2.asm: rel2.c
	./ropc -c cache -O2 -g -n $< > $@

stage4.bin: stage4.asm config2.asm rope4.asm
	nasm -o $@ -fbin -O6 $<

rope4.asm: rope4.i
	./ropc -c cache -O2 -g -n -a $< > $@

rope4.i: rope4.c
	gcc -o $@ -E $<

racoon.conf: racoon.cfg confsplit
	./confsplit $< $@ 8192

racoon.cfg config2.asm config2.h stage3.bin: untether
	./untether cache $(SLIDE)

untether: untether.o
	$(LD) -o $@ $(LDFLAGS) $^ $(LDLIBS)

untether.o: config.h config.bin

config.bin: rocky
	./rocky racoon $@

rocky: rocky.o
	$(LD) -o $@ $(LDFLAGS) $^ $(LDLIBS)

confsplit: confsplit.o
	$(LD) -o $@ $(LDFLAGS) $^ $(LDLIBS)

clean:
	-$(RM) rocky rocky.o confsplit confsplit.o untether untether.o
	-$(RM) config.bin config2.asm config2.h racoon.cfg
	-$(RM) rope2.asm rope2.i
	-$(RM) stage4.bin rope4.asm rope4.i
	-$(RM) stage3.bin
	-$(RM) rel2.asm

realclean: clean
	-$(RM) racoon.conf
	-$(RM) stage2.bin
