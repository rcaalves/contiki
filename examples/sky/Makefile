CONTIKI = ../..
ifndef TARGET
TARGET=sky
endif

CFLAGS+="-DNETSTACK_CONF_RDC_CHANNEL_CHECK_RATE=4"
#CFLAGS+="-DCONTIKIMAC_CONF_WITH_PHASE_OPTIMIZATION=1"
CFLAGS+="-DRDC_CONF_UNIDIR_SUPPORT=1"

all: blink sky-collect #rt-leds test-button test-cfs tcprudolph0

%.tgz: %.ihex
	mkdir $(basename $<) ; \
	mv $< $(basename $<) ; \
	echo $(basename $<)/$(basename $<).ihex 600 > $(basename $<)/runfile ; \
	tar czf $@ $(basename $<)

CONTIKI_WITH_IPV4 = 1
CONTIKI_WITH_RIME = 1
include $(CONTIKI)/Makefile.include
