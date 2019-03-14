CONTIKI = ../..

CFLAGS+="-DNETSTACK_CONF_RDC_CHANNEL_CHECK_RATE=4"
CFLAGS+="-DCONTIKIMAC_CONF_WITH_PHASE_OPTIMIZATION=1"
CFLAGS+="-DRDC_CONF_UNIDIR_SUPPORT=1"
# CFLAGS+="-DCONTIKIMAC_CONF_INTER_PACKET_INTERVAL=12"
# CFLAGS+="-DCONTIKIMAC_CONF_AFTER_ACK_DETECTECT_WAIT_TIME=(RTIMER_ARCH_SECOND / 100)"

all: example-abc example-mesh example-collect example-trickle example-polite \
     example-rudolph1 example-rudolph2 example-rucb \
     example-runicast example-unicast example-neighbors

CONTIKI_WITH_RIME = 1
include $(CONTIKI)/Makefile.include
