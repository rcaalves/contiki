/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Creates and parses the ContikiMAC header.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/contikimac/contikimac-framer.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include <string.h>

#define CONTIKIMAC_ID 0xCC

/* SHORTEST_PACKET_SIZE is the shortest packet that ContikiMAC
   allows. Packets have to be a certain size to be able to be detected
   by two consecutive CCA checks, and here is where we define this
   shortest size.
   Padded packets will have the wrong ipv6 checksum unless CONTIKIMAC_HEADER
   is used (on both sides) and the receiver will ignore them.
   With no header, reduce to transmit a proper multicast RPL DIS. */
#ifdef CONTIKIMAC_FRAMER_CONF_SHORTEST_PACKET_SIZE
#define SHORTEST_PACKET_SIZE CONTIKIMAC_FRAMER_CONF_SHORTEST_PACKET_SIZE
#else /* CONTIKIMAC_FRAMER_CONF_SHORTEST_PACKET_SIZE */
#define SHORTEST_PACKET_SIZE 43
#endif /* CONTIKIMAC_FRAMER_CONF_SHORTEST_PACKET_SIZE */

#ifdef CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#define DECORATED_FRAMER CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER
#else /* CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER */
#define DECORATED_FRAMER framer_802154
#endif /* CONTIKIMAC_FRAMER_CONF_DECORATED_FRAMER */

#define MAX_N_SEQNOS 16


#if RDC_UNIDIR_SUPPORT
struct seqno {
  linkaddr_t receiver;
  uint8_t seqno;
};

static struct seqno sent_seqnos[MAX_N_SEQNOS];
static uint8_t seqno_count = 0;
static uint8_t bcast_seqno = 1;
#endif


extern const struct framer DECORATED_FRAMER;
#include <stdio.h>
#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

/* 2-byte header for recovering padded packets.
   Wireshark will not understand such packets at present. */
struct hdr {
  uint8_t id;
  uint8_t len;
#ifdef RDC_UNIDIR_SUPPORT
  uint16_t tx_offset;
  uint8_t seqno_ind;
#endif
} __attribute__((packed));

/*---------------------------------------------------------------------------*/
#if RDC_UNIDIR_SUPPORT
void
set_tx_offset(rtimer_clock_t offset, uint8_t is_known_receiver)
{
  struct hdr *chdr;

  offset = offset | (is_known_receiver << 15);

  chdr = (struct hdr *)(packetbuf_hdrptr() + DECORATED_FRAMER.length());
  chdr->tx_offset = offset;
}
uint16_t
get_tx_offset(uint8_t *is_known_receiver_ret)
{
  struct hdr *chdr;

  chdr = (struct hdr *)(packetbuf_hdrptr() + DECORATED_FRAMER.length());

  if(is_known_receiver_ret)
    *is_known_receiver_ret = (chdr->tx_offset & 0x8000) >> 15;
  return (chdr->tx_offset & 0x7FFF);
}
void
set_ind_seqno_hdr(uint8_t seqno)
{
  struct hdr *chdr;

  chdr = (struct hdr *)(packetbuf_hdrptr() + DECORATED_FRAMER.length());
  chdr->seqno_ind = seqno;
}
uint8_t
get_ind_seqno()
{
  struct hdr *chdr;

  chdr = (struct hdr *)(packetbuf_hdrptr() + DECORATED_FRAMER.length());
  return chdr->seqno_ind;
}
void
replace_seqno()
{
  struct hdr *chdr;
  chdr = (struct hdr *)(packetbuf_hdrptr() + DECORATED_FRAMER.length());
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, chdr->seqno_ind);
}
void
set_ind_seqno(void)
{
  int i;

  printf("%d ", packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u16);
  if(packetbuf_holds_broadcast()) {
    set_ind_seqno_hdr(bcast_seqno++);
    return;
  }

  /*
   * Check for duplicate packet by comparing the sequence number of the incoming
   * packet with the last few ones we saw.
   */
  for(i = 0; i < seqno_count; ++i) {
    // printf("loop %04u %04u\n", packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u16, sent_seqnos[i].receiver.u16);
    if(linkaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_RECEIVER), &sent_seqnos[i].receiver)) {
      // printf("deu match\n");
      set_ind_seqno_hdr(++sent_seqnos[i].seqno);
      return;
    }
  }
  // printf("num deu match\n");

  if (seqno_count == MAX_N_SEQNOS) {
    set_ind_seqno_hdr(1);
    return;
  }

  // for(i = 0; i < seqno_count && i < MAX_N_SEQNOS -1; ++i) {
  for(i = seqno_count; i > 0; i--) {
    memcpy(&sent_seqnos[i], &sent_seqnos[i-1], sizeof(struct seqno));
  }
  seqno_count ++;
  // if (seqno_count > MAX_N_SEQNOS)
  //   seqno_count = MAX_N_SEQNOS;
  sent_seqnos[0].seqno = 1;
  set_ind_seqno_hdr(sent_seqnos[0].seqno);
  linkaddr_copy(&sent_seqnos[0].receiver, packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
}
#endif
/*---------------------------------------------------------------------------*/
static int
hdr_length(void)
{
  return DECORATED_FRAMER.length() + sizeof(struct hdr);
}
/*---------------------------------------------------------------------------*/
static int
create(void)
{
  struct hdr *chdr;
  int hdr_len;

  if(packetbuf_hdralloc(sizeof(struct hdr)) == 0) {
    PRINTF("contikimac-framer: too large header\n");
    return FRAMER_FAILED;
  }
  chdr = packetbuf_hdrptr();
  chdr->id = CONTIKIMAC_ID;
  chdr->len = 0;
#ifdef RDC_UNIDIR_SUPPORT
  chdr->tx_offset = 0;
#endif

  hdr_len = DECORATED_FRAMER.create();
  if(hdr_len < 0) {
    PRINTF("contikimac-framer: decorated framer failed\n");
    return FRAMER_FAILED;
  }

  return hdr_len + sizeof(struct hdr);
}
/*---------------------------------------------------------------------------*/
static void
pad(void)
{
  int transmit_len;
  uint8_t *ptr;
  uint8_t zeroes_count;

  transmit_len = packetbuf_totlen();
  if(transmit_len < SHORTEST_PACKET_SIZE) {
    /* Padding required */
    zeroes_count = SHORTEST_PACKET_SIZE - transmit_len;
    ptr = packetbuf_dataptr();
    memset(ptr + packetbuf_datalen(), 0, zeroes_count);
    packetbuf_set_datalen(packetbuf_datalen() + zeroes_count);
  }
}
/*---------------------------------------------------------------------------*/
static int
create_and_secure(void)
{
  struct hdr *chdr;
  int hdr_len;

  hdr_len = create();
  if(hdr_len < 0) {
    return FRAMER_FAILED;
  }

  packetbuf_compact();
  if(!NETSTACK_LLSEC.on_frame_created()) {
    PRINTF("contikimac-framer: securing failed\n");
    return FRAMER_FAILED;
  }

  chdr = (struct hdr *)(((uint8_t *) packetbuf_dataptr()) - sizeof(struct hdr));
  chdr->len = packetbuf_datalen();
  pad();
  set_ind_seqno();

  return hdr_len;
}
/*---------------------------------------------------------------------------*/
static int
parse(void)
{
  int hdr_len;
  struct hdr *chdr;

  hdr_len = DECORATED_FRAMER.parse();
  if(hdr_len < 0) {
    return FRAMER_FAILED;
  }

  chdr = packetbuf_dataptr();
  if(chdr->id != CONTIKIMAC_ID) {
    PRINTF("contikimac-framer: CONTIKIMAC_ID is missing\n");
    return FRAMER_FAILED;
  }

  if(!packetbuf_hdrreduce(sizeof(struct hdr))) {
    PRINTF("contikimac-framer: packetbuf_hdrreduce failed\n");
    return FRAMER_FAILED;
  }

  packetbuf_set_datalen(chdr->len);
  chdr->len = 0;
  // printf("Received phase: %d %X %X\n", chdr->tx_offset, chdr->tx_offset, get_tx_offset());

  return hdr_len + sizeof(struct hdr);
}
/*---------------------------------------------------------------------------*/
const struct framer contikimac_framer = {
  hdr_length,
  create,
  create_and_secure,
  parse
};
/*---------------------------------------------------------------------------*/
