/*
 * Copyright 2017 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* ===========================================
   LABEL the packet with the connection status
   =========================================== */

#include <uapi/linux/ip.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16     /* Information Reply		*/
#define ICMP_ADDRESS 17        /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_ACK 0x10

struct icmphdr {
  u_int8_t type; /* message type */
  u_int8_t code; /* type sub-code */
  u_int16_t checksum;
  union {
    struct {
      u_int16_t id;
      u_int16_t sequence;
    } echo;            /* echo datagram */
    u_int32_t gateway; /* gateway address */
    struct {
      u_int16_t __unused;
      u_int16_t mtu;
    } frag; /* path mtu discovery */
  } un;
};

enum {
  WILDCARD,
  NEW,
  ESTABLISHED,
  RELATED,
  INVALID,
  SYN_SENT,
  SYN_RECV,
  FIN_WAIT,
  LAST_ACK,
  TIME_WAIT
};

struct packetHeaders {
  uint32_t srcIp;
  uint32_t dstIp;
  uint8_t l4proto;
  uint16_t srcPort;
  uint16_t dstPort;
  uint8_t flags;
  uint32_t seqN;
  uint32_t ackN;
  uint8_t connStatus;
};

struct ct_k {
  uint32_t srcIp;
  uint32_t dstIp;
  uint8_t l4proto;
  uint16_t srcPort;
  uint16_t dstPort;
};

struct ct_v {
  uint64_t ttl;
  uint8_t state;
  uint32_t sequence;
};
BPF_TABLE_SHARED("hash", struct ct_k, struct ct_v, connections, 10240);

BPF_TABLE("extern", int, struct packetHeaders, packetIngress, 1);
BPF_TABLE("extern", int, struct packetHeaders, packetEgress, 1);

static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_DEBUG, "Conntrack label received packet");
  struct packetHeaders *pkt;
  int k = 0;
  if (md->in_port == _INGRESSPORT) {
    pkt = packetIngress.lookup(&k);
  } else {
    pkt = packetEgress.lookup(&k);
  }
  if (pkt == NULL) {
    // Not possible
    return RX_DROP;
  }

  struct ct_k key = {0, 0, 0, 0, 0};
  key.srcIp = pkt->srcIp;
  key.dstIp = pkt->dstIp;
  key.l4proto = pkt->l4proto;
  key.srcPort = pkt->srcPort;
  key.dstPort = pkt->dstPort;

  struct ct_k rev_key = {0, 0, 0, 0, 0};
  rev_key.srcIp = pkt->dstIp;
  rev_key.dstIp = pkt->srcIp;
  rev_key.l4proto = pkt->l4proto;
  rev_key.srcPort = pkt->dstPort;
  rev_key.dstPort = pkt->srcPort;

  struct ct_v *value;

  struct ct_v newEntry = {0, 0, 0};

  /* == UDP == */
  if (pkt->l4proto == IPPROTO_UDP) {
    value = connections.lookup(&key);
    if (value != NULL) {
      // Found in forward direction
      if (value->ttl <= bpf_ktime_get_ns()) {
        // Entry expired, so now it is to be treated as NEW.
        pkt->connStatus = NEW;
        goto action;
      } else {
        // Valid entry
        if (value->state == NEW) {
          // An entry was already present with the NEW state. This means that
          // there has been no answer, from the other side. Connection is still
          // NEW.
          pkt->connStatus = NEW;
          goto action;
        } else {
          // value->state == ESTABLISHED
          pkt->connStatus = ESTABLISHED;
          goto action;
        }
      }
    }
    // If it gets here, the entry in the forward direction was not present

    // Checking if the entry is present in the reverse direction
    value = connections.lookup(&rev_key);
    if (value != NULL) {
      // Found in the reverse direction.
      if (value->ttl <= bpf_ktime_get_ns()) {
        // Entry expired, so now it is to be treated as NEW.
        pkt->connStatus = NEW;
        goto action;
      } else {
        if (value->state == NEW) {
          // An entry was present in the rev direction with the NEW state. This
          // means that this is an answer, from the other side. Connection is
          // now ESTABLISHED.
          pkt->connStatus = ESTABLISHED;
          goto action;
        } else {
          // value->state == ESTABLISHED
          pkt->connStatus = ESTABLISHED;
          goto action;
        }
      }
    }
    // No entry found in both directions. Create one.
    pkt->connStatus = NEW;
    goto action;
  }

  /* == ICMP  == */
  if (pkt->l4proto == IPPROTO_ICMP) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    // 34 = sizeof(eth_hdr) + sizeof(ip_hdr)
    if (data + 34 + sizeof(struct icmphdr) > data_end) {
      return RX_DROP;
    }
    struct icmphdr *icmp = data + 34;
    if (icmp->type == ICMP_ECHO) {
      // Echo request is always treated as the first of the connection
      pkt->connStatus = NEW;
      goto action;
    }
    if (icmp->type == ICMP_ECHOREPLY) {
      value = connections.lookup(&rev_key);
      if (value != NULL) {
        if (value->ttl <= bpf_ktime_get_ns()) {
          // The reply is not valid anymore.
          // TODO: drop it?
          pkt->connStatus = INVALID;
          goto action;
        }
        pkt->connStatus = ESTABLISHED;
        goto action;
      } else {
        // A reply without a request
        // TODO drop it?
        pkt->connStatus = INVALID;
        goto action;
      }
    }
    if (icmp->type == ICMP_TIMESTAMP || icmp->type == ICMP_TIMESTAMPREPLY ||
        icmp->type == ICMP_INFO_REQUEST || icmp->type == ICMP_INFO_REPLY ||
        icmp->type == ICMP_ADDRESS || icmp->type == ICMP_ADDRESSREPLY) {
      // Not yet supported
      pkt->connStatus = INVALID;
      goto action;
    }

    // Here there are only ICMP errors
    // Error messages always include a copy of the offending IP header and up to
    // 8 bytes of the data that caused the host or gateway to send the error
    // message.
    if (data + 34 + sizeof(struct icmphdr) + sizeof(struct iphdr) > data_end) {
      return RX_DROP;
    }
    struct iphdr *encapsulatedIp = data + 34 + sizeof(struct icmphdr);
    key.srcIp = encapsulatedIp->saddr;
    key.dstIp = encapsulatedIp->daddr;
    key.l4proto = encapsulatedIp->protocol;
    if (data + 34 + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8 >
        data_end) {
      return RX_DROP;
    }
    uint16_t *temp = data + 34 + sizeof(struct icmphdr) + sizeof(struct iphdr);
    key.srcPort = *temp;
    temp = data + 34 + sizeof(struct icmphdr) + sizeof(struct iphdr) + 2;
    key.dstPort = *temp;

    value = connections.lookup(&key);
    if (value != NULL && value->ttl > bpf_ktime_get_ns()) {
      pkt->connStatus = RELATED;
      goto action;
    }

    rev_key.srcIp = key.dstIp;
    rev_key.dstIp = key.srcIp;
    rev_key.l4proto = key.l4proto;
    rev_key.srcPort = key.dstPort;
    rev_key.dstPort = key.srcPort;
    value = connections.lookup(&rev_key);
    if (value != NULL && value->ttl > bpf_ktime_get_ns()) {
      pkt->connStatus = RELATED;
      goto action;
    }

    // If it gets here, this error is an answer to a packet not known or to an
    // expired connection.
    // TODO: drop it?
    pkt->connStatus = INVALID;
    goto action;
  }

  /* == TCP  == */
  if (pkt->l4proto == IPPROTO_TCP) {
    value = connections.lookup(&key);
    if (value != NULL) {
      // Found in forward direction
      if (value->ttl <= bpf_ktime_get_ns()) {
        // TODO: I am not sure this is the right way to go for TCP
        connections.delete(&key);
        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 &&
            (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
          pkt->connStatus = NEW;
          goto action;
        } else {
          // Validation failed
          // TODO: drop it?
          pkt->connStatus = INVALID;
          goto action;
        }
      }

      // Valid entry

      // If it is a RST, label it as established.
      if ((pkt->flags & TCPHDR_RST) != 0) {
        pkt->connStatus = ESTABLISHED;
        goto action;
      }

      if (value->state == SYN_SENT) {
        // Still haven't received a SYN,ACK To the SYN
        if ((pkt->flags & TCPHDR_SYN) != 0 &&
            (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
          // Another SYN. It is valid, probably a retransmission.
          connections.delete(&key);
          pkt->connStatus = NEW;
          goto action;
        } else {
          // Receiving packets outside the 3-Way handshake without completing
          // the handshake
          // TODO: Drop it?
          pkt->connStatus = INVALID;
          goto action;
        }
      }
      if (value->state == SYN_RECV) {
        // Expecting an ACK here
        if ((pkt->flags & TCPHDR_ACK) != 0 &&
            (pkt->flags | TCPHDR_ACK) == TCPHDR_ACK &&
            (pkt->ackN == value->sequence)) {
          // Valid ACK to the SYN, ACK
          pkt->connStatus = ESTABLISHED;
          goto action;
        } else {
          // Validation failed, either ACK is not the only flag set or the ack
          // number is wrong
          // TODO: drop it?
          pkt->connStatus = INVALID;
          goto action;
        }
      }

      if (value->state == ESTABLISHED || value->state == FIN_WAIT ||
          value->state == LAST_ACK || value->state == TIME_WAIT) {
        pkt->connStatus = ESTABLISHED;
        goto action;
      }

      // Unexpected situation
      pcn_log(ctx, LOG_DEBUG,
              "[FW_DIRECTION] Should not get here. Flags: %d. State: %d. ",
              pkt->flags, value->state);
      pkt->connStatus = INVALID;
      goto action;
    }

    // If it gets here, the entry in the forward direction was not present
    value = connections.lookup(&rev_key);
    if (value != NULL) {
      // Found in reverse direction
      if (value->ttl <= bpf_ktime_get_ns()) {
        // TODO: I am not sure this is the right way to go for TCP
        connections.delete(&rev_key);
        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 &&
            (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
          pkt->connStatus = NEW;
          goto action;
        } else {
          // Validation failed
          // TODO: drop it?
          pkt->connStatus = INVALID;
          goto action;
        }
      }

      // If it is a RST, label it as established.
      if ((pkt->flags & TCPHDR_RST) != 0) {
        pkt->connStatus = ESTABLISHED;
        goto action;
      }

      if (value->state == SYN_SENT) {
        // This should be a SYN, ACK answer
        if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
            (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) ==
                (TCPHDR_SYN | TCPHDR_ACK) &&
            pkt->ackN == value->sequence) {
          pkt->connStatus = ESTABLISHED;
          goto action;
        }
        // Here is an unexpected packet, only a SYN, ACK is acepted as an answer
        // to a SYN
        // TODO: Drop it?
        pkt->connStatus = INVALID;
        goto action;
      }

      if (value->state == SYN_RECV) {
        // The only acceptable packet in SYN_RECV here is a SYN,ACK
        // retransmission
        if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
            (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) ==
                (TCPHDR_SYN | TCPHDR_ACK) &&
            pkt->ackN == value->sequence) {
          pkt->connStatus = ESTABLISHED;
          goto action;
        }
        pkt->connStatus = INVALID;
        goto action;
      }

      if (value->state == ESTABLISHED || value->state == FIN_WAIT ||
          value->state == LAST_ACK || value->state == TIME_WAIT) {
        pkt->connStatus = ESTABLISHED;
        goto action;
      }
      pcn_log(ctx, LOG_DEBUG,
              "[REV_DIRECTION] Should not get here. Flags: %d. State: %d. ",
              pkt->flags, value->state);
      pkt->connStatus = INVALID;
      goto action;
    }

    // New entry. It has to be a SYN.
    if ((pkt->flags & TCPHDR_SYN) != 0 &&
        (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
      pkt->connStatus = NEW;
      goto action;
    } else {
      // Validation failed
      // TODO: drop it?
      pkt->connStatus = INVALID;
      goto action;
    }
  }

  pcn_log(ctx, LOG_DEBUG, "Conntrack does not support the l4proto= %d",
          pkt->l4proto);

  // If it gets here, the protocol is not yet supported.
  pkt->connStatus = INVALID;
  goto action;

action:
#if _CONNTRACK_MODE == 1
  // Manual mode
  call_ingress_program(ctx, _NEXT_HOP_1);
  return RX_DROP;
#elif _CONNTRACK_MODE == 2
  // Automatic mode: if established, forward directly
  if (pkt->connStatus == ESTABLISHED) {
    call_ingress_program(ctx, _CONNTRACKTABLEUPDATE);
  } else {
    call_ingress_program(ctx, _NEXT_HOP_1);
  }
  pcn_log(ctx, LOG_DEBUG, "[ConntrackLabel] Something went wrong.");
  return RX_DROP;
#endif
  return RX_DROP;
}
