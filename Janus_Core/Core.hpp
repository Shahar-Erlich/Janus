#pragma once
#include <errno.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <memory>
#include <vector>

#include <linux/ip.h>   // struct iphdr
#include <linux/tcp.h>  // struct tcphdr
#include <linux/udp.h>  // struct udphdr
#include <linux/icmp.h> // struct icmphdr
#include <arpa/inet.h>  // inet_ntop, ntohs, ntohl
#include <netinet/in.h> // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP
#include <algorithm>

/* Examples so i know how the structs are built*/

/*Structure*/
// struct nlmsghdr {
//       __u32   nlmsg_len;      /* Length of message including headers */
//       __u16   nlmsg_type;     /* Generic Netlink Family (subsystem) ID */
//       __u16   nlmsg_flags;    /* Flags - request or dump */
//       __u32   nlmsg_seq;      /* Sequence number */
//       __u32   nlmsg_pid;      /* Port ID, set to 0 */
// };
// struct genlmsghdr {
//       __u8    cmd;            /* Command, as defined by the Family */
//       __u8    version;        /* Irrelevant, set to 1 */
//       __u16   reserved;       /* Reserved, set to 0 */
// };

//============================================================
/*Example*/
// struct nlmsghdr:
//   __u32 nlmsg_len:    32
//   __u16 nlmsg_type:   GENL_ID_CTRL               // (1)
//   __u16 nlmsg_flags:  NLM_F_REQUEST | NLM_F_ACK  // (2)
//   __u32 nlmsg_seq:    1
//   __u32 nlmsg_pid:    0

// struct genlmsghdr:
//   __u8 cmd:           CTRL_CMD_GETFAMILY         // (3)
//   __u8 version:       2 /* or 1, doesn't matter */
//   __u16 reserved:     0

// struct nlattr:                                   // (4)
//   __u16 nla_len:      10
//   __u16 nla_type:     CTRL_ATTR_FAMILY_NAME
//   char data:          test1\0

//(padding:)
// char data:          \0\0