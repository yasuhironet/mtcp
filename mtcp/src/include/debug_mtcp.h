#ifndef __DEBUG_MTCP_H__
#define __DEBUG_MTCP_H__

/* mtcp types */
#define DEBUG_MTCP_SEQNUM   (1ULL << 0)
#define DEBUG_MTCP_PROCESS  (1ULL << 1)
#define DEBUG_MTCP_ACK      (1ULL << 2)
#define DEBUG_MTCP_RECV     (1ULL << 3)

#define DEBUG_MTCP_LOG(type, format, ...) \
  DEBUG_LOG(MTCP, type, format, ##__VA_ARGS__)

#endif /*__DEBUG_MTCP_H__*/
