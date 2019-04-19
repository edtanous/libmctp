/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _LIBMCTP_H
#define _LIBMCTP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

typedef uint8_t mctp_eid_t;

/* MCTP packet definitions */
/* clang-format off */
struct mctp_hdr {
	uint8_t	ver;
	uint8_t	dest;
	uint8_t	src;
	uint8_t	flags_seq_tag;
};

/* Definitions for flags_seq_tag field */
#define MCTP_HDR_FLAG_SOM	(1<<7)
#define MCTP_HDR_FLAG_EOM	(1<<6)
#define MCTP_HDR_FLAG_TO	(1<<3)
#define MCTP_HDR_SEQ_SHIFT	(4)
#define MCTP_HDR_SEQ_MASK	(0x3)
#define MCTP_HDR_TAG_SHIFT	(0)
#define MCTP_HDR_TAG_MASK	(0x7)
/* clang-format on */

/* Maximum size of *payload* data in a MCTP packet
 * @todo: dynamic sixing based on channel implementation.
 */
#define MCTP_MTU	64

#define MCTP_CONTROL_MESSAGE_TYPE	0x00

enum MCTP_COMMAND_CODE {
	MCTP_COMMAND_CODE_SET_EID			= 0x01,
	MCTP_COMMAND_CODE_GET_EID			= 0x02,
	MCTP_COMMAND_CODE_GET_ENDPOINT_UUID		= 0x03,
	MCTP_COMMAND_CODE_GET_MCTP_VERSION_SUPPORT	= 0x04,
	MCTP_COMMAND_CODE_GET_MESSAGE_TYPE_SUPPORT	= 0x05,
	MCTP_COMMAND_CODE_GET_VENDOR_DEFINED_MSG_SUPPORT= 0x06,
	MCTP_COMMAND_CODE_RESOLVE_ENDPOINT_ID		= 0x07,
	MCTP_COMMAND_CODE_ALLOCATE_ENDPOINT_IDS		= 0x08,
	MCTP_COMMAND_CODE_ROUTING_INFORMATION_UPDATE	= 0x09,
	MCTP_COMMAND_CODE_GET_ROUTING_TABLE_ENTRIES	= 0x0A,
	MCTP_COMMAND_CODE_PREPARE_FOR_ENDPOINT_DISCOVERY= 0x0B,
	MCTP_COMMAND_CODE_ENDPOINT_DISCOVERY		= 0x0C,
	MCTP_COMMAND_CODE_DISCOVERY_NOTIFY		= 0x0D,
	MCTP_COMMAND_CODE_GET_NETWORK_ID		= 0x0E,
	MCTP_COMMAND_CODE_QUERY_HOP			= 0x0F,
	MCTP_COMMAND_CODE_RESOLVE_UUID			= 0x10,
	MCTP_COMMAND_CODE_QUERY_RATE_LIMIT		= 0x11,
	MCTP_COMMAND_CODE_REQUEST_TX_RATE_LIMIT		= 0x12,
	MCTP_COMMAND_CODE_UPDATE_RATE_LIMIT		= 0x13,
	MCTP_COMMAND_CODE_QUERY_SUPPORTED_INTERFACES	= 0x14
};

enum MCTP_CONTROL_MSG_COMPLETION_CODE {
	MCTP_CONTROL_MSG_STATUS_SUCCESS			= 0x00,
	MCTP_CONTROL_MSG_STATUS_ERROR			= 0x01,
	MCTP_CONTROL_MSG_STATUS_ERROR_INVALID_DATA	= 0x02,
	MCTP_CONTROL_MSG_STATUS_ERROR_INVALID_LENGTH	= 0x03,
	MCTP_CONTROL_MSG_STATUS_ERROR_NOT_READY		= 0x04,
	MCTP_CONTROL_MSG_STATUS_ERROR_UNSUPPORTED_CMD	= 0x05
};

/* packet buffers */

/* Allow a little space before the MCTP header in the packet, for bindings that
 * may add their own header
 */
#define MCTP_PKTBUF_BINDING_PAD	2

#define MCTP_PKTBUF_SIZE	(MCTP_PKTBUF_BINDING_PAD + \
		(sizeof(struct mctp_hdr) + MCTP_MTU))

/* clang-format off */
struct mctp_pktbuf {
	unsigned char	data[MCTP_PKTBUF_SIZE];
	uint8_t		start, end;
	uint8_t		mctp_hdr_off;
	struct mctp_pktbuf *next;
};
/* clang-format on */

struct mctp_pktbuf *mctp_pktbuf_alloc(uint8_t len);
void mctp_pktbuf_free(struct mctp_pktbuf *pkt);
struct mctp_hdr *mctp_pktbuf_hdr(struct mctp_pktbuf *pkt);
void *mctp_pktbuf_data(struct mctp_pktbuf *pkt);
uint8_t mctp_pktbuf_size(struct mctp_pktbuf *pkt);
void *mctp_pktbuf_alloc_start(struct mctp_pktbuf *pkt, uint8_t size);
void *mctp_pktbuf_alloc_end(struct mctp_pktbuf *pkt, uint8_t size);
int mctp_pktbuf_push(struct mctp_pktbuf *pkt, void *data, uint8_t len);

/* MCTP core */
struct mctp;
struct mctp_binding;

struct mctp *mctp_init(void);

unsigned long mctp_register_bus(struct mctp *mctp,
		struct mctp_binding *binding,
		mctp_eid_t eid);

typedef void (*mctp_rx_fn)(uint8_t src_eid, void *data,
		void *msg, size_t len);

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data);

int mctp_message_tx(struct mctp *mctp, mctp_eid_t eid,
		void *msg, size_t msg_len);

/* hardware bindings */
/* clang-format off */
struct mctp_binding {
	const char	*name;
	uint8_t		version;
	int		(*tx)(struct mctp_binding *binding,
				struct mctp_pktbuf *pkt);
};
/* clang-format on */

void mctp_bus_rx(struct mctp *mctp, unsigned long bus_id,
		struct mctp_pktbuf *pkt);

/* environment-specific allocation */
void mctp_set_alloc_ops(void *(*alloc)(size_t),
		void (*free)(void *),
		void *(realloc)(void *, size_t));

#ifdef __cplusplus
}
#endif
#endif /* _LIBMCTP_H */
