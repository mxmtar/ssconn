/* ss_ctrl_msg.h */

#ifndef __SS_CTRL_MSG_H__
#define __SS_CTRL_MSG_H__

#include <sys/types.h>

enum {
	SS_CTRL_MSG_ENABLE		= 0x37,
	SS_CTRL_MSG_STATUS		= 0x3b,
	SS_CTRL_MSG_DISABLE		= 0x45,
};

struct ss_ctrl_msg_req_hdr {
	u_int32_t id;
	u_int8_t proto;
	u_int16_t length;
	u_int16_t flags;
	u_int8_t cmd;
	u_int8_t chnl;
} __attribute__((packed));

struct ss_ctrl_msg_resp_hdr {
	u_int16_t length;
	u_int16_t flags;
	u_int8_t cmd;
	u_int8_t status;
} __attribute__((packed));

#endif //__SS_CTRL_MSG_H__
