/* ss_data_msg.h */

#ifndef __SS_DATA_MSG_H__
#define __SS_DATA_MSG_H__

#include <sys/types.h>

enum {
	SS_DATA_MSG_AUTHORIZATION	= 0x01,
	SS_DATA_MSG_COMBINED		= 0x83,
};

struct ss_data_msg_generic {
	u_int8_t cmd;
	u_int8_t status;
	u_int8_t reserved;
} __attribute__((packed));

struct ss_data_msg_auth_req {
	u_int8_t hex01;
	u_int16_t checksum;
	u_int8_t user[20];
	u_int8_t password[20];
} __attribute__((packed));

struct ss_data_msg_auth_resp {
	u_int8_t hex01;
	u_int8_t status;
	u_int8_t reserved;
	u_int32_t id;
	u_int8_t number;
} __attribute__((packed));

struct ss_data_msg_comb_hdr {
	u_int8_t hex83;
	u_int16_t length;
} __attribute__((packed));

struct ss_data_msg_comb_chunk_hdr {
	u_int8_t chnl;
	u_int16_t length;
} __attribute__((packed));

#endif //__SS_DATA_MSG_H__
