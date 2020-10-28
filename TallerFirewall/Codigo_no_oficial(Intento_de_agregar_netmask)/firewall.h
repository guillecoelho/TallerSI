#ifndef _FW_H_
#define _FW_H_

#include <linux/types.h>

#define DEVICE_INTF_NAME "tsiFirewall"


/* Mode of an instruction */
enum fw_mode {
	FW_NONE = 0,
	FW_ADD = 1,
	FW_REMOVE = 2,
	FW_VIEW = 3,
	FW_POLICY = 4
};


/* Filter rule of tsiFirewall */
struct fw_rule {
	uint8_t  in; // 1 = Inbound, 0 = Outbound
	uint32_t s_ip;
	uint32_t s_mask;
	uint16_t s_port;
	uint32_t d_ip;
	uint32_t d_mask;
	uint16_t d_port;
	uint8_t  proto;	// ICMP = 1, UDP =  6, TCP = 17 
	uint8_t  action; // 1 = Allow, 0 = Deny
};


/* Control instruction */
struct fw_ctl {
	enum fw_mode mode;
	struct fw_rule rule;
	uint8_t index;
};

#endif