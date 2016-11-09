#ifndef _XT_SETXID_H_target
#define _XT_SETXID_H_target

enum {
	XT_SET_PACKET_XID=0
};

struct xt_setxid_target_info_v2 {
	unsigned long mark;
	u_int8_t mode;
};

#endif /*_XT_SETXID_H_target*/
