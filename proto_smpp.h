#ifndef SMPP_PROTO_H
#define SMPP_PROTO_H

#include "util_common.h"

/* SMPP v3.4 */
#define SMPP_CMD_NACK                	0x80000000L
#define SMPP_CMD_BIND_RECEIVER       	0x00000001L
#define SMPP_CMD_BIND_RECEIVER_RSP   	0x80000001L
#define SMPP_CMD_BIND_TRANSMITTER    	0x00000002L
#define SMPP_CMD_BIND_TRANSMITTER_RSP	0x80000002L
#define SMPP_CMD_QUERY               	0x00000003L
#define SMPP_CMD_QUERY_RSP           	0x80000003L
#define SMPP_CMD_SUBMIT              	0x00000004L
#define SMPP_CMD_SUBMIT_RSP          	0x80000004L
#define SMPP_CMD_DELIVER             	0x00000005L
#define SMPP_CMD_DELIVER_RSP         	0x80000005L
#define SMPP_CMD_UNBIND              	0x00000006L
#define SMPP_CMD_UNBIND_RSP          	0x80000006L
#define SMPP_CMD_REPLACE             	0x00000007L
#define SMPP_CMD_REPLACE_RSP         	0x80000007L
#define SMPP_CMD_CANCEL              	0x00000008L
#define SMPP_CMD_CANCEL_RSP          	0x80000008L
#define SMPP_CMD_BIND_TRANSCEIVER    	0x00000009L
#define SMPP_CMD_BIND_TRANSCEIVER_RSP	0x80000009L
#define SMPP_CMD_ENQUIRE_LINK        	0x00000015L
#define SMPP_CMD_ENQUIRE_LINK_RSP    	0x80000015L
#define SMPP_CMD_MULTI               	0x00000021L
#define SMPP_CMD_MULTI_RSP           	0x80000021L
#define SMPP_CMD_ALTER               	0x00000102L
#define SMPP_CMD_DATA                	0x00000103L
#define SMPP_CMD_DATA_RSP            	0x80000103L

/* commond status */
#define SMPP_STAT_RINVMSGLEN        	0x00000001
#define SMPP_STAT_RINVCMDLEN        	0x00000002
#define SMPP_STAT_RINVCMDID         	0x00000003
#define SMPP_STAT_RINVSYSERR        	0x00000008
#define SMPP_STAT_RINVPASWD         	0x0000000E
#define SMPP_STAT_RINVSYSID         	0x0000000F
#define SMPP_STAT_RMSGQFUL          	0x00000014
#define SMPP_STAT_RINVOPTPARSTREAM  	0x000000C0
#define SMPP_STAT_RINVOPTPARNOTALLWD	0x000000C1
#define SMPP_STAT_RINVOPTPARLEN     	0x000000C2
#define SMPP_STAT_RMISSINGOPTPARAM  	0x000000C3
#define SMPP_STAT_RINVOPTPAMVAL     	0x000000C4
#define SMPP_STAT_RINVUNKNOWN       	0x000000FF
#define SMPP_STAT_RINVIP            	0x00000009
#define SMPP_STAT_RINVCONN          	0x00000012
#define SMPP_STAT_RINVSRC           	0x00000016
#define SMPP_STAT_RSERVSRC          	0x00000017
#define SMPP_STAT_RINVDST           	0x00000018
#define SMPP_STAT_RINVMLEN          	0x00000019
#define SMPP_STAT_RINVUDH           	0x0000001A
#define SMPP_STAT_RINVLNGSEQ        	0x0000001B
#define SMPP_STAT_RINVROUTE         	0x0000001C
#define SMPP_STAT_RINVSCGID         	0x0000001D
#define SMPP_STAT_RMSGPULL          	0x0000001E
#define SMPP_STAT_RINVMSGID         	0x0000001F
#define SMPP_STAT_RINVSRPARA        	0x00000020
#define SMPP_STAT_RINVSRID          	0x00000021
#define SMPP_STAT_RINVCTYPE         	0x00000022
#define SMPP_STAT_RINVREBIND        	0x00000023
#define SMPP_STAT_RTHROTTLED        	0x00000058

#define SMPP_PK_HEAD_SIZE		16
#define SMPP_PK_MAX_SIZE		1024
#define SMPP_SERVICE_TYPE_LEN        	6
#define SMPP_PASSWD_LEN              	9
#define SMPP_SYS_TYPE_LEN            	13
#define SMPP_SYS_ID_LEN              	16
#define SMPP_TIME_LEN                	17
#define SMPP_ADDR_LEN                	21
#define SMPP_ADDRESS_RANGE_LEN       	41
#define SMPP_MESSAGE_ID_LEN          	65
#define SMPP_SHORT_MESSAGE_LEN		160

typedef struct smpp_head	smpp_head;
typedef struct smpp_bind	smpp_bind;
typedef struct smpp_bind_rsp	smpp_bind_rsp;
typedef struct smpp_deliver	smpp_deliver;
typedef struct smpp_deliver_rsp	smpp_deliver_rsp;
typedef struct smpp_submit	smpp_submit;
typedef struct smpp_submit_rsp	smpp_submit_rsp;
typedef struct smpp_message	smpp_message;

struct smpp_head{
	uint32_t	cmd_len;
	uint32_t	cmd_id;
	uint32_t	cmd_stat;
	uint32_t	seq_num;
};
struct smpp_bind{
	char		sys_id[SMPP_SYS_ID_LEN];
	char		passwd[SMPP_PASSWD_LEN];
	char		sys_type[SMPP_SYS_TYPE_LEN];
	uint8_t		ver;
	uint8_t		addr_ton;
	uint8_t		addr_npi;
	char		addr_range[SMPP_ADDRESS_RANGE_LEN];
};
struct smpp_bind_rsp{
	char		sys_id[SMPP_SYS_ID_LEN];
};
struct smpp_submit{
	char		svc_type[SMPP_SERVICE_TYPE_LEN];
	uint8_t		src_addr_ton;
	uint8_t		src_addr_npi;
	char 		src_addr[SMPP_ADDR_LEN];
	uint8_t		dst_addr_ton;
	uint8_t		dst_addr_npi;
	char 		dst_addr[SMPP_ADDR_LEN];
	uint8_t		esm_class;
	uint8_t		proto_id;
	uint8_t		pri_flag;
	char 		dlv_time[SMPP_TIME_LEN];
	char 		valid_period[SMPP_TIME_LEN];
	uint8_t		reg_dlv;
	uint8_t		replace_if;
	uint8_t		data_coding;
	uint8_t		dft_msg_id;
	uint8_t		sm_len;
	char 		short_msg[SMPP_SHORT_MESSAGE_LEN];
};
struct smpp_submit_rsp{
	char		msg_id[SMPP_MESSAGE_ID_LEN];
};

struct smpp_deliver{
	char		svc_type[SMPP_SERVICE_TYPE_LEN];
	uint8_t		src_addr_ton;
	uint8_t		src_addr_npi;
	char		src_addr[SMPP_ADDR_LEN];
	uint8_t		dst_addr_ton;
	uint8_t		dst_addr_npi;
	char		dst_addr[SMPP_ADDR_LEN];
	uint8_t		esm_class;
	uint8_t   	proto_id;
	uint8_t   	pri_flag;
	uint8_t   	dlv_time;
	uint8_t   	valid_period;
	uint8_t   	reg_dlv;
	uint8_t   	replace_if;
	uint8_t   	data_coding;
	uint8_t   	dft_msg_id;
	uint8_t   	sm_len;
	char		short_msg[SMPP_SHORT_MESSAGE_LEN];
};
struct smpp_deliver_rsp{
	char		msg_id[SMPP_MESSAGE_ID_LEN];
};

struct smpp_message{
	smpp_head	head;
	union{
		smpp_bind			bind;
		smpp_bind_rsp		bind_rsp;
		smpp_submit			submit;
		smpp_submit_rsp		submit_rsp;
		smpp_deliver		deliver;
		smpp_deliver_rsp	deliver_rsp;
		smpp_head			enquire_link;
		smpp_head			enquire_link_rsp;
		smpp_head			unbind;
		smpp_head			unbind_rsp;
	}body;
};

int smpp_parse_buf2pk(char buf[], size_t size, smpp_message *ppk, uint32_t *status);
int smpp_make_pk2buf(smpp_message *ppk, char buf[], size_t *len, uint32_t *status);
void smpp_print_pk(smpp_message *ppk);

#endif
