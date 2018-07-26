#ifndef PROTO_CMPP30_H
#define PROTO_CMPP30_H

#include "util_common.h"

/*
 * CMD_ID
 */
#define	CMPP30_CMD_CONNECT			0x00000001
#define	CMPP30_CMD_CONNECT_RESP		0x80000001
#define	CMPP30_CMD_TERMINATE		0x00000002
#define	CMPP30_CMD_TERMINATE_RESP	0x80000002
#define	CMPP30_CMD_SUBMIT			0x00000004
#define	CMPP30_CMD_SUBMIT_RESP		0x80000004
#define	CMPP30_CMD_DELIVER			0x00000005
#define	CMPP30_CMD_DELIVER_RESP		0x80000005
#define	CMPP30_CMD_QUERY			0x00000006
#define	CMPP30_CMD_QUERY_RESP		0x80000006
#define	CMPP30_CMD_CANCEL			0x00000007
#define	CMPP30_CMD_CANCEL_RESP		0x80000007
#define	CMPP30_CMD_ACTIVE			0x00000008
#define	CMPP30_CMD_ACTIVE_RESP		0x80000008

/*
 * PROTO_LEN
 */
#define	CMPP30_PROTO_SP_ID			6
#define CMPP30_PROTO_ATUH			16
#define CMPP30_PROTO_SERVICE		10
#define CMPP30_PROTO_MSISDN			21
#define CMPP30_PROTO_TERMINAL		32
#define	CMPP30_PROTO_DESTUSERTL		99
#define CMPP30_PROTO_FEETYPE		2
#define CMPP30_PROTO_FEECODE		6
#define CMPP30_PROTO_TIME			17
#define CMPP30_PROTO_CONTENT		160
#define CMPP30_PROTO_LINKID			20
#define CMPP30_PROTO_RESERVE		8	
#define CMPP30_PROTO_QUERY_TIME		8	
#define CMPP30_PROTO_QUERY_CODE		10	
#define CMPP30_PROTO_REPORT_STAT	7
#define CMPP30_PROTO_REPORT_TIME	10	

/*
 * ERR_CODE
 */
#define CMPP30_STAT_CONNECT_SUCCESS		0
#define CMPP30_STAT_CONNECT_ESTRUCT		1
#define CMPP30_STAT_CONNECT_ESRC		2
#define CMPP30_STAT_CONNECT_EAUTH		3
#define CMPP30_STAT_CONNECT_EVERSION	4
#define CMPP30_STAT_CONNECT_EOTHER		5

#define CMPP30_STAT_SP_SUCCESS		0
#define CMPP30_STAT_SP_ESTRUCT		1
#define CMPP30_STAT_SP_ECMD			2
#define CMPP30_STAT_SP_ESEQ			3
#define CMPP30_STAT_SP_ELEN			4
#define CMPP30_STAT_SP_EFEECODE		5
#define CMPP30_STAT_SP_ECONTENT		6
#define CMPP30_STAT_SP_EBUSYCODE	7
#define CMPP30_STAT_SP_EFLOW		8
#define CMPP30_STAT_SP_EOTHER		9
#define CMPP30_STAT_SP_ESRC_ID      10
#define CMPP30_STAT_SP_EMSG_SRC     11
#define CMPP30_STAT_SP_EFEE_ID      12
#define CMPP30_STAT_SP_EDEST_ID     13

/*
 * BUSI
 */
#define	CMPP30_PACKET_LEN_MAX			2455
#define	CMPP30_PACKET_LEN_HEADER		12
#define	CMPP30_PACKET_LEN_CONNECT		39
#define	CMPP30_PACKET_LEN_CONNECT_RESP	30
#define	CMPP30_PACKET_LEN_SUBMIT		355
#define	CMPP30_PACKET_LEN_SUBMIT_RESP	21
#define	CMPP30_PACKET_LEN_DELIVER		245
#define	CMPP30_PACKET_LEN_DELIVER_RESP	21
#define	CMPP30_PACKET_LEN_REPORT		71
#define	CMPP30_PACKET_LEN_QUERY			39
#define	CMPP30_PACKET_LEN_QUERY_RESP	63

/*
 * STRUCT
 */
typedef struct cmpp30_header		cmpp30_header;
typedef struct cmpp30_connect		cmpp30_connect;
typedef struct cmpp30_connect_resp	cmpp30_connect_resp;
typedef struct cmpp30_submit		cmpp30_submit;
typedef struct cmpp30_submit_resp	cmpp30_submit_resp;
typedef struct cmpp30_query			cmpp30_query;
typedef struct cmpp30_query_resp	cmpp30_query_resp;
typedef struct cmpp30_deliver		cmpp30_deliver;
typedef struct cmpp30_deliver_resp	cmpp30_deliver_resp;
typedef struct cmpp30_report		cmpp30_report;
typedef struct cmpp30_header		cmpp30_active;
typedef struct cmpp30_active_resp	cmpp30_active_resp;
typedef struct cmpp30_packet		cmpp30_packet;

struct cmpp30_header
{
	uint32_t	len;
	uint32_t	cmd;
	uint32_t	seq;
};
struct cmpp30_connect
{
	char		source[CMPP30_PROTO_SP_ID + 1];
	char		auth[CMPP30_PROTO_ATUH];
	uint8_t		version;
	uint32_t	timestamp;
};
struct cmpp30_connect_resp
{
	uint32_t	status;
	char		auth[CMPP30_PROTO_ATUH];
	uint8_t		version;
};
struct cmpp30_submit
{
	uint64_t	msg_id;
	uint8_t		pk_total;
	uint8_t		pk_number;
	uint8_t		reg_delivery;
	uint8_t		msg_level;
	char		service_id[CMPP30_PROTO_SERVICE + 1];
	uint8_t		fee_usertype;
	char		fee_id[CMPP30_PROTO_TERMINAL + 1]; //32
	uint8_t		fee_type;
	uint8_t		tp_pid;
	uint8_t		tp_udhi;
	uint8_t		msg_fmt;
	char		msg_src[CMPP30_PROTO_SP_ID + 1];
	char		feetype[CMPP30_PROTO_FEETYPE + 1];
	char		feecode[CMPP30_PROTO_FEECODE + 1];
	char		valid_time[CMPP30_PROTO_TIME + 1];
	char		at_time[CMPP30_PROTO_TIME + 1];
	char		src_id[CMPP30_PROTO_MSISDN + 1];
	uint8_t		destusr_tl;
	char		dest_id[CMPP30_PROTO_DESTUSERTL][CMPP30_PROTO_TERMINAL + 1]; //32
	uint8_t		dest_type;
	uint8_t		msg_length;
	char		msg_content[CMPP30_PROTO_CONTENT];
	char		linkid[CMPP30_PROTO_LINKID + 1];
};
struct cmpp30_submit_resp
{
	uint64_t	msg_id;
	uint32_t	result;
};
struct cmpp30_deliver
{
	uint64_t	msg_id;
	char		dest_id[CMPP30_PROTO_MSISDN + 1];
	char		service_id[CMPP30_PROTO_SERVICE + 1];
	uint8_t		tp_pid;
	uint8_t		tp_udhi;
	uint8_t		msg_fmt;
	char		src_id[CMPP30_PROTO_TERMINAL + 1]; //32
	uint8_t		src_type;
	uint8_t		reg_delivery;
	uint8_t		msg_length;
	char		msg_content[CMPP30_PROTO_CONTENT];
	char		linkid[CMPP30_PROTO_LINKID + 1];
};
struct cmpp30_deliver_resp
{
	uint64_t	msg_id;
	uint32_t	result;
};
struct cmpp30_report
{
	uint64_t	msg_id;
	char		stat[CMPP30_PROTO_REPORT_STAT + 1];
	char		submit_time[CMPP30_PROTO_REPORT_TIME + 1];
	char		done_time[CMPP30_PROTO_REPORT_TIME + 1];
	char		dest_id[CMPP30_PROTO_TERMINAL + 1]; //32
	uint32_t	smsc_seq;
};
struct cmpp30_active_resp
{
	uint8_t		reserved;
};
struct cmpp30_query
{
	char		time[CMPP30_PROTO_QUERY_TIME + 1];
	uint8_t		query_type;
	char		query_code[CMPP30_PROTO_QUERY_CODE + 1];
	char		reserve[CMPP30_PROTO_RESERVE];
};
struct cmpp30_query_resp
{
	char		time[CMPP30_PROTO_QUERY_TIME + 1];
	uint8_t		query_type;
	char		query_code[CMPP30_PROTO_QUERY_CODE + 1];
	uint32_t	mt_tlmsg;
	uint32_t	mt_tlusr;
	uint32_t	mt_scs;
	uint32_t	mt_wt;
	uint32_t	mt_fl;
	uint32_t	mo_scs;
	uint32_t	mo_wt;
	uint32_t	mo_fl;
};
struct cmpp30_packet
{
	cmpp30_header	header;
	union{
		cmpp30_connect		connect;
		cmpp30_connect_resp	connect_resp;
		cmpp30_submit		submit;
		cmpp30_submit_resp	submit_resp;
		cmpp30_deliver		deliver;
		cmpp30_deliver_resp	deliver_resp;
		cmpp30_active		active;
		cmpp30_active_resp	active_resp;
		cmpp30_query		query;
		cmpp30_query_resp	query_resp;
	};
};

int cmpp30_parse_buf2pk(char buf[], size_t len, cmpp30_packet *pk);
int cmpp30_make_pk2buf(cmpp30_packet *pk, char buf[], size_t *len);
void cmpp30_print_pk(cmpp30_packet *pk);

#endif
