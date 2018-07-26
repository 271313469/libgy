#ifndef PROTO_SGIP_H
#define PROTO_SGIP_H

#include "util_common.h"

/*
 * CMD_ID
 */
#define SGIP_CMD_BIND				0x1
#define SGIP_CMD_BIND_RESP			0x80000001
#define SGIP_CMD_UNBIND				0x2
#define SGIP_CMD_UNBIND_RESP		0x80000002
#define SGIP_CMD_SUBMIT				0x3
#define SGIP_CMD_SUBMIT_RESP		0x80000003
#define SGIP_CMD_DELIVER			0x4
#define SGIP_CMD_DELIVER_RESP		0x80000004
#define SGIP_CMD_REPORT				0x5
#define SGIP_CMD_REPORT_RESP		0x80000005

/*
 * PROTO_LEN
 */
#define SGIP_PROTO_LOGIN_NAME	16
#define SGIP_PROTO_LOGIN_PWD	16
#define SGIP_PROTO_RESERVE		8
#define SGIP_PROTO_MSISDN		21
#define SGIP_PROTO_USERCOUNT	100
#define SGIP_PROTO_CORPID		5
#define SGIP_PROTO_SERVICE		10
#define SGIP_PROTO_FEEVALUE		6
#define SGIP_PROTO_GIVENVALUE	6
#define SGIP_PROTO_TIME			16
#define SGIP_PROTO_CONTENT		160

/*
 * ERR_CODE
 */
#define SGIP_STAT_SUCESS		0
#define SGIP_STAT_ELOGIN		1
#define SGIP_STAT_ERELOG		2
#define SGIP_STAT_EMCONN		3
#define SGIP_STAT_ELOGTYPE		4
#define SGIP_STAT_EPARFMT		5
#define SGIP_STAT_EMSISDN		6
#define SGIP_STAT_EMSGID		7
#define SGIP_STAT_EMSGLEN		8
#define SGIP_STAT_EMSGSEQ		9
#define SGIP_STAT_EGNS			10
#define SGIP_STAT_EBUSY			11
#define SGIP_STAT_ECONTENT		12
#define SGIP_STAT_EDST			21
#define SGIP_STAT_EROUTE		22
#define SGIP_STAT_EROUNO		23
#define SGIP_STAT_EFEE			24
#define SGIP_STAT_EUSERCON		25
#define SGIP_STAT_EUSERMEM		26
#define SGIP_STAT_EUSERSM		27
#define SGIP_STAT_EUSERRCV		28
#define SGIP_STAT_EUSERNO		29
#define SGIP_STAT_EINVAL		30
#define SGIP_STAT_EILLEGAL		31
#define SGIP_STAT_ESYS			32
#define SGIP_STAT_ESMSC			33

/*
 *  * BUSI
 *   */
#define SGIP_PACKET_LEN_MAX				2403
#define SGIP_PACKET_LEN_HEADER			20
#define SGIP_PACKET_LEN_BIND			61
#define SGIP_PACKET_LEN_BIND_RESP		29
#define SGIP_PACKET_LEN_SUBMIT			324
#define SGIP_PACKET_LEN_SUBMIT_RESP		29
#define SGIP_PACKET_LEN_DELIVER			237
#define SGIP_PACKET_LEN_DELIVER_RESP	29
#define SGIP_PACKET_LEN_REPORT			64
#define SGIP_PACKET_LEN_REPORT_RESP		29

/*
 * STRUCT
 */
typedef struct sgip_header			sgip_header;
typedef struct sgip_bind			sgip_bind;
typedef struct sgip_bind_resp		sgip_bind_resp;
typedef struct sgip_submit			sgip_submit;
typedef struct sgip_submit_resp		sgip_submit_resp;
typedef struct sgip_deliver			sgip_deliver;
typedef struct sgip_deliver_resp	sgip_deliver_resp;
typedef struct sgip_report			sgip_report;
typedef struct sgip_report_resp		sgip_report_resp;
typedef struct sgip_packet			sgip_packet;

struct sgip_header
{
	uint32_t	len;
	uint32_t	cmd;
	uint32_t	seq1;
	uint32_t	seq2;
	uint32_t	seq3;
};
struct sgip_bind
{
	uint8_t		type;
	char		name[SGIP_PROTO_LOGIN_NAME + 1];
	char		passwd[SGIP_PROTO_LOGIN_PWD + 1];
	char		reserve[SGIP_PROTO_RESERVE];
};
struct sgip_bind_resp
{
	uint8_t		result;
	char		reserve[SGIP_PROTO_RESERVE];
};
struct sgip_submit
{
	char		sp_id[SGIP_PROTO_MSISDN + 1];
	char		charge[SGIP_PROTO_MSISDN + 1];
	uint8_t		usercount;
	char		user[SGIP_PROTO_USERCOUNT][SGIP_PROTO_MSISDN + 1];
	char		corpid[SGIP_PROTO_CORPID + 1];
	char		service[SGIP_PROTO_SERVICE + 1];
	uint8_t		feetype;
	char		feevalue[SGIP_PROTO_FEEVALUE + 1];
	char		givenvalue[SGIP_PROTO_GIVENVALUE + 1];
	uint8_t		agentflag;
	uint8_t		mtflag;
	uint8_t		priority;
	char		expire[SGIP_PROTO_TIME + 1];
	char		schedule[SGIP_PROTO_TIME + 1];
	uint8_t		reportflag;
	uint8_t		tp_pid;
	uint8_t		tp_udhi;
	uint8_t		msgcoding;
	uint8_t		msgtype;
	uint32_t	msglength;
	char		msgcontent[SGIP_PROTO_CONTENT];
	char		reserve[SGIP_PROTO_RESERVE];
};
struct sgip_submit_resp
{
	uint8_t		result;
	char		reserve[SGIP_PROTO_RESERVE];
};
struct sgip_deliver
{
	char		user[SGIP_PROTO_MSISDN + 1];
	char		sp_id[SGIP_PROTO_MSISDN + 1];
	uint8_t		tp_pid;
	uint8_t		tp_udhi;
	uint8_t		msgcoding;
	uint32_t	msglength;
	char		msgcontent[SGIP_PROTO_CONTENT];
	char		reserve[SGIP_PROTO_RESERVE];
};
struct sgip_deliver_resp
{
	uint8_t		result;
	char		reserve[SGIP_PROTO_RESERVE];
};
struct sgip_report
{
	uint32_t	seq1;
	uint32_t	seq2;
	uint32_t	seq3;
	uint8_t		reporttype;
	char		user[SGIP_PROTO_MSISDN + 1];
	uint8_t		state;
	uint8_t		errcode;
	char		reserve[SGIP_PROTO_RESERVE];
};
struct sgip_report_resp
{
	uint8_t		result;
	char		reserve[SGIP_PROTO_RESERVE];
};
struct sgip_packet
{
	sgip_header				header;
	union {
		sgip_bind			bind;
		sgip_bind_resp		bind_resp;
		sgip_submit			submit;
		sgip_submit_resp	submit_resp;
		sgip_deliver		deliver;
		sgip_deliver_resp	deliver_resp;
		sgip_report			report;
		sgip_report_resp	report_resp;
	};
};

int sgip_parse_buf2pk(char buf[], size_t len, sgip_packet *pk);
int sgip_make_pk2buf(sgip_packet *pk, char buf[], size_t *len);
void sgip_print_pk(sgip_packet *pk);

#endif
