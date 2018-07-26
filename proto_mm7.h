#ifndef PROTO_MM7_H
#define PROTO_MM7_H

#include "util_common.h"
#include "libxml/xmlmemory.h"
#include "libxml/parser.h"
#include "libxml/tree.h"

/*
 * CMD_ID
 */
#define MM7_MSGTYPE_SUBMIT_REQ		"SubmitReq"
#define MM7_MSGTYPE_SUBMIT_RESP		"SubmitRsp"
#define MM7_MSGTYPE_DELIVER_REQ		"DeliverReq"                              
#define MM7_MSGTYPE_DELIVER_RESP	"DeliverRsp" 
#define MM7_MSGTYPE_REPORT_REQ		"DeliveryReportReq"
#define MM7_MSGTYPE_REPORT_RESP		"DeliveryReportRsp"
#define MM7_MSGTYPE_READREPLY_REQ	"ReadReplyReq"
#define MM7_MSGTYPE_READREPLY_RESP	"ReadReplyRsp"

#define MM7_CMD_SUBMIT_REQ		0X00000001
#define MM7_CMD_SUBMIT_RESP		0X80000001
#define MM7_CMD_DELIVER_REQ		0X00000002
#define MM7_CMD_DELIVER_RESP	0X80000002
#define MM7_CMD_REPORT_REQ		0X00000003
#define MM7_CMD_REPORT_RESP		0X80000003
#define MM7_CMD_READREPLY_REQ	0X00000004
#define MM7_CMD_READREPLY_RESP	0X80000004

/*
 * PROTO_LEN
 */
#define	MM7_PROTO_VASPID		21
#define	MM7_PROTO_VASID			21
#define	MM7_PROTO_USERADDR		32
#define	MM7_PROTO_RECV_MAX		1
#define	MM7_PROTO_SERVICE		20
#define	MM7_PROTO_LINKEDID		20
#define	MM7_PROTO_MSGCLASS		20
#define	MM7_PROTO_TIMESTAMP		25
#define MM7_PROTO_REPORT		5
#define MM7_PROTO_READREPLY		5
#define MM7_PROTO_READCHARG		5
#define MM7_PROTO_PRIORITY		16
#define	MM7_PROTO_SUBJECT		128
#define	MM7_PROTO_ADAPTATIONS	5
#define	MM7_PROTO_INDICATOR		5
#define	MM7_PROTO_REQUEST_LINE	128
#define	MM7_PROTO_HOST			32
#define	MM7_PROTO_CONTENT_TYPE	128
#define	MM7_PROTO_BOUNDARY_PART	128
#define	MM7_PROTO_HREF			128
#define	MM7_PROTO_MSGID			64
#define MM7_PROTO_STATUS		32
#define MM7_PROTO_STATUS_TEXT	32
#define MM7_PROTO_DETAIL		32
#define MM7_PROTO_SERVER_ID		32
#define MM7_PROTO_TRANS_ID		32
#define MM7_PROTO_MSGTYPE		17
#define MM7_PROTO_VERSION		8

/*
 * ERR_CODE
 */
#define MM7_STAT_SUCCESS		1000
#define MM7_STAT_EPARTIAL		1100
#define MM7_STAT_ECLIENT		2000
#define MM7_STAT_ERESTRICT		2001
#define MM7_STAT_EADDRESS		2002
#define MM7_STAT_EADDR_NOTF		2003
#define MM7_STAT_ECONT_REJECT	2004
#define MM7_STAT_EMSGID_NOTF	2005
#define MM7_STAT_ELINKID_NOTF	2006
#define MM7_STAT_EMSG_FORMAT	2007
#define MM7_STAT_ESERVER		3000
#define MM7_STAT_ENOT_ACCEPT	3001
#define MM7_STAT_EMSG_REJECT	3002
#define MM7_STAT_EMULTIADDR		3003
#define MM7_STAT_EGEN_SERVICE	4000
#define MM7_STAT_EID			4001
#define MM7_STAT_EVERSION		4002
#define MM7_STAT_EOPERATER		4003
#define MM7_STAT_ECHECK			4004
#define MM7_STAT_ESERVICE		4005
#define MM7_STAT_EAVAILABLE		4006
#define MM7_STAT_ESVC_REJECT	4007

#define MM7_STAT_ECONTENT_LEN	5000
#define MM7_STAT_EPACKET_LEN	5001
#define MM7_STAT_EREQUEST_LINE	5002
#define MM7_STAT_EHOST			5003
#define MM7_STAT_ECONTENT_TYPE	5004
#define MM7_STAT_EAUTH			5005
#define MM7_STAT_EXML_FORMAT	5010
#define MM7_STAT_ETransactionID	5011
#define MM7_STAT_EMsgType		5012
#define MM7_STAT_EVersion		5013
#define MM7_STAT_EVASPID		5020
#define MM7_STAT_EVASID			5021
#define MM7_STAT_ESender		5022
#define MM7_STAT_ERecipient		5023
#define MM7_STAT_EServiceCode	5024
#define MM7_STAT_EStatusCode	5025
#define MM7_STAT_EStatus		5026

/*
 * BUSI
 */
#define MM7_PACKET_LEN_MAX		1600000

#define MM7_CODING_US_ASCII			"US-ASCII"
#define MM7_CODING_ISO8859_1		"ISO-8859-1"
#define MM7_CODING_ISO8859_2		"ISO-8859-2"
#define MM7_CODING_ISO10646_UCS2	"ISO-10646-UCS-2"
#define MM7_CODING_UTF8				"UTF-8"
#define MM7_CODING_GBK				"GBK"
#define MM7_CODING_GB2312			"GB2312"

/*
 * STRUCT
 */
typedef struct mm7_submit_req		mm7_submit_req;
typedef struct mm7_submit_resp		mm7_submit_resp;
typedef struct mm7_deliver_req		mm7_deliver_req;
typedef struct mm7_deliver_resp		mm7_deliver_resp;
typedef struct mm7_report_req		mm7_report_req;
typedef struct mm7_report_resp		mm7_report_resp;
typedef struct mm7_readreply_req	mm7_readreply_req;
typedef struct mm7_readreply_resp	mm7_readreply_resp;
typedef struct mm7_packet			mm7_packet;

struct mm7_submit_req
{
	char	version[MM7_PROTO_VERSION + 1]; //required
	char	vaspid[MM7_PROTO_VASPID + 1]; //required
	char	vasid[MM7_PROTO_VASID + 1]; //required
	char	sender[MM7_PROTO_USERADDR + 1];
	uint8_t	rec_count;
	char	recipient[MM7_PROTO_RECV_MAX][MM7_PROTO_USERADDR + 1]; //required
	char	service[MM7_PROTO_SERVICE + 1]; //required
	char	linked_id[MM7_PROTO_LINKEDID + 1];
	char	msg_class[MM7_PROTO_MSGCLASS + 1];
	char	timestamp[MM7_PROTO_TIMESTAMP + 1];
	char	expiry_date[MM7_PROTO_TIMESTAMP + 1];
	char	delivery_time[MM7_PROTO_TIMESTAMP + 1];
	char	delivery_report[MM7_PROTO_REPORT + 1];
	char	read_reply[MM7_PROTO_READREPLY + 1];
	uint8_t	reply_charging;
	uint32_t	reply_chargsize;
	char	reply_deadline[MM7_PROTO_TIMESTAMP + 1];
	char	priority[MM7_PROTO_PRIORITY + 1];
	char	subject[MM7_PROTO_SUBJECT + 1];
	char	charged_party[MM7_PROTO_USERADDR + 1];
	char	charged_party_id[MM7_PROTO_USERADDR + 1];
	char	indicator[MM7_PROTO_INDICATOR + 1];
	char	adaptations[MM7_PROTO_ADAPTATIONS + 1];
	char	href[MM7_PROTO_HREF + 1];
};
struct mm7_submit_resp
{
	char	version[MM7_PROTO_VERSION + 1]; //required
	char	msgid[MM7_PROTO_MSGID + 1]; //if success, required
	uint32_t	status_code; //required
	char	status_text[MM7_PROTO_STATUS_TEXT + 1];
};
struct mm7_deliver_req
{
	char	version[MM7_PROTO_VERSION + 1]; //required
	char	server_id[MM7_PROTO_SERVER_ID + 1];
	char	linked_id[MM7_PROTO_LINKEDID + 1];
	char	sender[MM7_PROTO_USERADDR + 1]; //required
	char	recipient[MM7_PROTO_USERADDR + 1];
	char	timestamp[MM7_PROTO_TIMESTAMP + 1];
	char	reply_charging_id[MM7_PROTO_USERADDR + 1];
	char	priority[MM7_PROTO_PRIORITY + 1];
	char	subject[MM7_PROTO_SUBJECT + 1];
	char	href[MM7_PROTO_HREF + 1];
};
struct mm7_deliver_resp
{
	char	version[MM7_PROTO_VERSION + 1]; //required
	char	service[MM7_PROTO_SERVICE + 1];
	uint32_t	status_code; //required
	char	status_text[MM7_PROTO_STATUS_TEXT + 1];
};
struct mm7_report_req
{
	char	version[MM7_PROTO_VERSION + 1]; //required
	char	server_id[MM7_PROTO_SERVER_ID + 1];
	char	msgid[MM7_PROTO_MSGID + 1]; //required
	char	recipient[MM7_PROTO_USERADDR + 1]; //required
	char	sender[MM7_PROTO_USERADDR + 1]; //required
	char	timestamp[MM7_PROTO_TIMESTAMP + 1]; //required
	char	status[MM7_PROTO_STATUS + 1]; //required
	char	status_ex[MM7_PROTO_STATUS_TEXT + 1];
	char	status_text[MM7_PROTO_STATUS_TEXT + 1];
};
struct mm7_report_resp
{
	char	version[MM7_PROTO_VERSION + 1]; //required
	uint32_t	status_code; //required
	char	status_text[MM7_PROTO_STATUS_TEXT + 1];
};
struct mm7_readreply_req
{
	char	version[MM7_PROTO_VERSION + 1]; //required
	char	server_id[MM7_PROTO_SERVER_ID + 1];
	char	recipient[MM7_PROTO_USERADDR + 1]; //required
	char	sender[MM7_PROTO_USERADDR + 1]; //required
	char	msgid[MM7_PROTO_MSGID + 1]; //required
	char	timestamp[MM7_PROTO_TIMESTAMP + 1]; //required
	char	status[MM7_PROTO_STATUS + 1]; //required
	char	status_text[MM7_PROTO_STATUS_TEXT + 1];
};
struct mm7_readreply_resp
{
	char	version[MM7_PROTO_VERSION + 1]; //required
	uint32_t	status_code; //required
	char	status_text[MM7_PROTO_STATUS_TEXT + 1];
};
struct mm7_packet
{
	uint32_t	cmd;
	uint32_t	content_len;
	uint32_t	header_len;
	char	request_line[MM7_PROTO_REQUEST_LINE + 1];
	char	host[MM7_PROTO_HOST + 1];
	char	content_type[MM7_PROTO_CONTENT_TYPE + 1];
	char	boundary_part[MM7_PROTO_BOUNDARY_PART + 1];
	char	transactionid[MM7_PROTO_TRANS_ID + 1];
	union{
		mm7_submit_req		submit_req;
		mm7_submit_resp		submit_resp;
		mm7_deliver_req		deliver_req;
		mm7_deliver_resp	deliver_resp;
		mm7_report_req		report_req;
		mm7_report_resp		report_resp;
		mm7_readreply_req	readreply_req;
		mm7_readreply_resp	readreply_resp;
	};
	uint32_t	attachment_len;
	char	*attachment;
};

typedef struct mm7_trans	mm7_trans;
struct mm7_trans
{
	int		sockfd;
	char	status; //0:unlogin 1:login
	char	isauth; //0:none 1:Basic 2:Digest
	uint32_t	timeout;
	uint16_t	port;
	char	ip[16];
	char	authinfo[256];
	size_t	buf_len; //default MM7_PACKET_LEN_MAX
	char	*buffer; //temp buf
};

int mm7_proto_recv(mm7_trans *trans, mm7_packet *pk);
int mm7_proto_send(mm7_trans *trans, mm7_packet *pk);
int mm7_proto_parse_buf2pk(char *buf, size_t buf_len, mm7_packet *pk);
int mm7_proto_make_pk2buf(mm7_packet *pk, char *buf, size_t *buf_len);
int mm7_trans_init(mm7_trans *trans);
void mm7_trans_destroy(mm7_trans *trans);
void mm7_print_pk(mm7_packet *pk);

#endif
