#include "proto_sgip.h"

static int parse_header(char buf[], size_t len, sgip_packet *pk);
static int parse_bind(char buf[], size_t len, sgip_packet *pk);
static int parse_bind_resp(char buf[], size_t len, sgip_packet *pk);
static int parse_submit(char buf[], size_t len, sgip_packet *pk);
static int parse_submit_resp(char buf[], size_t len, sgip_packet *pk);
static int parse_deliver(char buf[], size_t len, sgip_packet *pk);
static int parse_deliver_resp(char buf[], size_t len, sgip_packet *pk);
static int parse_report(char buf[], size_t len, sgip_packet *pk);
static int parse_report_resp(char buf[], size_t len, sgip_packet *pk);

static int make_header(sgip_packet *pk, char buf[], size_t *len);
static int make_bind(sgip_packet *pk, char buf[], size_t *len);
static int make_bind_resp(sgip_packet *pk, char buf[], size_t *len);
static int make_submit(sgip_packet *pk, char buf[], size_t *len);
static int make_submit_resp(sgip_packet *pk, char buf[], size_t *len);
static int make_deliver(sgip_packet *pk, char buf[], size_t *len);
static int make_deliver_resp(sgip_packet *pk, char buf[], size_t *len);
static int make_report(sgip_packet *pk, char buf[], size_t *len);
static int make_report_resp(sgip_packet *pk, char buf[], size_t *len);

/*
 * interface functions
 */
int sgip_parse_buf2pk(char buf[], size_t len, sgip_packet *pk)
{
	int		ret = 0;

	if(buf == NULL || pk == NULL)
		return EINVAL;
	if(len < SGIP_PACKET_LEN_HEADER)
		return SGIP_STAT_EMSGLEN;

	memset(pk, 0, sizeof(sgip_packet));
	ret = parse_header(buf, len, pk);
	if(ret != 0)
		return ret;
	switch(pk->header.cmd){
		case SGIP_CMD_BIND:
			ret = parse_bind(buf + SGIP_PACKET_LEN_HEADER, len - SGIP_PACKET_LEN_HEADER, pk);
			break;
		case SGIP_CMD_BIND_RESP:
			ret = parse_bind_resp(buf + SGIP_PACKET_LEN_HEADER, len - SGIP_PACKET_LEN_HEADER, pk);
			break;
		case SGIP_CMD_SUBMIT:
			ret = parse_submit(buf + SGIP_PACKET_LEN_HEADER, len - SGIP_PACKET_LEN_HEADER, pk);
			break;
		case SGIP_CMD_SUBMIT_RESP:
			ret = parse_submit_resp(buf + SGIP_PACKET_LEN_HEADER, len - SGIP_PACKET_LEN_HEADER, pk);
			break;
		case SGIP_CMD_DELIVER:
			ret = parse_deliver(buf + SGIP_PACKET_LEN_HEADER, len - SGIP_PACKET_LEN_HEADER, pk);
			break;
		case SGIP_CMD_DELIVER_RESP:
			ret = parse_deliver_resp(buf + SGIP_PACKET_LEN_HEADER, len - SGIP_PACKET_LEN_HEADER, pk);
			break;
		case SGIP_CMD_REPORT:
			ret = parse_report(buf + SGIP_PACKET_LEN_HEADER, len - SGIP_PACKET_LEN_HEADER, pk);
			break;
		case SGIP_CMD_REPORT_RESP:
			ret = parse_report_resp(buf + SGIP_PACKET_LEN_HEADER, len - SGIP_PACKET_LEN_HEADER, pk);
			break;
		default:
			ret = SGIP_STAT_EPARFMT;
	}
	return ret;
}
int sgip_make_pk2buf(sgip_packet *pk, char buf[], size_t *len)
{
	int		ret = 0;
	size_t	nhead, n = 0;

	if(pk == NULL || buf == NULL || len == NULL)
		return EINVAL;

	switch(pk->header.cmd){
		case SGIP_CMD_BIND:
			ret = make_bind(pk, buf + SGIP_PACKET_LEN_HEADER, &n);
			break;
		case SGIP_CMD_BIND_RESP:
			ret = make_bind_resp(pk, buf + SGIP_PACKET_LEN_HEADER, &n);
			break;
		case SGIP_CMD_SUBMIT:
			ret = make_submit(pk, buf + SGIP_PACKET_LEN_HEADER, &n);
			break;
		case SGIP_CMD_SUBMIT_RESP:
			ret = make_submit_resp(pk, buf + SGIP_PACKET_LEN_HEADER, &n);
			break;
		case SGIP_CMD_DELIVER:
			ret = make_deliver(pk, buf + SGIP_PACKET_LEN_HEADER, &n);
			break;
		case SGIP_CMD_DELIVER_RESP:
			ret = make_deliver_resp(pk, buf + SGIP_PACKET_LEN_HEADER, &n);
			break;
		case SGIP_CMD_REPORT:
			ret = make_report(pk, buf + SGIP_PACKET_LEN_HEADER, &n);
			break;
		case SGIP_CMD_REPORT_RESP:
			ret = make_report_resp(pk, buf + SGIP_PACKET_LEN_HEADER, &n);
			break;
		default:
			ret = SGIP_STAT_EPARFMT;
	}
	*len = SGIP_PACKET_LEN_HEADER + n;
	pk->header.len = *len;
	make_header(pk, buf, &nhead);
	return ret;
}
void sgip_print_pk(sgip_packet *pk)
{
	if(pk == NULL)
		return;
	switch(pk->header.cmd){
		case SGIP_CMD_BIND:
			printf("sgip_bind:len[%u]cmd[%#x]seq[%u][%u][%u]type[%u]name[%s]\n",
					pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3, pk->bind.type, pk->bind.name);
			break;
		case SGIP_CMD_BIND_RESP:
			printf("sgip_bind_resp:len[%u]cmd[%#x]seq[%u][%u][%u]result[%u]\n",
					pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3, pk->bind_resp.result);
			break;
		case SGIP_CMD_SUBMIT:
			printf("sgip_submit:len[%u]cmd[%#x]seq[%u][%u][%u]sp_id[%s]charge[%s]usercount[%u]user[%s]corpid[%s]service[%s]feetype[%u]feevalue[%s]givenvalue[%s]agentflag[%u]mtflag[%u]priority[%u]expire[%s]schedule[%s]reportflag[%u]tp_pid[%u]tp_udhi[%u]msgcoding[%u]msgtype[%u]msglength[%u]\n",
					pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3, 
					pk->submit.sp_id, pk->submit.charge, pk->submit.usercount, pk->submit.user[0], pk->submit.corpid,
					pk->submit.service, pk->submit.feetype, pk->submit.feevalue, pk->submit.givenvalue, pk->submit.agentflag,
					pk->submit.mtflag, pk->submit.priority, pk->submit.expire, pk->submit.schedule, pk->submit.reportflag,
					pk->submit.tp_pid, pk->submit.tp_udhi, pk->submit.msgcoding, pk->submit.msgtype, pk->submit.msglength);
			break;
		case SGIP_CMD_SUBMIT_RESP:
			printf("sgip_submit_resp:len[%u]cmd[%#x]seq[%u][%u][%u]result[%u]\n",
					pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3, pk->submit_resp.result);
			break;
		case SGIP_CMD_DELIVER:
			printf("sgip_deliver:len[%u]cmd[%#x]seq[%u][%u][%u]user[%s]sp_id[%s]tp_pid[%u]tp_udhi[%u]msgcoding[%u]msglength[%u]\n",
					pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3,
					pk->deliver.user, pk->deliver.sp_id, pk->deliver.tp_pid, pk->deliver.tp_udhi, pk->deliver.msgcoding, pk->deliver.msglength);
			break;
		case SGIP_CMD_DELIVER_RESP:
			printf("sgip_deliver_resp:len[%u]cmd[%#x]seq[%u][%u][%u]result[%u]\n",
					pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3, pk->deliver_resp.result);
			break;
		case SGIP_CMD_REPORT:
			printf("sgip_report:len[%u]cmd[%#x]seq[%u][%u][%u]reportseq[%u][%u][%u]reporttype[%u]user[%s]state[%u]errcode[%u]\n",
					pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3,
					pk->report.seq1, pk->report.seq2, pk->report.seq3, pk->report.reporttype, pk->report.user, pk->report.state, pk->report.errcode);
			break;
		case SGIP_CMD_REPORT_RESP:
			printf("sgip_report_resp:len[%u]cmd[%#x]seq[%u][%u][%u]result[%u]\n",
					pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3, pk->report_resp.result);
			break;
		default:
			printf("sgip_header:len[%u]cmd[%#x]seq[%u][%u][%u]\n", pk->header.len, pk->header.cmd, pk->header.seq1, pk->header.seq2, pk->header.seq3);
			break;
	}
}
/*
 * 1. parse pk
 */
static int parse_header(char buf[], size_t len, sgip_packet *pk)
{
	char	*p = buf;
	sgip_header	*header = &pk->header;
	uint32_t	net32;

	memcpy(&net32, p, 4);
	header->len = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	header->cmd = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	header->seq1 = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	header->seq2 = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	header->seq3 = ntohl(net32);
	p += 4;

	if(len < header->len)
		return SGIP_STAT_EMSGLEN;
	return 0;
}
static int parse_bind(char buf[], size_t len, sgip_packet *pk)
{
	char    *p = buf;
	sgip_bind    *bind = &pk->bind;

	bind->type = *p++;

	memcpy(bind->name, p, SGIP_PROTO_LOGIN_NAME);
	p += SGIP_PROTO_LOGIN_NAME;

	memcpy(bind->passwd, p, SGIP_PROTO_LOGIN_PWD);
	p += SGIP_PROTO_LOGIN_PWD;

	memcpy(bind->reserve, p, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	if(len < p-buf)
		return SGIP_STAT_EMSGLEN;
	return 0;
}
static int parse_bind_resp(char buf[], size_t len, sgip_packet *pk)
{
	char    *p = buf;
	sgip_bind_resp	*bind_resp = &pk->bind_resp;

	bind_resp->result = *p++;

	memcpy(bind_resp->reserve, p, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	if(len < p-buf)
		return SGIP_STAT_EMSGLEN;
	return 0;
}
static int parse_submit(char buf[], size_t len, sgip_packet *pk)
{
	char    *p = buf;
	sgip_submit     *submit = &pk->submit;
	uint32_t	net32;

	memcpy(submit->sp_id, p, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	memcpy(submit->charge, p, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	submit->usercount = *p++;
	if(submit->usercount < 1 || submit->usercount > SGIP_PROTO_USERCOUNT)
		return SGIP_STAT_EMSISDN;

	int		i;
	for(i=0; i<submit->usercount; i++){
		memcpy(submit->user[i], p, SGIP_PROTO_MSISDN);
		p += SGIP_PROTO_MSISDN;
	}

	memcpy(submit->corpid, p, SGIP_PROTO_CORPID);
	p += SGIP_PROTO_CORPID;

	memcpy(submit->service, p, SGIP_PROTO_SERVICE);
	p += SGIP_PROTO_SERVICE;

	submit->feetype = *p++;

	memcpy(submit->feevalue, p, SGIP_PROTO_FEEVALUE);
	p += SGIP_PROTO_FEEVALUE;

	memcpy(submit->givenvalue, p, SGIP_PROTO_GIVENVALUE);
	p += SGIP_PROTO_GIVENVALUE;

	submit->agentflag = *p++;
	submit->mtflag = *p++;
	submit->priority = *p++;

	memcpy(submit->expire, p, SGIP_PROTO_TIME);
	p += SGIP_PROTO_TIME;

	memcpy(submit->schedule, p, SGIP_PROTO_TIME);
	p += SGIP_PROTO_TIME;

	submit->reportflag = *p++;
	submit->tp_pid = *p++;
	submit->tp_udhi = *p++;
	submit->msgcoding = *p++;
	submit->msgtype = *p++;

	memcpy(&net32, p, 4);
	submit->msglength = ntohl(net32);
	p += 4;
	if(submit->msglength > SGIP_PROTO_CONTENT)
		return SGIP_STAT_ECONTENT;

	memcpy(submit->msgcontent, p, submit->msglength);
	p += submit->msglength;

	memcpy(submit->reserve, p, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	if(len < p-buf)
		return SGIP_STAT_EMSGLEN;
	return 0;
}
static int parse_submit_resp(char buf[], size_t len, sgip_packet *pk)
{
	char    *p = buf;
	sgip_submit_resp	*submit_resp = &pk->submit_resp;

	submit_resp->result = *p++;

	memcpy(submit_resp->reserve, p, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	if(len < p-buf)
		return SGIP_STAT_EMSGLEN;
	return 0;
}
static int parse_deliver(char buf[], size_t len, sgip_packet *pk)
{
	char    *p = buf;
	sgip_deliver	*deliver = &pk->deliver;
	uint32_t	net32;

	memcpy(deliver->user, p, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	memcpy(deliver->sp_id, p, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	deliver->tp_pid = *p++;
	deliver->tp_udhi = *p++;
	deliver->msgcoding = *p++;
	
	memcpy(&net32, p, 4);
	deliver->msglength = ntohl(net32);
	p += 4;
	if(deliver->msglength > SGIP_PROTO_CONTENT)
		return SGIP_STAT_ECONTENT;

	memcpy(deliver->msgcontent, p, deliver->msglength);
	p += deliver->msglength;

	memcpy(deliver->reserve, p, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	if(len < p-buf)
		return SGIP_STAT_EMSGLEN;
	return 0;
}
static int parse_deliver_resp(char buf[], size_t len, sgip_packet *pk)
{
	char    *p = buf;
	sgip_deliver_resp   *deliver_resp = &pk->deliver_resp;

	deliver_resp->result = *p++;

	memcpy(deliver_resp->reserve, p, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	if(len < p-buf)
		return SGIP_STAT_EMSGLEN;
	return 0;
}   
static int parse_report(char buf[], size_t len, sgip_packet *pk)
{
	char    *p = buf;
	sgip_report	*report = &pk->report;
	uint32_t	net32;

	memcpy(&net32, p, 4);
	report->seq1 = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	report->seq2 = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	report->seq3 = ntohl(net32);
	p += 4;

	report->reporttype = *p++;

	memcpy(report->user, p, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	report->state = *p++;
	report->errcode = *p++;

	memcpy(report->reserve, p, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	if(len < p-buf)
		return SGIP_STAT_EMSGLEN;
	return 0;
}
static int parse_report_resp(char buf[], size_t len, sgip_packet *pk)
{
	char    *p = buf;
	sgip_report_resp   *report_resp = &pk->report_resp;

	report_resp->result = *p++;

	memcpy(report_resp->reserve, p, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	if(len < p-buf)
		return SGIP_STAT_EMSGLEN;
	return 0;
}   

/*
 *	2. make pk
 */
static int make_header(sgip_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	sgip_header	*header = &pk->header;
	uint32_t	net32;

	net32 = htonl(header->len);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(header->cmd);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(header->seq1);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(header->seq2);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(header->seq3);
	memcpy(p, &net32, 4);
	p += 4;

	*len = p - buf;
	return 0;
}
static int make_bind(sgip_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	sgip_bind	*bind = &pk->bind;

	*p++ = bind->type;

	memcpy(p, bind->name, SGIP_PROTO_LOGIN_NAME);
	p += SGIP_PROTO_LOGIN_NAME;

	memcpy(p, bind->passwd, SGIP_PROTO_LOGIN_PWD);
	p += SGIP_PROTO_LOGIN_PWD;

	memcpy(p, bind->reserve, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_bind_resp(sgip_packet *pk, char buf[], size_t *len)
{
	char    *p = buf;
	sgip_bind_resp   *bind_resp = &pk->bind_resp;

	*p++ = bind_resp->result;

	memcpy(p, bind_resp->reserve, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_submit(sgip_packet *pk, char buf[], size_t *len)
{
	int		i;
	char	*p = buf;
	sgip_submit		*submit = &pk->submit;
	uint32_t	net32;

	if(submit->usercount < 1 || submit->usercount > SGIP_PROTO_USERCOUNT)
		return SGIP_STAT_EMSISDN;
	if(submit->msglength > SGIP_PROTO_CONTENT)
		return SGIP_STAT_ECONTENT;

	memcpy(p, submit->sp_id, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	memcpy(p, submit->charge, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	*p++ = submit->usercount;
	for(i=0; i<submit->usercount; i++){
		memcpy(p, submit->user[i], SGIP_PROTO_MSISDN);
		p += SGIP_PROTO_MSISDN;
	}

	memcpy(p, submit->corpid, SGIP_PROTO_CORPID);
	p += SGIP_PROTO_CORPID;

	memcpy(p, submit->service, SGIP_PROTO_SERVICE);
	p += SGIP_PROTO_SERVICE;

	*p++ = submit->feetype;

	memcpy(p, submit->feevalue, SGIP_PROTO_FEEVALUE);
	p += SGIP_PROTO_FEEVALUE;

	memcpy(p, submit->givenvalue, SGIP_PROTO_GIVENVALUE);
	p += SGIP_PROTO_GIVENVALUE;

	*p++ = submit->agentflag;
	*p++ = submit->mtflag;
	*p++ = submit->priority;

	memcpy(p, submit->expire, SGIP_PROTO_TIME);
	p += SGIP_PROTO_TIME;

	memcpy(p, submit->schedule, SGIP_PROTO_TIME);
	p += SGIP_PROTO_TIME;

	*p++ = submit->reportflag;
	*p++ = submit->tp_pid;
	*p++ = submit->tp_udhi;
	*p++ = submit->msgcoding;
	*p++ = submit->msgtype;
	
	net32 = htonl(submit->msglength);
	memcpy(p, &net32, 4);
	p += 4;

	memcpy(p, submit->msgcontent, submit->msglength);
	p += submit->msglength;

	memcpy(p, submit->reserve, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_submit_resp(sgip_packet *pk, char buf[], size_t *len)
{
	char    *p = buf;
	sgip_submit_resp    *submit_resp = &pk->submit_resp;

	*p++ = submit_resp->result;

	memcpy(p, submit_resp->reserve, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_deliver(sgip_packet *pk, char buf[], size_t *len)
{
	char    *p = buf;
	sgip_deliver	*deliver = &pk->deliver;
	uint32_t	net32;

	if(deliver->msglength > SGIP_PROTO_CONTENT)
		return SGIP_STAT_ECONTENT;

	memcpy(p, deliver->user, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	memcpy(p, deliver->sp_id, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	*p++ = deliver->tp_pid;
	*p++ = deliver->tp_udhi;
	*p++ = deliver->msgcoding;
	
	net32 = htonl(deliver->msglength);
	memcpy(p, &net32, 4);
	p += 4;


	memcpy(p, deliver->msgcontent, deliver->msglength);
	p += deliver->msglength;

	memcpy(p, deliver->reserve, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_deliver_resp(sgip_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	sgip_deliver_resp	*deliver_resp = &pk->deliver_resp;

	*p++ = deliver_resp->result;

	memcpy(p, deliver_resp->reserve, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_report(sgip_packet *pk, char buf[], size_t *len)
{
	char    *p = buf;
	sgip_report	*report = &pk->report;
	uint32_t	net32;

	net32 = htonl(report->seq1);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(report->seq2);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(report->seq3);
	memcpy(p, &net32, 4);
	p += 4;

	*p++ = report->reporttype;

	memcpy(p, report->user, SGIP_PROTO_MSISDN);
	p += SGIP_PROTO_MSISDN;

	*p++ = report->state;
	*p++ = report->errcode;

	memcpy(p, report->reserve, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_report_resp(sgip_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	sgip_report_resp	*report_resp = &pk->report_resp;

	*p++ = report_resp->result;

	memcpy(p, report_resp->reserve, SGIP_PROTO_RESERVE);
	p += SGIP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
