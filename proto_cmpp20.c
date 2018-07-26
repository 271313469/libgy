#include "proto_cmpp20.h"

static int parse_header(char buf[], size_t len, cmpp20_packet *pk);
static int parse_connect(char buf[], size_t len, cmpp20_packet *pk);
static int parse_connect_resp(char buf[], size_t len, cmpp20_packet *pk);
static int parse_submit(char buf[], size_t len, cmpp20_packet *pk);
static int parse_submit_resp(char buf[], size_t len, cmpp20_packet *pk);
static int parse_deliver(char buf[], size_t len, cmpp20_packet *pk);
static int parse_deliver_resp(char buf[], size_t len, cmpp20_packet *pk);

static int make_header(cmpp20_packet *pk, char buf[], size_t *len);
static int make_connect(cmpp20_packet *pk, char buf[], size_t *len);
static int make_connect_resp(cmpp20_packet *pk, char buf[], size_t *len);
static int make_submit(cmpp20_packet *pk, char buf[], size_t *len);
static int make_submit_resp(cmpp20_packet *pk, char buf[], size_t *len);
static int make_deliver(cmpp20_packet *pk, char buf[], size_t *len);
static int make_deliver_resp(cmpp20_packet *pk, char buf[], size_t *len);


/*
 * interface functions
 */
int cmpp20_parse_buf2pk(char buf[], size_t len, cmpp20_packet *pk)
{
	int		ret = 0;

	if(buf == NULL || pk == NULL)
		return EINVAL;
	if(len < CMPP20_PACKET_LEN_HEADER)
		return CMPP20_STAT_SP_ELEN;

	memset(pk, 0, sizeof(cmpp20_packet));
	ret = parse_header(buf, len, pk);
	if(ret != 0)
		return ret;
	switch(pk->header.cmd){
		case CMPP20_CMD_CONNECT:
			ret = parse_connect(buf + CMPP20_PACKET_LEN_HEADER, len - CMPP20_PACKET_LEN_HEADER, pk);
			break;
		case CMPP20_CMD_CONNECT_RESP:
			ret = parse_connect_resp(buf + CMPP20_PACKET_LEN_HEADER, len - CMPP20_PACKET_LEN_HEADER, pk);
			break;
		case CMPP20_CMD_SUBMIT:
			ret = parse_submit(buf + CMPP20_PACKET_LEN_HEADER, len - CMPP20_PACKET_LEN_HEADER, pk);
			break;
		case CMPP20_CMD_SUBMIT_RESP:
			ret = parse_submit_resp(buf + CMPP20_PACKET_LEN_HEADER, len - CMPP20_PACKET_LEN_HEADER, pk);
			break;
		case CMPP20_CMD_DELIVER:
			ret = parse_deliver(buf + CMPP20_PACKET_LEN_HEADER, len - CMPP20_PACKET_LEN_HEADER, pk);
			break;
		case CMPP20_CMD_DELIVER_RESP:
			ret = parse_deliver_resp(buf + CMPP20_PACKET_LEN_HEADER, len - CMPP20_PACKET_LEN_HEADER, pk);
			break;
		case CMPP20_CMD_ACTIVE:
			break;
		case CMPP20_CMD_ACTIVE_RESP:
			break;
		default:
			ret = CMPP20_STAT_SP_ECMD;
	}
	return ret;
}
int cmpp20_make_pk2buf(cmpp20_packet *pk, char buf[], size_t *len)
{
	int		ret = 0;
	size_t	nhead, n = 0;

	if(pk == NULL || buf == NULL || len == NULL)
		return EINVAL;

	switch(pk->header.cmd){
		case CMPP20_CMD_CONNECT:
			ret = make_connect(pk, buf + CMPP20_PACKET_LEN_HEADER, &n);
			break;
		case CMPP20_CMD_CONNECT_RESP:
			ret = make_connect_resp(pk, buf + CMPP20_PACKET_LEN_HEADER, &n);
			break;
		case CMPP20_CMD_SUBMIT:
			ret = make_submit(pk, buf + CMPP20_PACKET_LEN_HEADER, &n);
			break;
		case CMPP20_CMD_SUBMIT_RESP:
			ret = make_submit_resp(pk, buf + CMPP20_PACKET_LEN_HEADER, &n);
			break;
		case CMPP20_CMD_DELIVER:
			ret = make_deliver(pk, buf + CMPP20_PACKET_LEN_HEADER, &n);
			break;
		case CMPP20_CMD_DELIVER_RESP:
			ret = make_deliver_resp(pk, buf + CMPP20_PACKET_LEN_HEADER, &n);
			break;
		case CMPP20_CMD_ACTIVE:
			break;
		case CMPP20_CMD_ACTIVE_RESP:
			buf[CMPP20_PACKET_LEN_HEADER] = 0;
			n = 1;
			break;
		default:
			ret = CMPP20_STAT_SP_ECMD;
	}
	*len = CMPP20_PACKET_LEN_HEADER + n;
	pk->header.len = *len;
	make_header(pk, buf, &nhead);
	return ret;
}
void cmpp20_print_pk(cmpp20_packet *pk)
{
	if(pk == NULL)
		return;
	switch(pk->header.cmd){
		case CMPP20_CMD_CONNECT:
			printf("cmpp20_connect:len[%u]cmd[%#x]seq[%u]source[%s]auth[]version[%#x]timestamp[%u]\n",
					pk->header.len,pk->header.cmd,pk->header.seq,pk->connect.source,pk->connect.version,pk->connect.timestamp);
			break;
		case CMPP20_CMD_CONNECT_RESP:
			printf("cmpp20_connect_resp:len[%u]cmd[%#x]seq[%u]status[%u]auth[]version[%#x]\n",
					pk->header.len,pk->header.cmd,pk->header.seq,pk->connect_resp.status,pk->connect_resp.version);
			break;
		case CMPP20_CMD_SUBMIT:
			printf("cmpp20_submit:len[%u]cmd[%#x]seq[%u]msgid[%lu]pk_total[%u]pk_number[%u]reg_delivery[%u]msg_level[%u]service_id[%s]fee_usertype[%u]fee_id[%s]tp_pid[%u]tp_udhi[%u]msg_fmt[%u]msg_src[%s]feetype[%s]feecode[%s]valid_time[%s]at_time[%s]src_id[%s]destusr_tl[%u]dest_id[%s]msg_length[%u]\n",
					pk->header.len,pk->header.cmd,pk->header.seq,pk->submit.msg_id,pk->submit.pk_total,pk->submit.pk_number,pk->submit.reg_delivery,pk->submit.msg_level,
					pk->submit.service_id,pk->submit.fee_usertype,pk->submit.fee_id,pk->submit.tp_pid,pk->submit.tp_udhi,
					pk->submit.msg_fmt,pk->submit.msg_src,pk->submit.feetype,pk->submit.feecode,pk->submit.valid_time,
					pk->submit.at_time,pk->submit.src_id,pk->submit.destusr_tl,pk->submit.dest_id[0],pk->submit.msg_length);
			break;
		case CMPP20_CMD_SUBMIT_RESP:
			printf("cmpp20_submit_resp:len[%u]cmd[%#x]seq[%u]msgid[%lu]result[%u]\n",
					pk->header.len,pk->header.cmd,pk->header.seq,pk->submit_resp.msg_id,pk->submit_resp.result);
			break;
		case CMPP20_CMD_DELIVER:
			printf("cmpp20_deliver:len[%u]cmd[%#x]seq[%u]msgid[%lu]dest_id[%s]service_id[%s]tp_pid[%u]tp_udhi[%u]msg_fmt[%u]src_id[%s]reg_delivery[%u]msg_length[%u]\n",
					pk->header.len,pk->header.cmd,pk->header.seq,pk->deliver.msg_id,pk->deliver.dest_id,pk->deliver.service_id,pk->deliver.tp_pid,pk->deliver.tp_udhi,
					pk->deliver.msg_fmt,pk->deliver.src_id,pk->deliver.reg_delivery,pk->deliver.msg_length);
			break;
		case CMPP20_CMD_DELIVER_RESP:
			printf("cmpp20_deliver_resp:len[%u]cmd[%#x]seq[%u]msgid[%lu]result[%u]\n",
					pk->header.len,pk->header.cmd,pk->header.seq,pk->deliver_resp.msg_id,pk->deliver_resp.result);
			break;
		case CMPP20_CMD_ACTIVE:
			printf("cmpp20_active:len[%u]cmd[%#x]seq[%u]\n", pk->header.len,pk->header.cmd,pk->header.seq);
			break;
		case CMPP20_CMD_ACTIVE_RESP:
			printf("cmpp20_active_resp:len[%u]cmd[%#x]seq[%u]\n", pk->header.len,pk->header.cmd,pk->header.seq);
			break;
		default:
			printf("cmpp20_header:len[%u]cmd[%#x]seq[%u]\n", pk->header.len,pk->header.cmd,pk->header.seq);
			break;
	}
}

/*
 * parse pk
 */
static int parse_header(char buf[], size_t len, cmpp20_packet *pk)
{
	char	*p = buf;
	cmpp20_header	*header = &pk->header;
	uint32_t	net32;

	memcpy(&net32, p, 4);
	header->len = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	header->cmd = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	header->seq = ntohl(net32);

	if(len < header->len)
		return CMPP20_STAT_SP_ELEN;
	return 0;
}
static int parse_connect(char buf[], size_t len, cmpp20_packet *pk)
{
	char    *p = buf;
	cmpp20_connect    *connect = &pk->connect;
	uint32_t	net32;

	memcpy(connect->source, p, CMPP20_PROTO_SP_ID);
	p += CMPP20_PROTO_SP_ID;

	memcpy(connect->auth, p, CMPP20_PROTO_ATUH);
	p += CMPP20_PROTO_ATUH;

	connect->version = *p++;

	memcpy(&net32, p, 4);
	connect->timestamp = ntohl(net32);
	p += 4;

	if(len < p-buf)
		return CMPP20_STAT_SP_ELEN;
	return 0;
}
static int parse_connect_resp(char buf[], size_t len, cmpp20_packet *pk)
{
	char    *p = buf;
	cmpp20_connect_resp	*connect_resp = &pk->connect_resp;

	connect_resp->status = *p++;

	memcpy(connect_resp->auth, p, CMPP20_PROTO_ATUH);
	p += CMPP20_PROTO_ATUH;

	connect_resp->version = *p++;

	if(len < p-buf)
		return CMPP20_STAT_SP_ELEN;
	return 0;
}
static int parse_submit(char buf[], size_t len, cmpp20_packet *pk)
{
	char    *p = buf;
	cmpp20_submit     *submit = &pk->submit;
	uint64_t	net64;

	memcpy(&net64, p, 8);
	submit->msg_id = be64toh(net64);
	p += 8;

	submit->pk_total = *p++;
	submit->pk_number = *p++;
	submit->reg_delivery = *p++;
	submit->msg_level = *p++;

	memcpy(submit->service_id, p, CMPP20_PROTO_SERVICE);
	p += CMPP20_PROTO_SERVICE;

	submit->fee_usertype = *p++;

	memcpy(submit->fee_id, p, CMPP20_PROTO_MSISDN);
	p += CMPP20_PROTO_MSISDN;

	submit->tp_pid = *p++;
	submit->tp_udhi = *p++;
	submit->msg_fmt = *p++;

	memcpy(submit->msg_src, p, CMPP20_PROTO_SP_ID);
	p += CMPP20_PROTO_SP_ID;

	memcpy(submit->feetype, p, CMPP20_PROTO_FEETYPE);
	p += CMPP20_PROTO_FEETYPE; 

	memcpy(submit->feecode, p, CMPP20_PROTO_FEECODE);
	p += CMPP20_PROTO_FEECODE; 

	memcpy(submit->valid_time, p, CMPP20_PROTO_TIME);
	p += CMPP20_PROTO_TIME;

	memcpy(submit->at_time, p, CMPP20_PROTO_TIME);
	p += CMPP20_PROTO_TIME;

	memcpy(submit->src_id, p, CMPP20_PROTO_MSISDN);
	p += CMPP20_PROTO_MSISDN; 

	submit->destusr_tl = *p++;
	if(submit->destusr_tl < 1 || submit->destusr_tl > CMPP20_PROTO_DESTUSERTL)
		return CMPP20_STAT_SP_EDEST_ID;
	int		i;
	for(i=0; i<submit->destusr_tl; i++){
		memcpy(submit->dest_id[i], p, CMPP20_PROTO_MSISDN);
		p += CMPP20_PROTO_MSISDN;
	}

	submit->msg_length = *p++;
	if(submit->msg_length > CMPP20_PROTO_CONTENT)
		return CMPP20_STAT_SP_ECONTENT;

	memcpy(submit->msg_content, p, submit->msg_length);
	p += submit->msg_length;

	memcpy(submit->reserve, p, CMPP20_PROTO_RESERVE);
	p += CMPP20_PROTO_RESERVE;

	if(len < p-buf)
		return CMPP20_STAT_SP_ELEN;
	return 0;
}
static int parse_submit_resp(char buf[], size_t len, cmpp20_packet *pk)
{
	char    *p = buf;
	cmpp20_submit_resp	*submit_resp = &pk->submit_resp;
	uint64_t	net64;

	memcpy(&net64, p, 8);
	submit_resp->msg_id = be64toh(net64);
	p += 8;

	submit_resp->result = *p++;

	if(len < p-buf)
		return CMPP20_STAT_SP_ELEN;
	return 0;
}
static int parse_deliver(char buf[], size_t len, cmpp20_packet *pk)
{
	char    *p = buf;
	cmpp20_deliver	*deliver = &pk->deliver;
	cmpp20_report	report;
	uint64_t	net64;
	uint32_t	net32;

	memcpy(&net64, p, 8);
	deliver->msg_id = be64toh(net64);
	p += 8;

	memcpy(deliver->dest_id, p, CMPP20_PROTO_MSISDN);
	p += CMPP20_PROTO_MSISDN;

	memcpy(deliver->service_id, p, CMPP20_PROTO_SERVICE);
	p += CMPP20_PROTO_SERVICE;

	deliver->tp_pid = *p++;
	deliver->tp_udhi = *p++;
	deliver->msg_fmt = *p++;

	memcpy(deliver->src_id, p, CMPP20_PROTO_MSISDN);
	p += CMPP20_PROTO_MSISDN;

	deliver->reg_delivery = *p++; 
	deliver->msg_length = *p++;
	if(deliver->msg_length > CMPP20_PROTO_CONTENT)
		return CMPP20_STAT_SP_ECONTENT;

	if(deliver->reg_delivery == 0){
		memcpy(deliver->msg_content, p, deliver->msg_length);
		p += deliver->msg_length;
	}else{
		memcpy(&net64, p, 8);
		report.msg_id = be64toh(net64);
		p += 8;

		memcpy(report.stat, p, CMPP20_PROTO_REPORT_STAT);
		p += CMPP20_PROTO_REPORT_STAT;

		memcpy(report.submit_time, p, CMPP20_PROTO_REPORT_TIME);
		p += CMPP20_PROTO_REPORT_TIME;

		memcpy(report.done_time, p, CMPP20_PROTO_REPORT_TIME);
		p += CMPP20_PROTO_REPORT_TIME;

		memcpy(report.dest_id, p, CMPP20_PROTO_MSISDN);
		p += CMPP20_PROTO_MSISDN;

		memcpy(&net32, p, 4);
		report.smsc_seq = ntohl(net32);
		p += 4;

		memcpy(deliver->msg_content, &report, sizeof(cmpp20_report));
	}

	memcpy(deliver->reserve, p, CMPP20_PROTO_RESERVE);
	p += CMPP20_PROTO_RESERVE;

	if(len < p-buf)
		return CMPP20_STAT_SP_ELEN;
	return 0;
}
static int parse_deliver_resp(char buf[], size_t len, cmpp20_packet *pk)
{
	char    *p = buf;
	cmpp20_deliver_resp   *deliver_resp = &pk->deliver_resp;
	uint64_t	net64;

	memcpy(&net64, p, 8);
	deliver_resp->msg_id = be64toh(net64);
	p += 8;

	deliver_resp->result = *p++;

	if(len < p-buf)
		return CMPP20_STAT_SP_ELEN;
	return 0;
}   

/*
 *	make pk
 */
static int make_header(cmpp20_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp20_header	*header = &pk->header;
	uint32_t	net32;

	net32 = htonl(header->len);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(header->cmd);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(header->seq);
	memcpy(p, &net32, 4);
	p += 4;

	*len = p - buf;
	return 0;
}
static int make_connect(cmpp20_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp20_connect	*connect = &pk->connect;
	uint32_t	net32;

	memcpy(p, connect->source, CMPP20_PROTO_SP_ID);
	p += CMPP20_PROTO_SP_ID;

	memcpy(p, connect->auth, CMPP20_PROTO_ATUH);
	p += CMPP20_PROTO_ATUH;

	*p++ = connect->version;

	net32 = htonl(connect->timestamp);
	memcpy(p, &net32, 4);
	p += 4;

	*len = p - buf;
	return 0;
}
static int make_connect_resp(cmpp20_packet *pk, char buf[], size_t *len)
{
	char    *p = buf;
	cmpp20_connect_resp   *connect_resp = &pk->connect_resp;

	*p++ = connect_resp->status;

	memcpy(p, connect_resp->auth, CMPP20_PROTO_ATUH);
	p += CMPP20_PROTO_ATUH;

	*p++ = connect_resp->version;

	*len = p - buf;
	return 0;
}
static int make_submit(cmpp20_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp20_submit		*submit = &pk->submit;
	uint64_t	net64;

	if(submit->destusr_tl < 1 || submit->destusr_tl > CMPP20_PROTO_DESTUSERTL)
		return CMPP20_STAT_SP_EDEST_ID;
	if(submit->msg_length > CMPP20_PROTO_CONTENT)
		return CMPP20_STAT_SP_ECONTENT;

	net64 = htobe64(submit->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	*p++ = submit->pk_total;
	*p++ = submit->pk_number;
	*p++ = submit->reg_delivery;
	*p++ = submit->msg_level;

	memcpy(p, submit->service_id, CMPP20_PROTO_SERVICE);
	p += CMPP20_PROTO_SERVICE;

	*p++ = submit->fee_usertype;

	memcpy(p, submit->fee_id, CMPP20_PROTO_MSISDN);
	p += CMPP20_PROTO_MSISDN;

	*p++ = submit->tp_pid;
	*p++ = submit->tp_udhi;
	*p++ = submit->msg_fmt;

	memcpy(p, submit->msg_src, CMPP20_PROTO_SP_ID);
	p += CMPP20_PROTO_SP_ID;

	memcpy(p, submit->feetype, CMPP20_PROTO_FEETYPE);
	p += CMPP20_PROTO_FEETYPE;

	memcpy(p, submit->feecode, CMPP20_PROTO_FEECODE);
	p += CMPP20_PROTO_FEECODE;

	memcpy(p, submit->valid_time, CMPP20_PROTO_TIME);
	p += CMPP20_PROTO_TIME;

	memcpy(p, submit->at_time, CMPP20_PROTO_TIME);
	p += CMPP20_PROTO_TIME;

	memcpy(p, submit->src_id, CMPP20_PROTO_MSISDN);
	p += CMPP20_PROTO_MSISDN;

	*p++ = submit->destusr_tl;
	int i;
	for(i=0; i<submit->destusr_tl; i++){
		memcpy(p, submit->dest_id[i], CMPP20_PROTO_MSISDN);
		p += CMPP20_PROTO_MSISDN;
	}

	*p++ = submit->msg_length;

	memcpy(p, submit->msg_content, submit->msg_length);
	p += submit->msg_length;

	memcpy(p, submit->reserve, CMPP20_PROTO_RESERVE);
	p += CMPP20_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_submit_resp(cmpp20_packet *pk, char buf[], size_t *len)
{
	char    *p = buf;
	cmpp20_submit_resp    *submit_resp = &pk->submit_resp;
	uint64_t	net64;

	net64 = htobe64(submit_resp->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	*p++ = submit_resp->result;

	*len = p - buf;
	return 0;
}
static int make_deliver(cmpp20_packet *pk, char buf[], size_t *len)
{
	char    *p = buf;
	cmpp20_deliver	*deliver = &pk->deliver;
	cmpp20_report	report;
	uint64_t		net64;
	uint32_t		net32;

	if(deliver->msg_length > CMPP20_PROTO_CONTENT)
		return CMPP20_STAT_SP_ECONTENT;

	net64 = htobe64(deliver->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	memcpy(p, deliver->dest_id, CMPP20_PROTO_MSISDN);
	p += CMPP20_PROTO_MSISDN;

	memcpy(p, deliver->service_id, CMPP20_PROTO_SERVICE);
	p += CMPP20_PROTO_SERVICE;

	*p++ = deliver->tp_pid;
	*p++ = deliver->tp_udhi;
	*p++ = deliver->msg_fmt;

	memcpy(p, deliver->src_id, CMPP20_PROTO_MSISDN);
	p += CMPP20_PROTO_MSISDN;

	*p++ = deliver->reg_delivery;

	if(deliver->reg_delivery == 0){
		*p++ = deliver->msg_length;

		memcpy(p, deliver->msg_content, deliver->msg_length);
		p += deliver->msg_length;
	}else{
		*p++ = CMPP20_PACKET_LEN_REPORT;
		memcpy(&report, deliver->msg_content, sizeof(cmpp20_report));

		net64 = htobe64(report.msg_id);
		memcpy(p, &net64, 8);
		p += 8;

		memcpy(p, report.stat, CMPP20_PROTO_REPORT_STAT);
		p += CMPP20_PROTO_REPORT_STAT;

		memcpy(p, report.submit_time, CMPP20_PROTO_REPORT_TIME);
		p += CMPP20_PROTO_REPORT_TIME;

		memcpy(p, report.done_time, CMPP20_PROTO_REPORT_TIME);
		p += CMPP20_PROTO_REPORT_TIME;

		memcpy(p, report.dest_id, CMPP20_PROTO_MSISDN);
		p += CMPP20_PROTO_MSISDN;

		net32 = htonl(report.smsc_seq);
		memcpy(p, &net32, 4);
		p += 4;
	}

	memcpy(p, deliver->reserve, CMPP20_PROTO_RESERVE);
	p += CMPP20_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
static int make_deliver_resp(cmpp20_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp20_deliver_resp	*deliver_resp = &pk->deliver_resp;
	uint64_t	net64;

	net64 = htobe64(deliver_resp->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	*p++ = deliver_resp->result;

	*len = p - buf;
	return 0;
}

