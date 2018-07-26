#include "util_common.h"
#include "proto_smpp.h"

int parse_bind(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus);
int parse_bind_rsp(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus);
int parse_submit(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus);
int parse_submit_rsp(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus);
int parse_deliver(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus);
int parse_deliver_rsp(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus);

int parse_str(char dst[], char* ptr, uint32_t* plft, size_t len, uint32_t* pst, uint32_t* pgtlen);
int parse_int8(uint8_t* pdst, char* ptr, uint32_t* plft, uint32_t* pst);
int parse_int16(ushort* pdst, char* ptr, uint32_t* plft, uint32_t* pst);
int parse_int32(uint32_t* pdst, char* ptr, uint32_t* plft, uint32_t* pst);

int make_head(char *buf, smpp_message* ppk);
int make_bind(char *buf, size_t *len, smpp_message* ppk);
int make_bind_rsp(char *buf, size_t *len, smpp_message* ppk);
int make_submit(char *buf, size_t *len, smpp_message* ppk);
int make_submit_rsp(char *buf, size_t *len, smpp_message* ppk);
int make_deliver(char *buf, size_t *len, smpp_message* ppk);
int make_deliver_rsp(char *buf, size_t *len, smpp_message* ppk);

int smpp_parse_buf2pk(char buf[], size_t size, smpp_message* ppk, uint32_t* pstatus)
{               
	int	stat = 0;
	uint32_t	net32;
	char	*pbuf = NULL;

	*pstatus = 0; 
	if(size < SMPP_PK_HEAD_SIZE){
		*pstatus = SMPP_STAT_RINVMSGLEN;
		return EINVAL;
	}

	pbuf = buf;
	memcpy(&net32, pbuf, 4);
	ppk->head.cmd_len = ntohl(net32);
	pbuf += 4;
	if(ppk->head.cmd_len < size){
		*pstatus = SMPP_STAT_RINVMSGLEN;
		return EINVAL;
	}

	memcpy(&net32, pbuf, 4);
	ppk->head.cmd_id = ntohl(net32);
	pbuf += 4;

	memcpy(&net32, pbuf, 4);
	ppk->head.cmd_stat = ntohl(net32);
	pbuf += 4;

	memcpy(&net32, pbuf, 4);
	ppk->head.seq_num = ntohl(net32);
	pbuf += 4;

	switch(ppk->head.cmd_id){
		case SMPP_CMD_NACK:
			break;
		case SMPP_CMD_BIND_RECEIVER:
			stat = parse_bind(pbuf, size - 16, ppk, pstatus);
			break;
		case SMPP_CMD_BIND_RECEIVER_RSP:
			stat = parse_bind_rsp(pbuf, size - 16, ppk, pstatus);
			break;
		case SMPP_CMD_BIND_TRANSMITTER:
			stat = parse_bind(pbuf, size - 16, ppk, pstatus);
			break;
		case SMPP_CMD_BIND_TRANSMITTER_RSP:
			stat = parse_bind_rsp(pbuf, size - 16, ppk, pstatus);
			break;
		case SMPP_CMD_SUBMIT:
			stat = parse_submit(pbuf, size - 16, ppk, pstatus);
			break;
		case SMPP_CMD_SUBMIT_RSP:
			stat = parse_submit_rsp(pbuf, size - 16, ppk, pstatus);
			break;
		case SMPP_CMD_DELIVER:
			stat = parse_deliver(pbuf, size - 16, ppk, pstatus);
			break;
		case SMPP_CMD_DELIVER_RSP:
			stat = parse_deliver_rsp(pbuf, size - 16, ppk, pstatus);
			break;
		case SMPP_CMD_ENQUIRE_LINK:
			break;
		case SMPP_CMD_ENQUIRE_LINK_RSP:
			break;
		default:
			stat = SMPP_STAT_RINVCMDID;
	}

	return stat;
}

/* make packet to buf */
int smpp_make_pk2buf(smpp_message* ppk, char buf[], size_t *len, uint32_t* pstatus)
{
	int	stat = 0;

	*pstatus = 0;
	*len = SMPP_PK_HEAD_SIZE;

	switch(ppk->head.cmd_id){
		case SMPP_CMD_NACK:
			stat = make_head(buf, ppk);
			break;
		case SMPP_CMD_BIND_RECEIVER:
			stat = make_bind(buf, len, ppk);
			break;
		case SMPP_CMD_BIND_RECEIVER_RSP:
			stat = make_bind_rsp(buf, len, ppk);
			break;
		case SMPP_CMD_BIND_TRANSMITTER:
			stat = make_bind(buf, len, ppk);
			break;
		case SMPP_CMD_BIND_TRANSMITTER_RSP:
			stat = make_bind_rsp(buf, len, ppk);
			break;
		case SMPP_CMD_SUBMIT:
			stat = make_submit(buf, len, ppk);
			break;
		case SMPP_CMD_SUBMIT_RSP:
			stat = make_submit_rsp(buf, len, ppk);
			break;
		case SMPP_CMD_DELIVER:
			stat = make_deliver(buf, len, ppk);
			break;
		case SMPP_CMD_DELIVER_RSP:
			stat = make_deliver_rsp(buf, len, ppk);
			break;
		case SMPP_CMD_UNBIND:
			stat = make_head(buf, ppk);
			break;
		case SMPP_CMD_UNBIND_RSP:
			stat = make_head(buf, ppk);
			break;
		case SMPP_CMD_BIND_TRANSCEIVER:
			stat = make_bind(buf, len, ppk);
			break;
		case SMPP_CMD_BIND_TRANSCEIVER_RSP:
			stat = make_bind_rsp(buf, len, ppk);
			break;
		case SMPP_CMD_ENQUIRE_LINK:
			stat = make_head(buf, ppk);
			break;
		case SMPP_CMD_ENQUIRE_LINK_RSP:
			stat = make_head(buf, ppk);
			break;
		default:
			stat = EINVAL;
			break;
	}

	return stat;
}

int parse_bind(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus)
{
	char		*pbuf = buf;
	uint32_t		get_len;
	smpp_bind	*pbind = &ppk->body.bind;

	// Parse system_id
	if(parse_str(pbind->sys_id, pbuf, &len, SMPP_SYS_ID_LEN - 1, pstatus, &get_len) != 0){
		*pstatus = SMPP_STAT_RINVSYSID;
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse passwd
	if(parse_str(pbind->passwd, pbuf, &len, SMPP_PASSWD_LEN - 1, pstatus, &get_len) != 0){
		*pstatus = SMPP_STAT_RINVPASWD;
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse sys_type
	if(parse_str(pbind->sys_type, pbuf, &len, SMPP_SYS_TYPE_LEN - 1, pstatus, &get_len) != 0){
		*pstatus = SMPP_STAT_RINVUNKNOWN;
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse ver
	if(parse_int8(&pbind->ver, pbuf, &len, pstatus) != 0){
		*pstatus = SMPP_STAT_RINVUNKNOWN;
		return EINVAL;
	}
	pbuf += 1;

	// Parse addr_ton
	if(parse_int8(&pbind->addr_ton, pbuf, &len, pstatus) != 0){
		*pstatus = SMPP_STAT_RINVUNKNOWN;
		return EINVAL;
	}
	pbuf += 1;

	// Parse addr_npi
	if(parse_int8(&pbind->addr_npi, pbuf, &len, pstatus) != 0){
		*pstatus = SMPP_STAT_RINVUNKNOWN;
		return EINVAL;
	}
	pbuf += 1;

	// Parse addr_range
	if(parse_str(pbind->addr_range, pbuf, &len, SMPP_ADDRESS_RANGE_LEN - 1, pstatus, &get_len) != 0){
		*pstatus = SMPP_STAT_RINVUNKNOWN;
		return EINVAL;
	}

	return 0;

}

int parse_bind_rsp(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus)
{
	char		*pbuf = buf;
	uint32_t		get_len;
	smpp_bind_rsp*	pbind_rsp = &ppk->body.bind_rsp;

	// Parse sys_id
	if(parse_str(pbind_rsp->sys_id, pbuf, &len, SMPP_SYS_ID_LEN - 1, pstatus, &get_len) != 0){
		*pstatus = SMPP_STAT_RINVSYSID;
		return EINVAL;
	}
	pbuf += get_len + 1;

	return 0;
}

int parse_submit(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus)
{
	int		stat = 0;
	char		*pbuf = buf;
	smpp_submit	*psubmit = &ppk->body.submit;
	uint32_t		get_len = 0;

	// Parse svc_type
	if(parse_str(psubmit->svc_type, pbuf, &len, SMPP_SERVICE_TYPE_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse src_addr_ton
	if(parse_int8(&psubmit->src_addr_ton, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse src_addr_npi
	if(parse_int8(&psubmit->src_addr_npi, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse src_addr
	if(parse_str(psubmit->src_addr, pbuf, &len, SMPP_ADDR_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse dst_addr_ton
	if(parse_int8(&psubmit->dst_addr_ton, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse dst_addr_npi
	if(parse_int8(&psubmit->dst_addr_npi, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse dst_addr
	if(parse_str(psubmit->dst_addr, pbuf, &len, SMPP_ADDR_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse esm_class
	if(parse_int8(&psubmit->esm_class, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse proto_id
	if(parse_int8(&psubmit->proto_id, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse pri_flag
	if(parse_int8(&psubmit->pri_flag, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse dlv_time
	if(parse_str(psubmit->dlv_time, pbuf, &len, SMPP_TIME_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse valid_period
	if(parse_str(psubmit->valid_period, pbuf, &len,  SMPP_TIME_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}	
	pbuf += get_len + 1;

	// Parse reg_dlv
	if(parse_int8(&psubmit->reg_dlv, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse replace_if
	if(parse_int8(&psubmit->replace_if, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse data_coding
	if(parse_int8(&psubmit->data_coding, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse dft_msg_id
	if(parse_int8(&psubmit->dft_msg_id, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse sm_len
	if(parse_int8(&psubmit->sm_len, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse short_msg
	if(psubmit->sm_len > SMPP_SHORT_MESSAGE_LEN){
		*pstatus = SMPP_STAT_RINVMSGLEN;
		return EINVAL;
	}
	memcpy(psubmit->short_msg, pbuf, psubmit->sm_len);
	pbuf += psubmit->sm_len;
	len -= psubmit->sm_len;

	return stat;
}

int parse_submit_rsp(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus)
{
	int		stat = 0;
	char*		pbuf = buf;
	smpp_submit_rsp	*psubmit_rsp = &ppk->body.submit_rsp;
	uint32_t		get_len = 0;

	// Parse msg_id
	if(parse_str(psubmit_rsp->msg_id, pbuf, &len, SMPP_MESSAGE_ID_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	return stat;	
}

int parse_deliver(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus)
{
	int		stat = 0;
	char		*pbuf = buf;
	smpp_deliver	*pdeliver = &ppk->body.deliver;
	uint32_t		get_len = 0;

	// Parse svc_type
	if(parse_str(pdeliver->svc_type, pbuf, &len, SMPP_SERVICE_TYPE_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse src_addr_ton
	if(parse_int8(&pdeliver->src_addr_ton, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse src_addr_npi
	if(parse_int8(&pdeliver->src_addr_npi, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse src_addr
	if(parse_str(pdeliver->src_addr, pbuf, &len, SMPP_ADDR_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse dst_addr_ton
	if(parse_int8(&pdeliver->dst_addr_ton, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse dst_addr_npi
	if(parse_int8(&pdeliver->dst_addr_npi, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse dst_addr
	if(parse_str(pdeliver->dst_addr, pbuf, &len, SMPP_ADDR_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	// Parse esm_class
	if(parse_int8(&pdeliver->esm_class, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse proto_id
	if(parse_int8(&pdeliver->proto_id, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse pri_flag
	if(parse_int8(&pdeliver->pri_flag, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse dlv_time
	if(parse_int8(&pdeliver->dlv_time, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse valid_period
	if(parse_int8(&pdeliver->valid_period, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse reg_dlv
	if(parse_int8(&pdeliver->reg_dlv, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse replace_if
	if(parse_int8(&pdeliver->replace_if, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse data_coding
	if(parse_int8(&pdeliver->data_coding, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse dft_msg_id
	if(parse_int8(&pdeliver->dft_msg_id, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse sm_len
	if(parse_int8(&pdeliver->sm_len, pbuf, &len, pstatus) != 0){
		return EINVAL;
	}
	pbuf += 1;

	// Parse short_msg
	if(pdeliver->sm_len > SMPP_SHORT_MESSAGE_LEN){
		*pstatus = SMPP_STAT_RINVMSGLEN;
		return EINVAL;
	}
	memcpy(pdeliver->short_msg, pbuf, pdeliver->sm_len);
	pbuf += pdeliver->sm_len;
	len -= pdeliver->sm_len;

	return stat;
}

int parse_deliver_rsp(char buf[], uint32_t len, smpp_message* ppk, uint32_t* pstatus)
{
	int			stat = 0;
	char*			pbuf = buf;
	smpp_deliver_rsp	*pdeliver_rsp = &ppk->body.deliver_rsp;
	uint32_t			get_len = 0;

	// Parse msg_id
	if(parse_str(pdeliver_rsp->msg_id, pbuf, &len, SMPP_MESSAGE_ID_LEN - 1, pstatus, &get_len) != 0){
		return EINVAL;
	}
	pbuf += get_len + 1;

	return stat;
}

// Base functions for base type
int parse_str(char dst[], char* ptr, uint32_t* plft, size_t len, uint32_t* pst, uint32_t* pgtlen)
{
	int	stat = 0;

	*pgtlen = strlen(ptr);
	if((*pgtlen > len) || (*pgtlen > *plft) || (*plft == 0)){
		*pst = SMPP_STAT_RINVUNKNOWN;
		return EINVAL;
	}
	strcpy(dst, ptr);
	*plft -= *pgtlen + 1;

	return stat;
}

int parse_int8(uint8_t* pdst, char* ptr, uint32_t* plft, uint32_t* pst)
{
	int	stat = 0;

	if(*plft < 1){
		*pst = SMPP_STAT_RINVMSGLEN;
		return EINVAL;
	}
	*pdst = *ptr;
	*plft -= 1;

	return stat;
}

int parse_int16(ushort* pdst, char* ptr, uint32_t* plft, uint32_t* pst)
{
	int	stat = 0;
	ushort	net16;

	if(*plft < 2){
		*pst = SMPP_STAT_RINVMSGLEN;
		return EINVAL;
	}
	memcpy(&net16, ptr, 2);
	*pdst = ntohs(net16);
	*plft -= 2;

	return stat;
}

int parse_int32(uint32_t* pdst, char* ptr, uint32_t* plft, uint32_t* pst)
{
	int	stat = 0;
	uint32_t	net32;

	if(*plft < 4){
		*pst = SMPP_STAT_RINVMSGLEN;
		return EINVAL;
	}

	memcpy(&net32, ptr, 4);
	*pdst = ntohl(net32);
	*plft -= 4;

	return stat;
}

int make_head(char *buf, smpp_message* ppk)
{
	char	*p = buf;
	uint32_t	lval;

	lval = htonl(ppk->head.cmd_len);
	memcpy(p, &lval, sizeof(lval));
	p+=4;

	lval = htonl(ppk->head.cmd_id);
	memcpy(p, &lval, sizeof(lval));
	p+=4;

	lval = htonl(ppk->head.cmd_stat);
	memcpy(p, &lval, sizeof(lval));
	p+=4;

	lval = htonl(ppk->head.seq_num);
	memcpy(p, &lval, sizeof(lval));

	return 0;
}

int make_bind(char *buf, size_t *len, smpp_message* ppk)
{
	uint32_t		lval;
	char		*p;
	smpp_bind	*pbind = &ppk->body.bind;

	p = buf + 16;

	// set sysem id
	if(strlen(pbind->sys_id) > SMPP_SYS_ID_LEN){
		return EINVAL;
	}
	strcpy(p, pbind->sys_id);
	p += strlen(pbind->sys_id) + 1;

	// set password
	if(strlen(pbind->passwd) > SMPP_PASSWD_LEN){
		return EINVAL;
	}
	strcpy(p, pbind->passwd);
	p += strlen(pbind->passwd) + 1;

	// set system type
	strcpy(p, pbind->sys_type);
	p += strlen(pbind->sys_type) + 1;

	// set interface version
	*p = pbind->ver;
	p++;

	*p = pbind->addr_ton;
	p++;

	*p = pbind->addr_npi;
	p++;

	// skip address range
	if(strlen(pbind->addr_range) > SMPP_ADDRESS_RANGE_LEN){
		return EINVAL;
	}
	strcpy(p, pbind->addr_range);
	p += strlen(pbind->addr_range) + 1;

	*len = p - buf;
	lval = htonl(*len);
	memcpy(buf, &lval, sizeof(lval));

	ppk->head.cmd_len = *len;
	make_head(buf, ppk);

	return 0;
}
int make_bind_rsp(char *buf, size_t *len, smpp_message* ppk)
{
	uint32_t		lval;
	char		*p;
	smpp_bind_rsp	*pbind_rsp = &ppk->body.bind_rsp;

	p = buf + 16;

	if(strlen(pbind_rsp->sys_id) > SMPP_SYS_ID_LEN){
		return EINVAL;
	}
	strcpy(p, pbind_rsp->sys_id);
	p += strlen(pbind_rsp->sys_id) + 1;

	*len = p - buf;
	lval = htonl(*len);
	memcpy(buf, &lval, sizeof(lval));

	ppk->head.cmd_len = *len;
	make_head(buf, ppk);

	return 0;
}
int make_submit(char *buf, size_t *len, smpp_message* ppk)
{
	uint32_t		lval;
	char		*p;
	smpp_submit	*psubmit= &ppk->body.submit;

	p = buf + 16;

	// set service_type
	strcpy(p, psubmit->svc_type);
	p += strlen(psubmit->svc_type) + 1;

	*p = psubmit->src_addr_ton;
	p++;

	*p = psubmit->src_addr_npi;
	p++;

	// set source_addr
	strcpy(p, psubmit->src_addr);
	p += strlen(psubmit->src_addr) + 1;

	*p = psubmit->dst_addr_ton;
	p++;

	*p = psubmit->dst_addr_npi;
	p++;

	// set dest_addr
	strcpy(p, psubmit->dst_addr);
	p += strlen(psubmit->dst_addr) + 1;

	// set the esm_class
	*p = psubmit->esm_class;
	p++;

	*p = psubmit->proto_id;
	p++;

	*p = psubmit->pri_flag;
	p++;

	strcpy(p,psubmit->dlv_time);
	p += strlen( psubmit->dlv_time)+ 1;

	strcpy(p,psubmit->valid_period);
	p += strlen(psubmit->valid_period) + 1;

	// set registered_delivery
	*p = psubmit->reg_dlv;
	p++;

	*p = psubmit->replace_if;
	p++;

	*p = psubmit->data_coding;
	p++;

	// Set sm_default_id
	*p = psubmit->dft_msg_id;
	p++;

	if(psubmit->sm_len > SMPP_SHORT_MESSAGE_LEN){
		psubmit->sm_len  = SMPP_SHORT_MESSAGE_LEN;
	}
	*p = psubmit->sm_len;
	p++;

	memcpy(p, psubmit->short_msg, psubmit->sm_len);
	p += psubmit->sm_len;

	*len = p - buf;
	lval = htonl(*len);
	memcpy(buf, &lval, sizeof(lval));

	ppk->head.cmd_len = *len;
	make_head(buf, ppk);

	return 0;
}
int make_submit_rsp(char *buf, size_t *len, smpp_message* ppk)
{
	uint32_t		lval;
	char		*p;
	smpp_submit_rsp	*psubmit_rsp = &ppk->body.submit_rsp;

	p = buf + 16;

	strcpy(p, psubmit_rsp->msg_id);
	p += strlen(psubmit_rsp->msg_id) + 1;

	*len = p - buf;
	lval = htonl(*len);
	memcpy(buf, &lval, sizeof(lval));

	ppk->head.cmd_len = *len;
	make_head(buf, ppk);

	return 0;
}
int make_deliver(char *buf, size_t *len, smpp_message* ppk)
{
	uint32_t		lval;
	char		*p;
	smpp_deliver	*pdeliver= &ppk->body.deliver;

	p = buf + 16;

	strcpy(p, pdeliver->svc_type);
	p += strlen(pdeliver->svc_type) + 1;

	*p = pdeliver->src_addr_ton;
	p++;

	*p = pdeliver->src_addr_npi;
	p++;

	strcpy(p, pdeliver->src_addr);
	p += strlen(pdeliver->src_addr) + 1;

	*p = pdeliver->dst_addr_ton;
	p++;

	*p = pdeliver->dst_addr_npi;
	p++;

	strcpy(p, pdeliver->dst_addr);
	p += strlen(pdeliver->dst_addr) + 1;

	*p = pdeliver->esm_class;
	p++;

	*p = pdeliver->proto_id;
	p++;

	*p = pdeliver->pri_flag;
	p++;

	p++;    //dlv_time

	p++;    //valitdity_period

	*p = pdeliver->reg_dlv;
	p++;

	*p = pdeliver->replace_if;
	p++;

	*p = pdeliver->data_coding;
	p++;

	p++; //skip dft_msg_id 

	*p = pdeliver->sm_len;
	p++;

	memcpy(p, pdeliver->short_msg, pdeliver->sm_len);
	p += pdeliver->sm_len;

	*len = p - buf;
	lval = htonl(*len);
	memcpy(buf, &lval, sizeof(lval));

	ppk->head.cmd_len = *len;
	make_head(buf, ppk);

	return 0;
}
int make_deliver_rsp(char *buf, size_t *len, smpp_message* ppk)
{
	uint32_t		lval;
	char            *p;
	smpp_deliver_rsp	*pdeliver_rsp= &ppk->body.deliver_rsp;

	p = buf + 16;

	strcpy(p, pdeliver_rsp->msg_id);
	p += sizeof(pdeliver_rsp->msg_id);

	*len = p - buf;
	lval = htonl(*len);
	memcpy(buf, &lval, sizeof(lval));

	ppk->head.cmd_len = *len;
	make_head(buf, ppk);

	return 0;
}

void smpp_print_pk(smpp_message *ppk)
{
	if(ppk == NULL)
		return;
	printf("head.len[%d]cmd[%#x]stat[%d]seq[%d]\n", ppk->head.cmd_len, ppk->head.cmd_id, ppk->head.cmd_stat, ppk->head.seq_num);
	switch(ppk->head.cmd_id){
		case SMPP_CMD_NACK:
		case SMPP_CMD_BIND_RECEIVER:
		case SMPP_CMD_BIND_TRANSMITTER:
		case SMPP_CMD_BIND_TRANSCEIVER:
			printf("bind.sys_id[%s]passwd[%s]sys_type[%s]ver[%d]ton[%d]npi[%d]range[%s]\n", ppk->body.bind.sys_id, ppk->body.bind.passwd,
					ppk->body.bind.sys_type, ppk->body.bind.ver, ppk->body.bind.addr_ton, ppk->body.bind.addr_npi, ppk->body.bind.addr_range);
			break;
		case SMPP_CMD_BIND_RECEIVER_RSP:
		case SMPP_CMD_BIND_TRANSMITTER_RSP:
		case SMPP_CMD_BIND_TRANSCEIVER_RSP:
			printf("bind_rsp.sys_id[%s]\n", ppk->body.bind_rsp.sys_id);
			break;
		case SMPP_CMD_SUBMIT:
			printf("submit.svc_type[%s]src_ton[%d]src_npi[%d]src_addr[%s]dst_ton[%d]dst_npi[%d]dst_addr[%s]esm[%d]proto[%d]pri[%d]dlv[%s]period[%s]reg_dlv[%d]replace[%d]coding[%d]msgid[%d]msglen[%d]content[]\n", ppk->body.submit.svc_type,
					ppk->body.submit.src_addr_ton, ppk->body.submit.src_addr_npi, ppk->body.submit.src_addr,
					ppk->body.submit.dst_addr_ton, ppk->body.submit.dst_addr_npi, ppk->body.submit.dst_addr,
					ppk->body.submit.esm_class, ppk->body.submit.proto_id, ppk->body.submit.pri_flag, ppk->body.submit.dlv_time,
					ppk->body.submit.valid_period, ppk->body.submit.reg_dlv, ppk->body.submit.replace_if,
					ppk->body.submit.data_coding, ppk->body.submit.dft_msg_id, ppk->body.submit.sm_len);
			break;
		case SMPP_CMD_SUBMIT_RSP:
			printf("submit_rsp.msg_id[%s]\n", ppk->body.submit_rsp.msg_id);
			break;
		case SMPP_CMD_DELIVER:
			printf("deliver.svc_type[%s]src_ton[%d]src_npi[%d]src_addr[%s]dst_ton[%d]dst_npi[%d]dst_addr[%s]esm[%d]proto[%d]pri[%d]dlv[%d]period[%d]reg_dlv[%d]replace[%d]coding[%d]msgid[%d]msglen[%d]content[]\n", ppk->body.deliver.svc_type,
					ppk->body.deliver.src_addr_ton, ppk->body.deliver.src_addr_npi, ppk->body.deliver.src_addr,
					ppk->body.deliver.dst_addr_ton, ppk->body.deliver.dst_addr_npi, ppk->body.deliver.dst_addr,
					ppk->body.deliver.esm_class, ppk->body.deliver.proto_id, ppk->body.deliver.pri_flag, ppk->body.deliver.dlv_time,
					ppk->body.deliver.valid_period, ppk->body.deliver.reg_dlv, ppk->body.deliver.replace_if,
					ppk->body.deliver.data_coding, ppk->body.deliver.dft_msg_id, ppk->body.deliver.sm_len);
			break;
		case SMPP_CMD_DELIVER_RSP:
			printf("deliver_rsp.msg_id[%s]\n", ppk->body.deliver_rsp.msg_id);
			break;
		case SMPP_CMD_ENQUIRE_LINK:
			printf("enquire_link\n");
			break;
		case SMPP_CMD_ENQUIRE_LINK_RSP:
			printf("enquire_link_rsp\n");
			break;
		case SMPP_CMD_UNBIND:
		case SMPP_CMD_UNBIND_RSP:
		case SMPP_CMD_QUERY:
		case SMPP_CMD_QUERY_RSP:
		case SMPP_CMD_REPLACE:
		case SMPP_CMD_REPLACE_RSP:
		case SMPP_CMD_CANCEL:
		case SMPP_CMD_CANCEL_RSP:
		case SMPP_CMD_MULTI:
		case SMPP_CMD_MULTI_RSP:
		case SMPP_CMD_ALTER:
		case SMPP_CMD_DATA:
		case SMPP_CMD_DATA_RSP:
			printf("don't support cmd[%#x]\n", ppk->head.cmd_id);
			break;
		default:
			printf("unknown cmd[%#x]\n", ppk->head.cmd_id);
			break;
	}
	return;
}
