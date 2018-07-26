#include "proto_mm7.h"

int mm7_proto_make_pk2buf(mm7_packet *pk, char *buf, size_t *buf_len);
static int make_SubmitReq(mm7_packet *pk, char *buf, size_t *buf_len);
static int make_SubmitRsp(mm7_packet *pk, char *buf, size_t *buf_len);
static int make_DeliverReq(mm7_packet *pk, char *buf, size_t *buf_len);
static int make_DeliverRsp(mm7_packet *pk, char *buf, size_t *buf_len);
static int make_DeliveryReportReq(mm7_packet *pk, char *buf, size_t *buf_len);
static int make_DeliveryReportRsp(mm7_packet *pk, char *buf, size_t *buf_len);
static int make_ReadReplyReq(mm7_packet *pk, char *buf, size_t *buf_len);
static int make_ReadReplyRsp(mm7_packet *pk, char *buf, size_t *buf_len);

static int parse_TransactionID(xmlNodePtr node, mm7_packet *pk);
static int parse_address(xmlNodePtr node, char *buf, int len);
static int parse_SubmitReq_Sender(xmlNodePtr node, mm7_packet *pk);
static int parse_recipient(xmlNodePtr node, char *buf, int len);
static int parse_SubmitReq_Recipients(xmlNodePtr node, mm7_packet *pk);
static int parse_Status(xmlNodePtr node, uint32_t *StatusCode, char *StatusText);

int mm7_proto_parse_buf2pk(char *buf, size_t buf_len, mm7_packet *pk);
static int parse_SubmitReq(xmlNodePtr node, mm7_packet *pk);
static int parse_SubmitRsp(xmlNodePtr node, mm7_packet *pk);
static int parse_DeliverReq(xmlNodePtr node, mm7_packet *pk);
static int parse_DeliverRsp(xmlNodePtr node, mm7_packet *pk);
static int parse_DeliveryReportReq(xmlNodePtr node, mm7_packet *pk);
static int parse_DeliveryReportRsp(xmlNodePtr node, mm7_packet *pk);
static int parse_ReadReplyReq(xmlNodePtr node, mm7_packet *pk);
static int parse_ReadReplyRsp(xmlNodePtr node, mm7_packet *pk);

static void mm7_print_submit_req(mm7_packet *pk);
static void mm7_print_submit_resp(mm7_packet *pk);
static void mm7_print_deliver_req(mm7_packet *pk);
static void mm7_print_deliver_resp(mm7_packet *pk);
static void mm7_print_report_req(mm7_packet *pk);
static void mm7_print_report_resp(mm7_packet *pk);
static void mm7_print_readreply_req(mm7_packet *pk);
static void mm7_print_readreply_resp(mm7_packet *pk);

/*
 * print mm7 package
 */
void mm7_print_pk(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	switch(pk->cmd){
		case MM7_CMD_SUBMIT_REQ:
			mm7_print_submit_req(pk);
			break;
		case MM7_CMD_SUBMIT_RESP:
			mm7_print_submit_resp(pk);
			break;
		case MM7_CMD_DELIVER_REQ:
			mm7_print_deliver_req(pk);
			break;
		case MM7_CMD_DELIVER_RESP:
			mm7_print_deliver_resp(pk);
			break;
		case MM7_CMD_REPORT_REQ:
			mm7_print_report_req(pk);
			break;
		case MM7_CMD_REPORT_RESP:
			mm7_print_report_resp(pk);
			break;
		case MM7_CMD_READREPLY_REQ:
			mm7_print_readreply_req(pk);
			break;
		case MM7_CMD_READREPLY_RESP:
			mm7_print_readreply_resp(pk);
			break;
		default:
			printf("unknown cmd %#x\n", pk->cmd);
			return;
	}
}
/*
 * parse mm7 package
 */
int mm7_proto_parse_buf2pk(char *buf, size_t buf_len, mm7_packet *pk)
{
	int		ret, len, isrequest;
	char	*start, *end;
	xmlDocPtr	doc;
	xmlNodePtr	node, node2;

	if(buf== NULL || pk == NULL)
		return EINVAL;
	/* get Request-Line */
	start = buf;
	if(!memcmp(start, "POST", 4))
		isrequest = 1;
	else if(!memcmp(start, "HTTP", 4))
		isrequest = 0;
	else
		return MM7_STAT_EREQUEST_LINE;
	if((end = strstr(start, "\r\n")) == NULL)
		return MM7_STAT_EREQUEST_LINE;
	len = (end-start) > sizeof(pk->request_line)-1 ? sizeof(pk->request_line)-1 : end-start;
	memcpy(pk->request_line, start, len);
	/* get Host */
	start = end + 2;
	if(!memcmp(start, "Host:", 5)){
		if((end = strstr(start, "\r\n")) == NULL)
			return MM7_STAT_EHOST;
		len = (end-start) > sizeof(pk->host)-1 ? sizeof(pk->host)-1 : end-start;
		memcpy(pk->host, start, len);
	}
	/* get Content-Type */
	if((end = strstr(start, "Content-Type:")) == NULL)
		return MM7_STAT_ECONTENT_TYPE;
	start = end + 13;
	if((end = strstr(start, "\r\n")) == NULL)
		return MM7_STAT_ECONTENT_TYPE;
	len = (end-start) > sizeof(pk->content_type)-1 ? sizeof(pk->content_type)-1 : end-start;
	memcpy(pk->content_type, start, len);
	/* get boundary part, include NextPart,Content-Type,Content-ID */
	start = buf+ pk->header_len;
	if((end = strstr(start, "<?xml")) == NULL)
		return MM7_STAT_EXML_FORMAT;
	if(isrequest && (end > start)){
		len = (end-start) > sizeof(pk->boundary_part)-1 ? sizeof(pk->boundary_part)-1 : end-start;
		memcpy(pk->boundary_part, start, len);
	}
	/* get XML */
	start = end;
	if((end = strstr(start, ":Envelope>")) == NULL)
		return MM7_STAT_EXML_FORMAT;
	end += 10;
	doc = xmlParseMemory(start, end - start);
	if(doc == NULL)
		return MM7_STAT_EXML_FORMAT;
	node = xmlDocGetRootElement(doc);
	if(node == NULL)
		return MM7_STAT_EXML_FORMAT;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if((!xmlStrcmp(node->name, BAD_CAST"Header"))) {
			ret = parse_TransactionID(node, pk);
			if(ret != 0)
				goto over;
		}
		else if((!xmlStrcmp(node->name, BAD_CAST"Body"))) {
			for(node2 = node->xmlChildrenNode; node2 != NULL; node2 = node2->next){
				if((!xmlStrcmp(node2->name, BAD_CAST"SubmitReq"))){
					pk->cmd = MM7_CMD_SUBMIT_REQ;
					ret = parse_SubmitReq(node2, pk);
					goto over;
				}
				else if((!xmlStrcmp(node2->name, BAD_CAST"SubmitRsp"))){
					pk->cmd = MM7_CMD_SUBMIT_RESP;
					ret = parse_SubmitRsp(node2, pk);
					goto over;
				}
				else if((!xmlStrcmp(node2->name, BAD_CAST"DeliverReq"))){
					pk->cmd = MM7_CMD_DELIVER_REQ;
					ret = parse_DeliverReq(node2, pk);
					goto over;
				}
				else if((!xmlStrcmp(node2->name, BAD_CAST"DeliverRsp"))){
					pk->cmd = MM7_CMD_DELIVER_RESP;
					ret = parse_DeliverRsp(node2, pk);
					goto over;
				}
				else if((!xmlStrcmp(node2->name, BAD_CAST"DeliveryReportReq"))){
					pk->cmd = MM7_CMD_REPORT_REQ;
					ret = parse_DeliveryReportReq(node2, pk);
					goto over;
				}
				else if((!xmlStrcmp(node2->name, BAD_CAST"DeliveryReportRsp"))){
					pk->cmd = MM7_CMD_REPORT_RESP;
					ret = parse_DeliveryReportRsp(node2, pk);
					goto over;
				}
				else if((!xmlStrcmp(node2->name, BAD_CAST"ReadReplyReq"))){
					pk->cmd = MM7_CMD_READREPLY_REQ;
					ret = parse_ReadReplyReq(node2, pk);
					goto over;
				}
				else if((!xmlStrcmp(node2->name, BAD_CAST"ReadReplyRsp"))){
					pk->cmd = MM7_CMD_READREPLY_RESP;
					ret = parse_ReadReplyRsp(node2, pk);
					goto over;
				}
				else{
					ret = MM7_STAT_EMsgType;
					goto over;
				}
			}
		}
	}
over:
	xmlFreeDoc(doc);
	if(ret != 0)
		return ret;
	/* get attachment */
	if(pk->cmd == MM7_CMD_SUBMIT_REQ || pk->cmd == MM7_CMD_DELIVER_REQ){
		pk->attachment_len = buf_len - (end - buf);
		if(pk->attachment_len > 2)
			pk->attachment = end + 1;
	}
	return 0;
}
/*
 * make mm7 package
 */
int mm7_proto_make_pk2buf(mm7_packet *pk, char *buf, size_t *buf_len)
{
	int		ret;

	if(pk == NULL || buf == NULL)
		return EINVAL;
	*buf_len = 0;
	switch(pk->cmd){
		case MM7_CMD_SUBMIT_REQ:
			ret = make_SubmitReq(pk, buf, buf_len);
			break;
		case MM7_CMD_SUBMIT_RESP:
			ret = make_SubmitRsp(pk, buf, buf_len);
			break;
		case MM7_CMD_DELIVER_REQ:
			ret = make_DeliverReq(pk, buf, buf_len);
			break;
		case MM7_CMD_DELIVER_RESP:
			ret = make_DeliverRsp(pk, buf, buf_len);
			break;
		case MM7_CMD_REPORT_REQ:
			ret = make_DeliveryReportReq(pk, buf, buf_len);
			break;
		case MM7_CMD_REPORT_RESP:
			ret = make_DeliveryReportRsp(pk, buf, buf_len);
			break;
		case MM7_CMD_READREPLY_REQ:
			ret = make_ReadReplyReq(pk, buf, buf_len);
			break;
		case MM7_CMD_READREPLY_RESP:
			ret = make_ReadReplyRsp(pk, buf, buf_len);
			break;
	}
	return ret;
}
static int make_SubmitReq(mm7_packet *pk, char *buf, size_t *buf_len)
{
	int		i;
	char	*start = buf;

	start += sprintf(start, "<SubmitReq xmlns=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\"><MM7Version>%s</MM7Version>", pk->submit_req.version);
	start += sprintf(start, "<SenderIdentification><VASPID>%s</VASPID><VASID>%s</VASID><SenderAddress><Number>%s</Number></SenderAddress></SenderIdentification><Recipients><To>", pk->submit_req.vaspid, pk->submit_req.vasid, pk->submit_req.sender);
	for(i=0; i<pk->submit_req.rec_count; i++)
		start += sprintf(start, "<Number>%s</Number>", pk->submit_req.recipient[i]);
	start += sprintf(start, "</To></Recipients><ServiceCode>%s</ServiceCode>", pk->submit_req.service);
	if(pk->submit_req.linked_id[0])
		start += sprintf(start, "<LinkedID>%s</LinkedID>", pk->submit_req.linked_id);
	if(pk->submit_req.msg_class[0])
		start += sprintf(start, "<MessageClass>%s</MessageClass>", pk->submit_req.msg_class);
	if(pk->submit_req.timestamp[0])
		start += sprintf(start, "<TimeStamp>%s</TimeStamp>", pk->submit_req.timestamp);
	if(pk->submit_req.expiry_date[0])
		start += sprintf(start, "<ExpiryDate>%s</ExpiryDate>", pk->submit_req.expiry_date);
	if(pk->submit_req.delivery_time[0])
		start += sprintf(start, "<EarliestDeliveryTime>%s</EarliestDeliveryTime>", pk->submit_req.delivery_time);
	if(pk->submit_req.delivery_report[0])
		start += sprintf(start, "<DeliveryReport>%s</DeliveryReport>", pk->submit_req.delivery_report);
	if(pk->submit_req.read_reply[0])
		start += sprintf(start, "<ReadReply>%s</ReadReply>", pk->submit_req.read_reply);
	if(pk->submit_req.reply_charging){
		start += sprintf(start, "<ReplyCharging>");
		if(pk->submit_req.reply_chargsize)
			start += sprintf(start, "<replyChargingSize>%u</replyChargingSize>", pk->submit_req.reply_chargsize);
		if(pk->submit_req.reply_deadline[0])
			start += sprintf(start, "<replyDeadline>%s</replyDeadline>", pk->submit_req.reply_deadline);
		start += sprintf(start, "</ReplyCharging>");
	}
	if(pk->submit_req.priority[0])
		start += sprintf(start, "<Priority>%s</Priority>", pk->submit_req.priority);
	if(pk->submit_req.subject[0])
		start += sprintf(start, "<Subject>%s</Subject>", pk->submit_req.subject);
	if(pk->submit_req.charged_party[0])
		start += sprintf(start, "<ChargedParty>%s</ChargedParty>", pk->submit_req.charged_party);
	if(pk->submit_req.charged_party_id[0])
		start += sprintf(start, "<ChargedPartyID>%s</ChargedPartyID>", pk->submit_req.charged_party_id);
	if(pk->submit_req.indicator[0])
		start += sprintf(start, "<DistributionIndicator>%s</DistributionIndicator>", pk->submit_req.indicator);
	if(pk->submit_req.href[0]){
		start += sprintf(start, "<Content href=\"%s\" ", pk->submit_req.href);
		if(pk->submit_req.adaptations[0])
			start += sprintf(start, "allowAdaptations=\"%s\"", pk->submit_req.adaptations);
		start += sprintf(start, "/>");
	}
	start += sprintf(start, "</SubmitReq></env:Body></env:Envelope>");
	if(pk->attachment_len > 0){
		if(start - buf + pk->attachment_len + 512 > MM7_PACKET_LEN_MAX)
			return ENOMEM;
		memcpy(start, pk->attachment, pk->attachment_len);
		start += pk->attachment_len;
	}
	*buf_len = start - buf;
	return 0;
}
static int make_SubmitRsp(mm7_packet *pk, char *buf, size_t *buf_len)
{
	char	*start = buf;
	start += sprintf(start, "<SubmitRsp xmlns=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\"><MM7Version>%s</MM7Version>", pk->submit_resp.version);
	if(pk->submit_resp.msgid[0])
		start += sprintf(start, "<MessageID>%s</MessageID>", pk->submit_resp.msgid);
	start += sprintf(start, "<Status><StatusCode>%u</StatusCode>", pk->submit_resp.status_code);
	if(pk->submit_resp.status_text[0])
		start += sprintf(start, "<StatusText>%s</StatusText>", pk->submit_resp.status_text);
	start += sprintf(start, "</Status></SubmitRsp></env:Body></env:Envelope>");
	*buf_len = start - buf;
	return 0;
}
static int make_DeliverReq(mm7_packet *pk, char *buf, size_t *buf_len)
{
	char	*start = buf;
	start += sprintf(start, "<DeliverReq xmlns=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\"><MM7Version>%s</MM7Version>", pk->deliver_req.version);
	if(pk->deliver_req.server_id[0])
		start += sprintf(start, "<MMSRelayServerID>%s</MMSRelayServerID>", pk->deliver_req.server_id);
	if(pk->deliver_req.linked_id[0])
		start += sprintf(start, "<LinkedID>%s</LinkedID>", pk->deliver_req.linked_id);
	start += sprintf(start, "<Sender><Number>%s</Number></Sender>", pk->deliver_req.sender);
	if(pk->deliver_req.recipient[0])
		start += sprintf(start, "<Recipients><To><Number>%s</Number></To></Recipients>", pk->deliver_req.recipient);
	if(pk->deliver_req.timestamp[0])
		start += sprintf(start, "<TimeStamp>%s</TimeStamp>", pk->deliver_req.timestamp);
	if(pk->deliver_req.reply_charging_id[0])
		start += sprintf(start, "<ReplyChargingID>%s</ReplyChargingID>", pk->deliver_req.reply_charging_id);
	if(pk->deliver_req.priority[0])
		start += sprintf(start, "<Priority>%s</Priority>", pk->deliver_req.priority);
	if(pk->deliver_req.subject[0])
		start += sprintf(start, "<Subject>%s</Subject>", pk->deliver_req.subject);
	if(pk->deliver_req.href[0])
		start += sprintf(start, "<Content href=\"%s\"/>", pk->deliver_req.href);
	start += sprintf(start, "</DeliverReq></env:Body></env:Envelope>");
	if(pk->attachment_len > 0){
		if(start - buf + pk->attachment_len + 512 > MM7_PACKET_LEN_MAX)
			return ENOMEM;
		memcpy(start, pk->attachment, pk->attachment_len);
		start += pk->attachment_len;
	}
	*buf_len = start - buf;
	return 0;
}
static int make_DeliverRsp(mm7_packet *pk, char *buf, size_t *buf_len)
{
	char	*start = buf;
	start += sprintf(start, "<DeliverRsp xmlns=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\"><MM7Version>%s</MM7Version>", pk->deliver_resp.version);
	if(pk->deliver_resp.service[0])
		start += sprintf(start, "<ServiceCode>%s</ServiceCode>", pk->deliver_resp.service);
	start += sprintf(start, "<Status><StatusCode>%u</StatusCode>", pk->deliver_resp.status_code);
	if(pk->deliver_resp.status_text[0])
		start += sprintf(start, "<StatusText>%s</StatusText>", pk->deliver_resp.status_text);
	start += sprintf(start, "</Status></DeliverRsp></env:Body></env:Envelope>");
	*buf_len = start - buf;
	return 0;
}
static int make_DeliveryReportReq(mm7_packet *pk, char *buf, size_t *buf_len)
{
	char	*start = buf;
	start += sprintf(start, "<DeliveryReportReq xmlns=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\"><MM7Version>%s</MM7Version>", pk->report_req.version);
	if(pk->report_req.server_id[0])
		start += sprintf(start, "<MMSRelayServerID>%s</MMSRelayServerID>", pk->report_req.server_id);
	start += sprintf(start, "<MessageID>%s</MessageID><Recipients><Number>%s</Number></Recipients><Sender><Number>%s</Number></Sender><Date>%s</Date><MMStatus>%s</MMStatus>", pk->report_req.msgid, pk->report_req.recipient, pk->report_req.sender, pk->report_req.timestamp, pk->report_req.status);
	if(pk->report_req.status_ex[0])
		start += sprintf(start, "<MMStatusExtension>%s</MMStatusExtension>", pk->report_req.status_ex);
	if(pk->report_req.status_text[0])
		start += sprintf(start, "<StatusText>%s</StatusText>", pk->report_req.status_text);
	start += sprintf(start, "</DeliveryReportReq></env:Body></env:Envelope>");
	*buf_len = start - buf;
	return 0;
}
static int make_DeliveryReportRsp(mm7_packet *pk, char *buf, size_t *buf_len)
{
	char	*start = buf;
	start += sprintf(start, "<DeliveryReportRsp xmlns=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\"><MM7Version>%s</MM7Version>", pk->report_resp.version);
	start += sprintf(start, "<Status><StatusCode>%u</StatusCode>", pk->report_resp.status_code);
	if(pk->report_resp.status_text[0])
		start += sprintf(start, "<StatusText>%s</StatusText>", pk->report_resp.status_text);
	start += sprintf(start, "</Status></DeliveryReportRsp></env:Body></env:Envelope>");
	*buf_len = start - buf;
	return 0;
}
static int make_ReadReplyReq(mm7_packet *pk, char *buf, size_t *buf_len)
{
	char	*start = buf;
	start += sprintf(start, "<ReadReplyReq xmlns=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\"><MM7Version>%s</MM7Version>", pk->readreply_req.version);
	if(pk->readreply_req.server_id[0])
		start += sprintf(start, "<MMSRelayServerID>%s</MMSRelayServerID>", pk->readreply_req.server_id);
	start += sprintf(start, "<Recipients><Number>%s</Number></Recipients><Sender><Number>%s</Number></Sender><MessageID>%s</MessageID><TimeStamp>%s</TimeStamp><MMStatus>%s</MMStatus>", pk->readreply_req.recipient, pk->readreply_req.sender, pk->readreply_req.msgid, pk->readreply_req.timestamp, pk->readreply_req.status);
	if(pk->readreply_req.status_text[0])
		start += sprintf(start, "<StatusText>%s</StatusText>", pk->readreply_req.status_text);
	start += sprintf(start, "</ReadReplyReq></env:Body></env:Envelope>");
	*buf_len = start - buf;
	return 0;
}
static int make_ReadReplyRsp(mm7_packet *pk, char *buf, size_t *buf_len)
{
	char	*start = buf;
	start += sprintf(start, "<ReadReplyRsp xmlns=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\"><MM7Version>%s</MM7Version>", pk->readreply_resp.version);
	start += sprintf(start, "<Status><StatusCode>%u</StatusCode>", pk->readreply_resp.status_code);
	if(pk->readreply_resp.status_text[0])
		start += sprintf(start, "<StatusText>%s</StatusText>", pk->readreply_resp.status_text);
	start += sprintf(start, "</Status></ReadReplyRsp></env:Body></env:Envelope>");
	*buf_len = start - buf;
	return 0;
}



static int parse_TransactionID(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"TransactionID")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->transactionid, (char*)key, sizeof(pk->transactionid)-1);
				xmlFree(key);
				return 0;
			}
		}
	}
	return MM7_STAT_ETransactionID;
}
static int parse_address(xmlNodePtr node, char *buf, int len)
{
	xmlChar	*key = NULL;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"Number")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(buf, (char*)key, len);
				xmlFree(key);
				return 0;
			}
			return MM7_STAT_EADDRESS;
		}
	}
	return MM7_STAT_EADDRESS;
}
static int parse_SubmitReq_Sender(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	vaspid, vasid;

	vaspid = vasid = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"VASPID")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.vaspid, (char*)key, sizeof(pk->submit_req.vaspid)-1);
				xmlFree(key);
				vaspid = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"VASID")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.vasid, (char*)key, sizeof(pk->submit_req.vasid)-1);
				xmlFree(key);
				vasid = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"SenderAddress")){ //optional
			parse_address(node, pk->submit_req.sender, MM7_PROTO_USERADDR);
		}
	}
	if(vaspid == 0)return MM7_STAT_EVASPID;
	if(vasid == 0)return MM7_STAT_EVASID;
	return 0;
}
static int parse_recipient(xmlNodePtr node, char *buf, int len)
{
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"To"))
			return parse_address(node, buf, len);
	}
	return MM7_STAT_EADDRESS;
}
static int parse_SubmitReq_Recipients(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	xmlNodePtr	node2;
	char	recipient;
	recipient = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"To")){
			for(node2 = node->xmlChildrenNode; node2 != NULL; node2 = node2->next){
				if(!xmlStrcmp(node2->name, BAD_CAST"Number")){
					if((key = xmlNodeGetContent(node2)) != NULL){
						if(pk->submit_req.rec_count + 1 < MM7_PROTO_RECV_MAX){
							strncpy(pk->submit_req.recipient[pk->submit_req.rec_count++], (char*)key, MM7_PROTO_USERADDR);
							xmlFree(key);
							recipient = 1;
						}else{
							xmlFree(key);
							goto over;
						}
					}
				}
			}
		}
	}
over:
	if(recipient == 0) return MM7_STAT_ERecipient;
	return 0;
}
static int parse_Status(xmlNodePtr node, uint32_t *StatusCode, char *StatusText)
{
	xmlChar *key = NULL;
	char    status_code;
	status_code = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"StatusCode")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				*StatusCode = atoi((char*)key);
				xmlFree(key);
				status_code = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"StatusText")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(StatusText, (char*)key, MM7_PROTO_STATUS_TEXT);
				xmlFree(key);
			}
		}
	}
	if(status_code == 0)return MM7_STAT_EStatusCode;
	return 0;
}
static int parse_SubmitReq(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	version, service;
	version = service = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"MM7Version")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.version, (char*)key, sizeof(pk->submit_req.version)-1);
				xmlFree(key);
				version = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"SenderIdentification")){ //VASPID VASID required 
			if(parse_SubmitReq_Sender(node, pk) != 0)
				return MM7_STAT_ESender;
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Recipients")){ //required
			if(parse_SubmitReq_Recipients(node, pk) != 0)
				return MM7_STAT_ERecipient;
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"ServiceCode")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.service, (char*)key, sizeof(pk->submit_req.service)-1);
				xmlFree(key);
				service = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"LinkedID")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.linked_id, (char*)key, sizeof(pk->submit_req.linked_id)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MessageClass")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.msg_class, (char*)key, sizeof(pk->submit_req.msg_class)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"TimeStamp")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.timestamp, (char*)key, sizeof(pk->submit_req.timestamp)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"ExpiryDate")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.expiry_date, (char*)key, sizeof(pk->submit_req.expiry_date)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"EarliestDeliveryTime")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.delivery_time, (char*)key, sizeof(pk->submit_req.delivery_time)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"DeliveryReport")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.delivery_report, (char*)key, sizeof(pk->submit_req.delivery_report)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"ReadReply")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.read_reply, (char*)key, sizeof(pk->submit_req.read_reply)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"ReplyCharging")){
			pk->submit_req.reply_charging = 1;
			if((key = xmlGetProp(node, BAD_CAST"replyChargingSize")) != NULL){
				pk->submit_req.reply_chargsize = atoi((char*)key);
				xmlFree(key);
			}
			if((key = xmlGetProp(node, BAD_CAST"replyDeadline")) != NULL){
				strncpy(pk->submit_req.reply_deadline, (char*)key, sizeof(pk->submit_req.reply_deadline)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Priority")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.priority, (char*)key, sizeof(pk->submit_req.priority)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Subject")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.subject, (char*)key, sizeof(pk->submit_req.subject)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"ChargedParty")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.charged_party, (char*)key, sizeof(pk->submit_req.charged_party)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"ChargedPartyID")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.charged_party_id, (char*)key, sizeof(pk->submit_req.charged_party_id)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"DistributionIndicator")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_req.indicator, (char*)key, sizeof(pk->submit_req.indicator)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Content")){
			if((key = xmlGetProp(node,BAD_CAST"allowAdaptations")) != NULL){
				strncpy(pk->submit_req.adaptations, (char*)key, sizeof(pk->submit_req.adaptations)-1);
				xmlFree(key);
			}
			if((key = xmlGetProp(node, BAD_CAST"href")) != NULL){
				strncpy(pk->submit_req.href, (char*)key, sizeof(pk->submit_req.href)-1);
				xmlFree(key);
			}
		}
	}
	if(version == 0) return MM7_STAT_EVersion;
	if(service == 0) return MM7_STAT_EServiceCode;
	return 0;
}
static int parse_SubmitRsp(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	version, msgid;
	version = msgid = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"MM7Version")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_resp.version, (char*)key, sizeof(pk->submit_resp.version)-1);
				xmlFree(key);
				version = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MessageID")){ //if status_code is successful, required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->submit_resp.msgid, (char*)key, sizeof(pk->submit_resp.msgid)-1);
				xmlFree(key);
				msgid = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Status")){ //StautsCode required
			if(parse_Status(node, &pk->submit_resp.status_code, pk->submit_resp.status_text) != 0)
				return MM7_STAT_EStatusCode;
		}
	}
	if(version == 0) return MM7_STAT_EVersion;
	if(msgid == 0 && pk->submit_resp.status_code != MM7_STAT_SUCCESS) return MM7_STAT_EMSGID_NOTF;
	return 0;
}
static int parse_DeliverReq(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	version;
	version = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"MM7Version")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_req.version, (char*)key, sizeof(pk->deliver_req.version)-1);
				xmlFree(key);
				version = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MMSRelayServerID")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_req.server_id, (char*)key, sizeof(pk->deliver_req.server_id)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"LinkedID")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_req.linked_id, (char*)key, sizeof(pk->deliver_req.linked_id)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Sender")){ //required
			if(parse_address(node, pk->deliver_req.sender, MM7_PROTO_USERADDR) != 0)
				return MM7_STAT_ESender;
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Recipients")){ //optional
			parse_recipient(node, pk->deliver_req.recipient, MM7_PROTO_USERADDR);
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"TimeStamp")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_req.timestamp, (char*)key, sizeof(pk->deliver_req.timestamp)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"ReplyChargingID")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_req.reply_charging_id, (char*)key, sizeof(pk->deliver_req.reply_charging_id)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Priority")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_req.priority, (char*)key, sizeof(pk->deliver_req.priority)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Subject")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_req.subject, (char*)key, sizeof(pk->deliver_req.subject)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Content")){
			if((key = xmlGetProp(node, BAD_CAST"href")) != NULL){
				strncpy(pk->deliver_req.href, (char*)key, sizeof(pk->deliver_req.href)-1);
				xmlFree(key);
			}
		}
	}
	if(version == 0) return MM7_STAT_EVersion;
	return 0;
}
static int parse_DeliverRsp(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	version;
	version = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"MM7Version")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_resp.version, (char*)key, sizeof(pk->deliver_resp.version)-1);
				xmlFree(key);
				version = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"ServiceCode")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->deliver_resp.service, (char*)key, sizeof(pk->deliver_resp.service)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Status")){
			if(parse_Status(node, &pk->deliver_resp.status_code, pk->deliver_resp.status_text) != 0)
				return MM7_STAT_EStatusCode;
		}
	}
	if(version == 0) return MM7_STAT_EVersion;
	return 0;
}
static int parse_DeliveryReportReq(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	version, msgid, status;
	version = msgid = status = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"MM7Version")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->report_req.version, (char*)key, sizeof(pk->report_req.version)-1);
				xmlFree(key);
				version = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MMSRelayServerID")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->report_req.server_id, (char*)key, sizeof(pk->report_req.server_id)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MessageID")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->report_req.msgid, (char*)key, sizeof(pk->report_req.msgid)-1);
				xmlFree(key);
				msgid = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Recipient")){ //required
			if(parse_recipient(node, pk->report_req.recipient, MM7_PROTO_USERADDR) != 0)
				return MM7_STAT_ERecipient;
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Sender")){ //required
			if(parse_address(node, pk->report_req.sender, MM7_PROTO_USERADDR) != 0)
				return MM7_STAT_ESender;
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Date")){ 
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->report_req.timestamp, (char*)key, sizeof(pk->report_req.timestamp)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MMStatus")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->report_req.status, (char*)key, sizeof(pk->report_req.status)-1);
				xmlFree(key);
				status = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"StatusText")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->report_req.status_text, (char*)key, sizeof(pk->report_req.status_text)-1);
				xmlFree(key);
			}
		}
	}
	if(version == 0) return MM7_STAT_EVersion;
	if(msgid == 0) return MM7_STAT_EMSGID_NOTF;
	if(status == 0) return MM7_STAT_EStatus;
	return 0;
}
static int parse_DeliveryReportRsp(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	version;
	version = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"MM7Version")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->report_resp.version, (char*)key, sizeof(pk->report_resp.version)-1);
				xmlFree(key);
				version = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Status")){ //StatusCode required
			if(parse_Status(node, &pk->report_resp.status_code, pk->report_resp.status_text) != 0)
				return MM7_STAT_EStatusCode;
		}
	}
	if(version == 0) return MM7_STAT_EVersion;
	return 0;
}
static int parse_ReadReplyReq(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	version, msgid, status;
	version = msgid = status = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"MM7Version")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->readreply_req.version, (char*)key, sizeof(pk->readreply_req.version)-1);
				xmlFree(key);
				version = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MMSRelayServerID")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->readreply_req.server_id, (char*)key, sizeof(pk->readreply_req.server_id)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Recipient")){ //required
			if(parse_recipient(node, pk->readreply_req.recipient, MM7_PROTO_USERADDR) != 0)
				return MM7_STAT_ERecipient;
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Sender")){ //required
			if(parse_address(node, pk->readreply_req.sender, MM7_PROTO_USERADDR) != 0)
				return MM7_STAT_ESender;
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MessageID")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->readreply_req.msgid, (char*)key, sizeof(pk->readreply_req.msgid)-1);
				xmlFree(key);
				msgid = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"TimeStamp")){ 
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->readreply_req.timestamp, (char*)key, sizeof(pk->readreply_req.timestamp)-1);
				xmlFree(key);
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"MMStatus")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->readreply_req.status, (char*)key, sizeof(pk->readreply_req.status)-1);
				xmlFree(key);
				status = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"StatusText")){
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->readreply_req.status_text, (char*)key, sizeof(pk->readreply_req.status_text)-1);
				xmlFree(key);
			}
		}
	}
	if(version == 0) return MM7_STAT_EVersion;
	if(msgid == 0) return MM7_STAT_EMSGID_NOTF;
	if(status == 0) return MM7_STAT_EStatus;
	return 0;
}
static int parse_ReadReplyRsp(xmlNodePtr node, mm7_packet *pk)
{
	xmlChar	*key = NULL;
	char	version;
	version = 0;
	for(node = node->xmlChildrenNode; node != NULL; node = node->next){
		if(!xmlStrcmp(node->name, BAD_CAST"MM7Version")){ //required
			if((key = xmlNodeGetContent(node)) != NULL){
				strncpy(pk->readreply_resp.version, (char*)key, sizeof(pk->readreply_resp.version)-1);
				xmlFree(key);
				version = 1;
			}
		}
		else if(!xmlStrcmp(node->name, BAD_CAST"Status")){ //StatusCode required
			if(parse_Status(node, &pk->readreply_resp.status_code, pk->readreply_resp.status_text) != 0)
				return MM7_STAT_EStatusCode;
		}
	}
	if(version == 0) return MM7_STAT_EVersion;
	return 0;
}
/*
 * print mm7 package
 */
static void mm7_print_header(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	printf("mm7-header-cmd:%#x\n", pk->cmd);
	printf("mm7-header-content_len:%u\n", pk->content_len);
	printf("mm7-header-header_len:%u\n", pk->header_len);
	printf("mm7-header-request_line:%s\n", pk->request_line);
	printf("mm7-header-host:%s\n", pk->host);
	printf("mm7-header-content_type:%s\n", pk->content_type);
	printf("mm7-header-boundary_part:%s\n", pk->boundary_part);
	printf("mm7-header-transactionid:%s\n", pk->transactionid);
}
static void mm7_print_submit_req(mm7_packet *pk)
{
	int		i;
	if(pk == NULL)
		return;
	mm7_print_header(pk);
	printf("mm7-submit_req-version:%s\n", pk->submit_req.version);
	printf("mm7-submit_req-vaspid:%s\n", pk->submit_req.vaspid);
	printf("mm7-submit_req-vasid:%s\n", pk->submit_req.vasid);
	printf("mm7-submit_req-sender:%s\n", pk->submit_req.sender);
	for(i=0; i<pk->submit_req.rec_count; i++)
		printf("mm7-submit_req-recipient:%s\n", pk->submit_req.recipient[i]);
	printf("mm7-submit_req-service:%s\n", pk->submit_req.service);
	printf("mm7-submit_req-linked_id:%s\n", pk->submit_req.linked_id);
	printf("mm7-submit_req-msg_class:%s\n", pk->submit_req.msg_class);
	printf("mm7-submit_req-timestamp:%s\n", pk->submit_req.timestamp);
	printf("mm7-submit_req-expiry_date:%s\n", pk->submit_req.expiry_date);
	printf("mm7-submit_req-delivery_time:%s\n", pk->submit_req.delivery_time);
	printf("mm7-submit_req-delivery_report:%s\n", pk->submit_req.delivery_report);
	printf("mm7-submit_req-read_reply:%s\n", pk->submit_req.read_reply);
	printf("mm7-submit_req-reply_charging:%u\n", pk->submit_req.reply_charging);
	printf("mm7-submit_req-reply_deadline:%s\n", pk->submit_req.reply_deadline);
	printf("mm7-submit_req-reply_chargsize:%u\n", pk->submit_req.reply_chargsize);
	printf("mm7-submit_req-priority:%s\n", pk->submit_req.priority);
	printf("mm7-submit_req-subject:%s\n", pk->submit_req.subject);
	printf("mm7-submit_req-adaptations:%s\n", pk->submit_req.adaptations);
	printf("mm7-submit_req-charged_party:%s\n", pk->submit_req.charged_party);
	printf("mm7-submit_req-charged_party_id:%s\n", pk->submit_req.charged_party_id);
	printf("mm7-submit_req-indicator:%s\n", pk->submit_req.indicator);
	printf("mm7-submit_req-href:%s\n", pk->submit_req.href);
}
static void mm7_print_submit_resp(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	mm7_print_header(pk);
	printf("mm7-submit_resp-version:%s\n", pk->submit_resp.version);
	printf("mm7-submit_resp-msgid:%s\n", pk->submit_resp.msgid);
	printf("mm7-submit_resp-status_code:%u\n", pk->submit_resp.status_code);
	printf("mm7-submit_resp-status_text:%s\n", pk->submit_resp.status_text);
}
static void mm7_print_deliver_req(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	mm7_print_header(pk);
	printf("mm7-deliver_req-version:%s\n", pk->deliver_req.version);
	printf("mm7-deliver_req-server_id:%s\n", pk->deliver_req.server_id);
	printf("mm7-deliver_req-linked_id:%s\n", pk->deliver_req.linked_id);
	printf("mm7-deliver_req-sender:%s\n", pk->deliver_req.sender);
	printf("mm7-deliver_req-recipient:%s\n", pk->deliver_req.recipient);
	printf("mm7-deliver_req-timestamp:%s\n", pk->deliver_req.timestamp);
	printf("mm7-deliver_req-reply_charging_id:%s\n", pk->deliver_req.reply_charging_id);
	printf("mm7-deliver_req-priority:%s\n", pk->deliver_req.priority);
	printf("mm7-deliver_req-subject:%s\n", pk->deliver_req.subject);
	printf("mm7-deliver_req-href:%s\n", pk->deliver_req.href);
}
static void mm7_print_deliver_resp(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	mm7_print_header(pk);
	printf("mm7-deliver_resp-version:%s\n", pk->deliver_resp.version);
	printf("mm7-deliver_resp-service:%s\n", pk->deliver_resp.service);
	printf("mm7-deliver_resp-status_code:%u\n", pk->deliver_resp.status_code);
	printf("mm7-deliver_resp-status_text:%s\n", pk->deliver_resp.status_text);
}
static void mm7_print_report_req(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	mm7_print_header(pk);
	printf("mm7-report_req-version:%s\n", pk->report_req.version);
	printf("mm7-report_req-server_id:%s\n", pk->report_req.server_id);
	printf("mm7-report_req-msgid:%s\n", pk->report_req.msgid);
	printf("mm7-report_req-recipient:%s\n", pk->report_req.recipient);
	printf("mm7-report_req-sender:%s\n", pk->report_req.sender);
	printf("mm7-report_req-timestamp:%s\n", pk->report_req.timestamp);
	printf("mm7-report_req-status:%s\n", pk->report_req.status);
	printf("mm7-report_req-status_ex:%s\n", pk->report_req.status_ex);
	printf("mm7-report_req-status_text:%s\n", pk->report_req.status_text);
}
static void mm7_print_report_resp(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	mm7_print_header(pk);
	printf("mm7-report_resp-version:%s\n", pk->report_resp.version);
	printf("mm7-report_resp-status_code:%u\n", pk->report_resp.status_code);
	printf("mm7-report_resp-status_text:%s\n", pk->report_resp.status_text);
}
static void mm7_print_readreply_req(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	mm7_print_header(pk);
	printf("mm7-readreply_req-version:%s\n", pk->readreply_req.version);
	printf("mm7-readreply_req-server_id:%s\n", pk->readreply_req.server_id);
	printf("mm7-readreply_req-recipient:%s\n", pk->readreply_req.recipient);
	printf("mm7-readreply_req-sender:%s\n", pk->readreply_req.sender);
	printf("mm7-readreply_req-msgid:%s\n", pk->readreply_req.msgid);
	printf("mm7-readreply_req-timestamp:%s\n", pk->readreply_req.timestamp);
	printf("mm7-readreply_req-status:%s\n", pk->readreply_req.status);
	printf("mm7-readreply_req-status_text:%s\n", pk->readreply_req.status_text);
}
static void mm7_print_readreply_resp(mm7_packet *pk)
{
	if(pk == NULL)
		return;
	mm7_print_header(pk);
	printf("mm7-readreply_resp-version:%s\n", pk->readreply_resp.version);
	printf("mm7-readreply_resp-status_code:%u\n", pk->readreply_resp.status_code);
	printf("mm7-readreply_resp-status_text:%s\n", pk->readreply_resp.status_text);
}

/*
 * init trans
 */
int mm7_trans_init(mm7_trans *trans)
{
	if(trans == NULL)
		return EINVAL;
	memset(trans, 0, sizeof(mm7_trans));
	trans->buf_len = MM7_PACKET_LEN_MAX;
	trans->buffer = malloc(trans->buf_len);
	if(trans->buffer == NULL)
		return ENOMEM;
	return 0;
}
void mm7_trans_destroy(mm7_trans *trans)
{
	if(trans == NULL)
		return;
	free(trans->buffer);
	return;
}
/*
 * send mm7 package
 */
int mm7_proto_send(mm7_trans *trans, mm7_packet *pk)
{
	int		ret; 
	char	header[512];
	char	*start;
	size_t	len, total, pos;

	if(trans == NULL || pk == NULL)
		return EINVAL;
	/* set body */
	start = trans->buffer + sizeof(header);
	start += sprintf(start, "%s<?xml version=\"1.0\"?><env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope\"><env:Header><mm7:TransactionID xmlns:mm7=\"http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-4\" env:mustUnderstand=\"1\">%s</mm7:TransactionID></env:Header><env:Body>", pk->boundary_part, pk->transactionid);
	ret = mm7_proto_make_pk2buf(pk, start, &len);
	if(ret != 0)
		return ret;
	/* set header */
	pk->content_len = start + len - trans->buffer; 
	if(pk->cmd == MM7_CMD_SUBMIT_REQ || pk->cmd == MM7_CMD_DELIVER_REQ){
		pk->header_len = snprintf(header, sizeof(header), "%s\r\nHost:%s\r\nContent-Type:%s\r\nAuthorization:%sContent-Length:%u\r\nSOAPAction:""\r\n", pk->request_line, pk->host, pk->content_type, trans->authinfo, pk->content_len);
	}else{
		pk->header_len = snprintf(header, sizeof(header), "%s\r\nHost:%s\r\nContent-Type:%s\r\nAuthorization:%sContent-Length:%u\r\n\r\n", pk->request_line, pk->host, pk->content_type, trans->authinfo, pk->content_len);
	}
	total = pk->header_len + pk->content_len;
	if(total > trans->buf_len)
		return MM7_STAT_EPACKET_LEN;
	/* send data */
	pos = sizeof(header) - pk->header_len;
	memcpy(trans->buffer + pos, header, pk->header_len);
	ret = com_socket_write(trans->sockfd, trans->buffer + pos, total, &len);
	if(ret != 0 || total != len)
		return EPIPE;
	return 0;
}
/*
 * recv mm7 package
 */
int mm7_proto_recv(mm7_trans *trans, mm7_packet *pk)
{
	int		ret;
	char	header[512], tmp[24];
	char	*start, *end;
	size_t	len, total;

	if(trans == NULL || pk == NULL)
		return EINVAL;
	memset(pk, 0, sizeof(mm7_packet));
	/* peek data */
	memset(header, 0, sizeof(header));
	ret = recv(trans->sockfd, header, sizeof(header)-1, MSG_PEEK);
	if(ret <= 0)
		return EPIPE;
	/* get Authorization */
	if(trans->status == 0){
		start = header;
		if((end = strstr(start, "Authorization:")) != NULL){
			start = end + 14;
			if(!memcmp(start, "Basic", 5) || !memcmp(start, " Basic", 6)) 
				trans->isauth = 1;
			else if(!memcmp(start, "Digest", 6) || !memcmp(start, " Digest", 7)) 
				trans->isauth = 2;
			else{
				return MM7_STAT_EAUTH;
			}
			if((end = strstr(start, "\r\n")) == NULL)
				return MM7_STAT_EAUTH;
			len = (end-start) > sizeof(trans->authinfo)-1 ? sizeof(trans->authinfo)-1 : end-start;
			memcpy(trans->authinfo, start, len);
		}
	}
	/* get Content-Length */
	start = header;
	if((end = strstr(start, "Content-Length:")) == NULL)
		return MM7_STAT_ECONTENT_LEN;
	start = end + 15;
	if((end = strstr(start, "\r\n")) == NULL)
		return MM7_STAT_ECONTENT_LEN;
	if(end - start > sizeof(tmp))
		return MM7_STAT_ECONTENT_LEN;
	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, start, end - start);
	pk->content_len = atoi(tmp);
	if(pk->content_len <= 0 || pk->content_len > trans->buf_len)
		return MM7_STAT_ECONTENT_LEN;
	/* get HTTP Header */
	start = end + 2;
	if((end = strstr(start, "\r\n\r\n")) == NULL)
		return MM7_STAT_EMSG_FORMAT;
	pk->header_len = start + 4 - header;
	/* get MM7 buffer */
	total = pk->header_len + pk->content_len;
	if(total > trans->buf_len)
		return MM7_STAT_EPACKET_LEN;
	ret = com_socket_read(trans->sockfd, trans->buffer, total, &len);
	if(ret != 0 || total != len)
		return EPIPE;
	/* parse packet */
	return mm7_proto_parse_buf2pk(trans->buffer, total, pk);
}
