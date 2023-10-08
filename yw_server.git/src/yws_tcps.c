
//yw_server 通信管理

#include "yw_server.h"

#define __USE_GNU
#include <sys/mman.h>

typedef struct st_agent_info {
	int		use_flag;
	int		conn_flag;
	char	agent_name[120];
	char	group_name[64];
	void	*p_conn_info;
} agent_info;

typedef struct st_tool_info {
	int		use_flag;
	int		conn_flag;
	char	tool_name[120];
	void	*p_conn_info;
} tool_info;

typedef struct st_yw_file_info {
	tool_info	ti[MAX_TOOL_COUNT];
	agent_info	ai[MAX_AGENT_COUNT];
	sem_t   data_lock;
} yw_file_info;

yw_file_info *gp_yw_file;
static int  g_yw_fd;

static int sg_tcp_server_id;

typedef struct {
	int     server_id;
	int     connect_id;
	int     conn_flag;
	int     send_len;
	int     recv_len;
	int     client_id;	//0:未注册,1-9999:agent,10000+:tool
	char    recv_buf[128 * 1024];
	char    send_buf[128 * 1024];
	sem_t   data_flag;
	sem_t   data_lock;
	time_t	last_send_time;
	time_t	last_recv_time;
} yw_connect_info;

int proc_yw_get_time(yw_connect_info *p_info)
{
	char	*p_buf;
	struct timespec ts;

	p_buf = p_info->recv_buf;
	*(int*)(p_info->send_buf + 4) = *(int*)(p_buf + 4);
	clock_gettime(CLOCK_REALTIME, &ts);

	*(int*)(p_info->send_buf + 8) = 0;
	memcpy(p_info->send_buf + 12, &ts, sizeof(ts));
	p_info->send_len = 12 + sizeof(ts);
	*(int*)(p_info->send_buf) = p_info->send_len;
	bbl_tcps_send(p_info->server_id, p_info->connect_id, p_info->send_buf, p_info->send_len);

	return 0;
}

const char *get_client_name(int client_id)
{
	if (client_id < TOOL_ID_BASE)
	{
		if (client_id > MAX_AGENT_COUNT)
			return NULL;
		if (gp_yw_file->ai[client_id - 1].use_flag == 0)
			return NULL;
		return gp_yw_file->ai[client_id - 1].agent_name;
	}
	else
	{
		client_id -= TOOL_ID_BASE;
		if (client_id > MAX_TOOL_COUNT)
			return NULL;
		if (gp_yw_file->ti[client_id - 1].use_flag == 0)
			return NULL;
		return gp_yw_file->ti[client_id - 1].tool_name;
	}
	return NULL;
}

int disconnect_client(int client_id)
{
	if (client_id < TOOL_ID_BASE)
	{
		if (client_id > MAX_AGENT_COUNT)
			return EC_NOTFOUND;
		if (gp_yw_file->ai[client_id - 1].use_flag == 0)
			return 0;
		gp_yw_file->ai[client_id - 1].conn_flag = 0;
		gp_yw_file->ai[client_id - 1].p_conn_info = NULL;
	}
	else
	{
		client_id -= TOOL_ID_BASE;
		if (client_id > MAX_TOOL_COUNT)
			return EC_NOTFOUND;
		if (gp_yw_file->ti[client_id - 1].use_flag == 0)
			return 0;
		gp_yw_file->ti[client_id - 1].conn_flag = 0;
		gp_yw_file->ti[client_id - 1].p_conn_info = NULL;
	}
	return 0;
}

int send_active_test(yw_connect_info *p_info)
{
	yw_pk_header pkh;

	memset(&pkh, 0, sizeof(pkh));
	pkh.dst_id = p_info->client_id;
	pkh.pk_cmd1 = YW_ACTIVE_TEST;

	bbl_tcps_send(p_info->server_id, p_info->connect_id, (char*)&pkh, 6);
	p_info->last_send_time = g_app_info.cur_time;

	return 0;
}

int send_resp(yw_connect_info *p_info, yw_pk_header *p_pk, cJSON *p_json)
{
	char	send_buf[64 * 1024];
	int		send_len;
	yw_pk_header *p_pk_send;
	char	*p_out;

	p_pk_send = (yw_pk_header*)send_buf;
	memcpy(p_pk_send, p_pk, sizeof(yw_pk_header));

	p_out = cJSON_PrintBuffered(p_json, 2048, 0);
	if (!p_out)
	{
		log_printf(LOG_ERROR, "print json failed.\n");
		cJSON_Delete(p_json);
		return EC_MEMORY;
	}
	strcpy(p_pk_send->data, p_out);
	p_pk_send->pk_len = strlen(p_out) + 1;
	send_len = 6 + p_pk_send->pk_len;

	log_printf(LOG_DEBUG, "向客户端:[%s]发送数据:[%s].\n", get_client_name(p_info->client_id), p_out);

	cJSON_Delete(p_json);
	free(p_out);

	p_info->last_send_time = g_app_info.cur_time;

	return bbl_tcps_send(p_info->server_id,p_info->connect_id,send_buf,send_len);
}

int make_simple_resp(yw_connect_info *p_info, yw_pk_header *p_pk,int ret_code)
{
	cJSON	*p_root;

	p_root = cJSON_CreateObject();
	if (!p_root) return EC_MEMORY;

	cJSON_AddNumberToObject(p_root, "resultCode", ret_code);
	switch (ret_code)
	{
	case RESP_OK:			//操作成功
		cJSON_AddStringToObject(p_root, "data", "操作成功");
		break;
	case ERR_NOT_REGISTER:	//client未注册
		cJSON_AddStringToObject(p_root, "data", "Client未注册");
		break;
	case ERR_INVALID_ID:	//无效agent_id
		cJSON_AddStringToObject(p_root, "data", "Agent不存在");
		break;
	case ERR_COMM_BREAK:	//agent连接断
		cJSON_AddStringToObject(p_root, "data", "Agent连接断");
		break;
	case ERR_AUTH_ERROR:	//密码错
		cJSON_AddStringToObject(p_root, "data", "口令不正确");
		break;
	case ERR_COMM_DATA:		//数据格式错
		cJSON_AddStringToObject(p_root, "data", "数据格式错");
		break;
	case ERR_SYS_FAILED:	//系统错
		cJSON_AddStringToObject(p_root, "data", "系统错");
		break;
	default:
		cJSON_Delete(p_root);
		return EC_NOTSUPPORT;
	}
	return send_resp(p_info,p_pk,p_root);
}

int register_agent(yw_connect_info *p_info, char *pwd, char *group, char *name)
{
	int i,find_flag;

	if (strcmp(pwd, g_app_info.agent_password) != 0)
		return ERR_AUTH_ERROR;

	find_flag = 0;

	sem_wait(&gp_yw_file->data_lock);
	for (i = 0; i < MAX_AGENT_COUNT; i++)
	{
		if (gp_yw_file->ai[i].use_flag == 0)
			continue;
		if (strcmp(gp_yw_file->ai[i].agent_name, name) == 0)
		{
			if (gp_yw_file->ai[i].conn_flag == 0)
			{
				gp_yw_file->ai[i].conn_flag = 1;
				strcpy(gp_yw_file->ai[i].group_name, group);
				gp_yw_file->ai[i].p_conn_info = p_info;
				p_info->client_id = i + 1;
				find_flag = 1;
				break;
			}
		}
	}
	if (!find_flag)
	{
		for (i = 0; i < MAX_AGENT_COUNT; i++)
		{
			if (gp_yw_file->ai[i].use_flag == 0)
			{
				gp_yw_file->ai[i].use_flag = 1;
				gp_yw_file->ai[i].conn_flag = 1;
				strcpy(gp_yw_file->ai[i].group_name, group);
				strcpy(gp_yw_file->ai[i].agent_name, name);
				gp_yw_file->ai[i].p_conn_info = p_info;
				p_info->client_id = i + 1;
				find_flag = 1;
				break;
			}
		}
	}
	sem_post(&gp_yw_file->data_lock);
	if (!find_flag)
		return ERR_INVALID_ID;	//太多了

	log_printf(LOG_INFO, "agent_name:[%s],agent_id:[%d].\n", name, i + 1);

	return RESP_OK;
}

int register_tool(yw_connect_info *p_info, char *pwd, char *group, char *name)
{
	int i, find_flag;

	if (strcmp(pwd, g_app_info.tool_password) != 0)
		return ERR_AUTH_ERROR;

	find_flag = 0;
	sem_wait(&gp_yw_file->data_lock);
	for (i = 0; i < MAX_TOOL_COUNT; i++)
	{
		if (gp_yw_file->ti[i].use_flag == 0)
			continue;
		if (strcmp(gp_yw_file->ti[i].tool_name, name) == 0)
		{
			if (gp_yw_file->ti[i].conn_flag == 0)
			{
				gp_yw_file->ti[i].conn_flag = 1;
				gp_yw_file->ti[i].p_conn_info = p_info;
				p_info->client_id = TOOL_ID_BASE + i + 1;
				find_flag = 1;
				break;
			}
		}
	}
	if (!find_flag)
	{
		for (i = 0; i < MAX_TOOL_COUNT; i++)
		{
			if (gp_yw_file->ti[i].use_flag == 0)
			{
				gp_yw_file->ti[i].use_flag = 1;
				gp_yw_file->ti[i].conn_flag = 1;
				strcpy(gp_yw_file->ti[i].tool_name, name);
				gp_yw_file->ti[i].p_conn_info = p_info;
				p_info->client_id = TOOL_ID_BASE + i + 1;
				find_flag = 1;
				break;
			}
		}
	}
	sem_post(&gp_yw_file->data_lock);
	if (!find_flag)
		return ERR_INVALID_ID;	//太多了

	log_printf(LOG_INFO, "tool_name:[%s],tool_id:[%d].\n", name, p_info->client_id);

	return RESP_OK;
}

//“type”：0x02，”pwd”:’口令’，“groupName”:’’, “name”：‘公司’
int proc_register(yw_connect_info *p_info, yw_pk_header *p_pk)
{
	char	buf[1024];
	int		i_re;
	cJSON	*p_json;
	cJSON	*p_type, *p_pwd, *p_group, *p_name;

	if (p_info->client_id > 0)	//have registered
		return make_simple_resp(p_info, p_pk, RESP_OK);

	memcpy(buf, p_pk->data, p_pk->pk_len);
	buf[p_pk->pk_len] = 0;

	p_json = cJSON_Parse(buf);
	if (!p_json)
	{
		log_printf(LOG_ERROR, "解析json串失败,值:[%s].\n", buf);
		return make_simple_resp(p_info,p_pk, ERR_COMM_DATA);
	}
	p_type = cJSON_GetObjectItem(p_json, "type");
	if (!p_type || p_type->type != cJSON_Number)
		return make_simple_resp(p_info, p_pk, ERR_COMM_DATA);

	p_pwd = cJSON_GetObjectItem(p_json, "pwd");
	if (!p_pwd || p_pwd->type != cJSON_String)
		return make_simple_resp(p_info, p_pk, ERR_COMM_DATA);

	p_group = cJSON_GetObjectItem(p_json, "groupName");
	if (!p_group || p_group->type != cJSON_String)
		return make_simple_resp(p_info, p_pk, ERR_COMM_DATA);

	p_name = cJSON_GetObjectItem(p_json, "name");
	if (!p_name || p_name->type != cJSON_String)
		return make_simple_resp(p_info, p_pk, ERR_COMM_DATA);

	if (p_type->valueint == 1)	//agent register
		i_re = register_agent(p_info, p_pwd->valuestring, p_group->valuestring, p_name->valuestring);
	else	//register tool
		i_re = register_tool(p_info, p_pwd->valuestring, p_group->valuestring, p_name->valuestring);

	cJSON_Delete(p_json);
	return make_simple_resp(p_info,p_pk,i_re);
}

int proc_active_test(yw_connect_info *p_info, yw_pk_header *p_pk)
{
	//do nothing
	return 0;
}

//{“type”:1|2, “agentID”:5, ”name”:”1区服务器”, ”groupName”:”绥化运维”, ”status”:0|1}
int proc_list_agent(yw_connect_info *p_info, yw_pk_header *p_pk)
{
	cJSON	*p_root,*p_data,*p_object;
	int	i;

	p_root = cJSON_CreateObject();
	if (!p_root) return make_simple_resp(p_info, p_pk, ERR_SYS_FAILED);

	p_data = cJSON_CreateArray();
	if(!p_data) goto ERR_RET;

	cJSON_AddNumberToObject(p_root, "resultCode", RESP_OK);

	sem_wait(&gp_yw_file->data_lock);
	for (i = 0; i < MAX_AGENT_COUNT; i++)
	{
		if (gp_yw_file->ai[i].use_flag == 0)
			continue;
		p_object = cJSON_CreateObject();
		if (!p_object) goto ERR_RET;

		cJSON_AddNumberToObject(p_object, "type", 1);
		cJSON_AddNumberToObject(p_object, "agentID", i + 1);
		cJSON_AddStringToObject(p_object, "name", gp_yw_file->ai[i].agent_name);
		cJSON_AddStringToObject(p_object, "groupName", gp_yw_file->ai[i].group_name);
		cJSON_AddNumberToObject(p_object, "status", gp_yw_file->ai[i].conn_flag);
		cJSON_AddItemToArray(p_data, p_object);
	}
	for (i = 0; i < MAX_TOOL_COUNT; i++)
	{
		if (gp_yw_file->ti[i].use_flag == 0)
			continue;
		p_object = cJSON_CreateObject();
		if (!p_object) goto ERR_RET;

		cJSON_AddNumberToObject(p_object, "type", 2);
		cJSON_AddNumberToObject(p_object, "agentID", TOOL_ID_BASE + i + 1);
		cJSON_AddStringToObject(p_object, "name", gp_yw_file->ti[i].tool_name);
		cJSON_AddStringToObject(p_object, "groupName", "");
		cJSON_AddNumberToObject(p_object, "status", gp_yw_file->ti[i].conn_flag);
		cJSON_AddItemToArray(p_data, p_object);
	}
	sem_post(&gp_yw_file->data_lock);

	cJSON_AddItemToObjectCS(p_root, "data", p_data);
	return send_resp(p_info, p_pk, p_root);

ERR_RET:
	cJSON_Delete(p_root);
	return make_simple_resp(p_info, p_pk, ERR_SYS_FAILED);
}

int proc_delete_agent(yw_connect_info *p_info, yw_pk_header *p_pk)
{
	int	dst_id;

	dst_id = p_pk->dst_id;

	if (dst_id == 0 || dst_id > MAX_AGENT_COUNT)
		return make_simple_resp(p_info, p_pk, ERR_INVALID_ID);
	if (gp_yw_file->ai[dst_id - 1].use_flag == 0)
		return make_simple_resp(p_info, p_pk, ERR_INVALID_ID);

	gp_yw_file->ai[dst_id - 1].use_flag = 0;
	
	return make_simple_resp(p_info, p_pk, RESP_OK);
}

//不发送应答
int proc_rename_agent(int agent_id, yw_pk_header *p_pk)
{
	char	buf[512],agent_name[256];
	int		i_re;

	memcpy(buf, p_pk->data, p_pk->pk_len);
	buf[p_pk->pk_len] = 0;

	i_re = json_get_header(buf, "data", agent_name);
	if (i_re < 0)
	{
		log_printf(LOG_ERROR, "get agent name failed,errno:[%d].\n", i_re);
		return EC_NOTFOUND;
	}

	log_printf(LOG_INFO, "改变agent名字[%s]->[%s].\n", gp_yw_file->ai[agent_id - 1].agent_name, agent_name);
	strcpy(gp_yw_file->ai[agent_id - 1].agent_name, agent_name);

	return 0;
}

int proc_server_request(yw_connect_info *p_info, yw_pk_header *p_pk)
{
	int		i_re;

	if (p_info->client_id == 0 && p_pk->pk_cmd1 != YW_REGISTER)
		return make_simple_resp(p_info, p_pk, ERR_NOT_REGISTER);

	switch (p_pk->pk_cmd1)
	{
	case YW_REGISTER:
		i_re = proc_register(p_info, p_pk);
		break;
	case YW_LIST_AGENT:
		i_re = proc_list_agent(p_info, p_pk);
		break;
	case YW_ACTIVE_TEST:
		i_re = proc_active_test(p_info, p_pk);
		break;
	case YW_DELETE_AGENT:
		i_re = proc_delete_agent(p_info, p_pk);
		break;
	default:
		return EC_NOTSUPPORT;
	}
	return i_re;
}

int route_client_request(yw_connect_info *p_info, yw_pk_header *p_pk)
{
	int		i_re;
	unsigned short dst_id;
	yw_connect_info *p_dst;

	if (p_info->client_id == 0)
		return make_simple_resp(p_info, p_pk, ERR_NOT_REGISTER);

	i_re = 0;
	dst_id = p_pk->dst_id;
	if (dst_id < TOOL_ID_BASE)	//tool -> agent
	{
		if (dst_id > MAX_AGENT_COUNT)
			return make_simple_resp(p_info, p_pk, ERR_INVALID_ID);
		if(gp_yw_file->ai[dst_id-1].use_flag == 0)
			return make_simple_resp(p_info, p_pk, ERR_INVALID_ID);
		if (gp_yw_file->ai[dst_id - 1].conn_flag == 0)
			return make_simple_resp(p_info, p_pk, ERR_COMM_BREAK);

		p_dst = gp_yw_file->ai[dst_id - 1].p_conn_info;
		if(!p_dst)
			return make_simple_resp(p_info, p_pk, ERR_INVALID_ID);
		if (p_pk->pk_cmd1 == YW_RENAME_AGENT)
			proc_rename_agent(dst_id, p_pk);
		p_pk->dst_id = (unsigned short)p_info->client_id;
		i_re = bbl_tcps_send(p_dst->server_id, p_dst->connect_id, (char*)p_pk, p_pk->pk_len + 6);
	}
	else	//agent -> tool,路由失败不应答
	{
		dst_id -= TOOL_ID_BASE;
		if (dst_id > MAX_TOOL_COUNT)
		{
			log_printf(LOG_ERROR, "tool_id:[%d] invalid.\n", p_pk->dst_id);
			return 0;
		}
		if (gp_yw_file->ti[dst_id - 1].use_flag == 0)
		{
			log_printf(LOG_ERROR, "tool_id:[%d] invalid.\n", p_pk->dst_id);
			return 0;
		}
		if (gp_yw_file->ti[dst_id - 1].conn_flag == 0)
		{
			log_printf(LOG_ERROR, "tool_id:[%d] not connected.\n", p_pk->dst_id);
			return 0;
		}

		p_dst = gp_yw_file->ti[dst_id - 1].p_conn_info;
		if (!p_dst)
		{
			log_printf(LOG_ERROR, "tool_id:[%d] error.\n", p_pk->dst_id);
			return 0;
		}
		p_pk->dst_id = (unsigned short)p_info->client_id;
		i_re = bbl_tcps_send(p_dst->server_id, p_dst->connect_id, (char*)p_pk, p_pk->pk_len + 6);
	}
	return i_re;
}

int proc_yw_data_request(yw_connect_info *p_info, yw_pk_header *p_pk)
{
	int		i_re;

	log_printf(LOG_INFO,"收到数据->dst_id:[%d],cmd1:[%d],cmd2:[%d],数据长度:[%d].\n",p_pk->dst_id,p_pk->pk_cmd1,p_pk->pk_cmd2,p_pk->pk_len);

	if (p_pk->dst_id == 0 || p_pk->pk_cmd1 == YW_DELETE_AGENT)
		i_re = proc_server_request(p_info, p_pk);
	else
		i_re = route_client_request(p_info, p_pk);

	return i_re;
}

void *yw_tcps_thread(void *param)
{
	yw_connect_info	*p_info;
	struct timespec ts;
	int		i_re,offset;

	yw_pk_header	*p_pk;

	p_info = (yw_connect_info*)param;

	while(p_info->conn_flag)
	{
		//发送链接检测报文
		if (g_app_info.cur_time > p_info->last_send_time + 60)	//1分钟
			send_active_test(p_info);

		//连接超时判断
		if (g_app_info.cur_time > p_info->last_recv_time + 300)	//5分钟
		{
			log_printf(LOG_ERROR, "客户端[%s]连接超时断开.", get_client_name(p_info->client_id));
			bbl_tcps_disconnect(p_info->server_id, p_info->connect_id);
		}

		//等待接收数据
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;
    
		do { i_re = sem_timedwait(&(p_info->data_flag),&ts);
		} while(i_re < 0 && errno == EINTR);

		if (p_info->recv_len < 6)	//最小数据包
			continue;

		sem_wait(&(p_info->data_lock));

		offset = 0;
		while(offset + 6 <= p_info->recv_len)	
		{
			p_pk = (yw_pk_header*)(p_info->recv_buf + offset);
			if (p_pk->pk_len + offset + 6 > p_info->recv_len)
				break;
			//收到完整的数据包
			proc_yw_data_request(p_info,p_pk);
			offset += p_pk->pk_len + 6;
		}
		if (p_info->recv_len > offset)
			memmove(p_info->recv_buf, p_info->recv_buf + offset, p_info->recv_len - offset);
		p_info->recv_len -= offset;

		sem_post(&(p_info->data_lock));
	}
	disconnect_client(p_info->client_id);

	sem_destroy(&(p_info->data_flag));
	free(p_info);
	return (void*)0;
}

int yw_tcps_on_connect(int server_id, int connect_id, char *client_ip, int client_port, char* server_ip, void **pp_app_param) 
{
	yw_connect_info	*p_info;
	pthread_t	thread_id;

	log_printf(LOG_INFO,"新连接:connect_id[%d],client_ip[%s].\n",connect_id,client_ip);

	p_info = (yw_connect_info*)malloc(sizeof(yw_connect_info));
	if(!p_info)
	{
		log_printf(LOG_ERROR,"申请内存失败,拒绝连接请求:connect_id[%d].\n",connect_id);
		return EC_MEMORY;
	}
	memset(p_info, 0, sizeof(yw_connect_info));
	p_info->conn_flag = 1;
	p_info->recv_len = 0;
	p_info->last_send_time = g_app_info.cur_time;
	p_info->last_recv_time = g_app_info.cur_time;

	sem_init(&(p_info->data_flag),0,0);
	sem_init(&(p_info->data_lock),0,1);
	p_info->server_id = server_id;
	p_info->connect_id = connect_id;
	*pp_app_param = p_info;

	if(pthread_create(&thread_id,NULL, yw_tcps_thread,(void*)p_info) != 0)
	{
		sem_destroy(&(p_info->data_flag));
		free(p_info);
		log_printf(LOG_ERROR,"创建线程失败,拒绝连接请求:connect_id[%d].\n",connect_id);
		return EC_THREAD;
	}
	pthread_detach(thread_id);

	return 0;
}

int yw_tcps_on_break(int server_id, int connect_id, char *client_ip, int client_port, char* server_ip, void *app_param)
{
	yw_connect_info	*p_info;

	p_info = (yw_connect_info*)app_param;

	log_printf(LOG_INFO,"连接中断:connect_id[%d],client_ip[%s].\n", connect_id,client_ip);

	p_info->conn_flag = 0;
	return 0;
}

int yw_tcps_on_data(int server_id,int connect_id, char *data, int data_len,void *app_param)
{
	yw_connect_info	*p_info;

	p_info = (yw_connect_info*)app_param;

	log_printf(LOG_DEBUG,"收到数据:connect_id[%d],data_len[%d].\n",connect_id,data_len);
	hlog_printf(LOG_DEBUG,(unsigned char*)data,data_len);

	p_info->last_recv_time = g_app_info.cur_time;

	sem_wait(&(p_info->data_lock));

	if(p_info->recv_len + data_len > sizeof(p_info->recv_buf))
	{
		log_printf(LOG_ERROR,"缓冲区满,丢弃数据:connect_id[%d],data_len[%d].\n",connect_id,data_len);
	}
	else
	{
		memcpy(p_info->recv_buf + p_info->recv_len,data,data_len);
		p_info->recv_len += data_len;
	}

	sem_post(&(p_info->data_lock));

	sem_post(&(p_info->data_flag));
	return 0;
}

int yw_data_init()
{
	int		i,new_flag;
	void    *p_map;

	new_flag = 0;
	g_yw_fd = open("yw_server.dat", O_RDWR);
	if (g_yw_fd < 0)
	{
		g_yw_fd = open("yw_server.dat", O_RDWR | O_CREAT, 0777);
		if (g_yw_fd < 0)
		{
			log_printf(LOG_ERROR, "open yw_server.dat failed,errno:[%d].\n", errno);
			return EC_FAILED;
		}
		new_flag = 1;
	}

	ftruncate(g_yw_fd, sizeof(yw_file_info));

	p_map = mmap(NULL, sizeof(yw_file_info), PROT_READ | PROT_WRITE, MAP_SHARED, g_yw_fd, 0);
	if (p_map == MAP_FAILED)
	{
		log_printf(LOG_ERROR, "mmap yw_server.dat failed,errno:[%d].\n", errno);
		return EC_FAILED;
	}
	if (new_flag)
	{
		memset(p_map, 0, sizeof(yw_file_info));
		msync(p_map, sizeof(yw_file_info), MS_SYNC);
	}

	gp_yw_file = (yw_file_info*)p_map;

	sem_init(&(gp_yw_file->data_lock), 0, 1);
	memset(gp_yw_file->ti, 0, sizeof(gp_yw_file->ti));
	for (i = 0; i < MAX_AGENT_COUNT; i++)
	{
		gp_yw_file->ai[i].conn_flag = 0;
		gp_yw_file->ai[i].p_conn_info = NULL;
	}

	return 0;
}

int yw_data_close()
{
	if (gp_yw_file)
	{
		sem_destroy(&(gp_yw_file->data_lock));
		munmap(gp_yw_file, sizeof(yw_file_info));
		close(g_yw_fd);
		gp_yw_file = NULL;
	}
	return 0;
}

int yw_tcps_init()
{
	int ret = 0;

	ret = bbl_create_tcp_server("0.0.0.0",g_app_info.yw_port,yw_tcps_on_connect,yw_tcps_on_break,yw_tcps_on_data);
	if(ret < 0)
	{
		log_printf(LOG_ERROR,"bbl_create_tcp_server failed:[%d].\n",ret);
		return ret;
	}
	sg_tcp_server_id = ret;

	return 0;
}
