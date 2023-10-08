
//created by wangye on 2121.5.29 for yw_server header

#ifndef	YWSERVER_H
#define YWSERVER_H

#include "bbl/bbl.h"

#define MAX_AGENT_COUNT	512
#define MAX_TOOL_COUNT	8

#define TOOL_ID_BASE	10000

#define CONF_FILE	"yw_server.conf"

typedef struct {
	unsigned short	dst_id;		//通信目标ID
	unsigned char	pk_cmd1;
	unsigned char	pk_cmd2;
	unsigned short	pk_len;
	char	data[1];
} yw_pk_header;

/* pk_cmd1
云端注册：0x01
Agent列表 : 0x02
执行脚本：0x03
文件列表：0x04
文件下载：0x05
文件上传：0x06
健康数据：0x07
心跳：    0x08
删除Agent：0x09
删除文件：0x0A
修改Agent名称：0x0B
*/
#define YW_REGISTER		0x01
#define YW_LIST_AGENT	0x02
#define YW_EXEC_SCRIPT	0x03
#define YW_LIST_FILE	0x04
#define YW_DOWN_FILE	0x05
#define YW_UP_FILE		0x06
#define YW_REPORT		0x07
#define YW_ACTIVE_TEST	0x08
#define YW_DELETE_AGENT	0x09
#define YW_DELETE_FILE	0x0A
#define YW_RENAME_AGENT	0x0B

#define RESP_OK				0
#define ERR_INVALID_ID		501
#define ERR_AUTH_ERROR		502
#define ERR_NOT_REGISTER	503
#define ERR_COMM_BREAK		504
#define ERR_COMM_DATA		505
#define ERR_SYS_FAILED		506

typedef struct {
	int		yw_port;
	char	agent_password[64];
	char	tool_password[64];
	time_t	cur_time;
} app_info;

extern app_info	g_app_info;

int yw_init(const char *conf_file);
int yw_tcps_init();

int yw_data_init();
int yw_data_close();

#endif
