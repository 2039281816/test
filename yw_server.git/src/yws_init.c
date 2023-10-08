
//for yw_server module init

#include "yw_server.h"

app_info	g_app_info;

int yw_init_cfg(const char *conf_file)
{
	int		i_re;

	i_re = get_cfg_int(conf_file,"yw_port",&(g_app_info.yw_port));
	if(i_re < 0)
	{
		log_printf(LOG_ERROR,"读取配置项[yw_port]失败,错误码:[%d].\n",i_re);
		return i_re;
	}

	i_re = get_cfg_string(conf_file,"agent_password",g_app_info.agent_password,sizeof(g_app_info.agent_password));
	if(i_re < 0)
	{
		log_printf(LOG_ERROR,"读取配置项[agent_password]失败,错误码:[%d].\n",i_re);
		return i_re;
	}

	i_re = get_cfg_string(conf_file, "tool_password", g_app_info.tool_password, sizeof(g_app_info.tool_password));
	if (i_re < 0)
	{
		log_printf(LOG_ERROR, "读取配置项[tool_password]失败,错误码:[%d].\n", i_re);
		return i_re;
	}

	return i_re;
}

int yw_init(const char *conf_file)
{
	int	i_re;

	i_re = yw_init_cfg(conf_file);
	if(i_re < 0)
	{
		log_printf(LOG_CRITICAL,"初始化配置文件[%s]失败,错误码:[%d].\n",conf_file,i_re);
		return i_re;
	}

	i_re = yw_data_init();
	if (i_re < 0)
	{
		log_printf(LOG_CRITICAL, "数据初始化失败.\n");
		return EC_FAILED;
	}

	i_re = yw_tcps_init();
	if(i_re < 0)
	{
		log_printf(LOG_CRITICAL,"tcp通信模块初始化失败.\n");
		return EC_FAILED;
	}

	return 0;
}
