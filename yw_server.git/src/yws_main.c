

// for yw_server main source file

#include "yw_server.h"

static char *g_version = "v1.1 20210622";

int refresh_log_level(char *conf_file)
{
	int i_re, log_level, cur_level;

	i_re = get_cfg_int(conf_file, "log_level", &log_level);
	if (i_re == 0)
	{
		cur_level = bbl_get_log_value();
		//log_printf(LOG_CRITICAL,"日志级别:[%d : %d].\n",cur_level,log_level);
		if (log_level != cur_level)
		{
			log_printf(LOG_CRITICAL, "重新设置日志输出级别:[%d - > %d].\n", cur_level, log_level);
			bbl_set_log_value(log_level);
		}
	}
	else
		log_printf(LOG_CRITICAL, "read log_level failed,error code:[%d].\n", i_re);

	return 0;
}

char *get_module_name(char *app_name)
{
	char	*module_name;
	int		offset;

	offset = 1;

	module_name = strrchr(app_name,'/');
	if(!module_name)
	{
		module_name = strrchr(app_name,'\\');
		if(!module_name)
		{
			module_name = app_name;
			offset = 0;
		}
	}

	return (module_name + offset);
}

// 第一个参数: 配置文件名字, 第二个参数: 日志文件前缀,都可以省略 
int bpa_main(int argc, char **argv)
{
	int		i_re,count;
	char	log_prefix[64];

	if(argc == 2 && strcasecmp(argv[1],"-v") == 0)
	{
		printf("program version: %s.\n",g_version);
		return 0;
	}

	sprintf(log_prefix,"../log/%s",get_module_name(argv[0]));

	bbl_mkdir("../log");
	bbl_log_init(LOG_DEBUG,log_prefix);

	g_app_info.cur_time = bbl_get_monotonic_time();

	i_re = yw_init(CONF_FILE);
	if(i_re < 0)
	{
		log_printf(LOG_CRITICAL,"程序初始化失败,错误码:[%d].\n",i_re);
		return 0;
	}

	log_printf(LOG_INFO,"程序正常启动.\n");

	count = 0;
	while(1)
	{
		bbl_sleep(1000);
		g_app_info.cur_time = bbl_get_monotonic_time();
		if (++count >= 60)	//1分钟
		{
			refresh_log_level(CONF_FILE);
			count = 0;
		}
	}
	return 0;
}

int bpa_quit()
{
	yw_data_close();

	log_printf(LOG_INFO,"程序正常退出.\n");
	return 0;
}
