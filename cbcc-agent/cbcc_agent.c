
#include "cbcc_agent.h"

// forground mode flag
static bool forground = false;
static char *config_path = NULL;

static enum CBCC_DEBUG_LEVEL cbcc_debug_level = CBCC_DEBUG_LEVEL_HIGH;
static bool end_flag = false;

static bool no_ssl = false;

// print version
static void print_version()
{
	static const char build_time[] = { __DATE__ " " __TIME__ };
	printf("CBCC agent version %s (Build at '%s')\n", CBCC_VERSION_STR, build_time);
	exit(0);
}

// print usage info
static void usage()
{
	fprintf(stderr, "Usage: cbcc-agent [Options]:\n"
			"\t\t-f\t\tRun forgound mode\n"
			"\t\t-c [conf path]\tSet configuration file path\n"
			"\t\t-n\t\tRun non-SSL mode\n"
			"\t\t-d [1-4]\tSet verbose level\n"
			"\t\t-v\t\tPrint version\n");
	exit(-1);
}


// signal handler
static void signal_handler(int signum)
{
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "Main: Received signal '%d'", signum);
	end_flag = true;
}

// init signal handlers
static void init_signal()
{
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, signal_handler);
}

// read CBCC configuration

static int cbcc_agent_read_config(cbcc_agent_opt_t *opt)
{
	int ret = -1;
	
	cbcc_json_object_t agent_opt_objs[] =
	{
		{
			.key = "cbccd_srv_hname",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val = opt->accd_srv_name,
			.data_size = sizeof(opt->accd_srv_name),
		},
		{
			.key = "cbccd_srv_port",
			.type = CBCC_JSON_DATA_TYPE_INT,
			.data.int_val = &opt->accd_srv_port,
		},
	};
	
	// if config file is given, then read configuration from it
	if (config_path)
	{
		CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "Main: Parsing configuration file '%s'.", config_path);
		
		if (cbcc_json_parse_from_file(config_path, agent_opt_objs, sizeof(agent_opt_objs) / sizeof(cbcc_json_object_t)) != 0)
		{
			CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "Main: Parsing configuration file '%s' has failed.", config_path);
		}
		else
		{
			CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "Main: Parsing configuration file '%s' has succeded.", config_path);
			ret = 0;
		}
	}
	
	if (ret == -1)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "Main: Could not read configuration.");
	}
	
	return ret;
}

// cbcc agent context initialize
static int cbcc_agent_ctx_init(cbcc_agent_ctx_t *c)
{
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "Main: Initializing CBCC agent context.");
	
	// initialize context object
	memset(c, 0, sizeof(cbcc_agent_ctx_t));
	
	c->no_ssl = no_ssl;
	
	// read config
	if (cbcc_agent_read_config(&c->opt) != 0)
		return -1;
	
	// initialize session manager
	if (cbcc_session_mgr_init(c) != 0)
		return -1;
	
	// initialize configuration manager
	if (cbcc_agent_config_init(c) != 0)
		return -1;

	// initialize monitoring manager
	if (cbcc_agent_monitor_init(c) != 0)
		return -1;

	return 0;
}

// cbcc agent context finalize
static void cbcc_agent_ctx_finalize(cbcc_agent_ctx_t *c)
{
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_NOR, "Main: Finalizing CBCC agent context.");

	// finalize monitoring manager
	cbcc_agent_monitor_finalize(&c->mon_mgr);
	
	// finalize configuration manager
	cbcc_agent_config_finalize(&c->conf_mgr);
	
	// finalize session manager
	cbcc_session_mgr_finalize(&c->session_mgr);
	
	return;
}

// stop cbcc agent
void cbcc_agent_stop(struct _cbcc_agent_ctx *c)
{
	char cmd[CBCC_MAX_CMD_LEN];
	char *param;
	
	// build command
	cbcc_json_object_t cmd_jobjs[] =
	{
		{
			.key = "cmd",
			.type = CBCC_JSON_DATA_TYPE_STRING,
			.data.str_val_set = "device.agent.disable"
		}
	};
	
	cbcc_json_build(cmd_jobjs, CBCC_JOBJS_COUNT(cmd_jobjs), &param);
	
	// run command
	snprintf(cmd, sizeof(cmd), "%s '%s'", c->opt.set_script_path, param);
	
	CBCC_DEBUG_MSG(CBCC_DEBUG_LEVEL_HIGH, "MAIN: Running command '%s'", cmd);
	system(cmd);
	
	// free param
	free(param);
	
	// set end flag
	end_flag = true;
	
	return;
}

// main function
int main(int argc, char *argv[])
{
	cbcc_agent_ctx_t ctx;
	
	// check if running user is root
	if (getuid() != 0)
	{
		fprintf(stderr, "Please run cbccd as root privilege.\n");
		exit(1);
	}

	// parse arguments
	if (argc > 1)
	{
		int opt;
		while ((opt = getopt(argc, argv, "fc:d:nv")) != -1)
		{
			switch (opt)
			{
				case 'f':
					forground = true;				// set forground flag
					break;
					
				case 'c':
					config_path = optarg;				// set config path
					break;
				
				case 'd':						// set debugging level
					cbcc_debug_level = (enum CBCC_DEBUG_LEVEL) atoi(optarg);
					if (cbcc_debug_level > CBCC_DEBUG_LEVEL_VERBOSE)
						cbcc_debug_level = CBCC_DEBUG_LEVEL_VERBOSE;
					
					break;
				
				case 'n':
					no_ssl = true;
					break;
				
				case 'v':
					print_version();
					break;

				default:
					usage();
					break;
			}
		}
	}
	
	// check process is running
	pid_t pid = get_procid_by_procname(CBCC_AGENT_PROC_NAME);
	if (pid > 0)
	{
		fprintf(stderr, "Process is already running with pid '%d'.\n", pid);
		exit(1);
	}
	
	// if forground flag isn't set, then daemonize program
	if (!forground)
		daemonize();

	// write PID file
	write_pid_file(CBCC_AGENT_PROC_NAME);
	
	// init signal
	init_signal();
	
	// initializing debugging
	if (cbcc_dbg_init(CBCC_AGENT_PROC_NAME, cbcc_debug_level) != 0)
	{
		exit(1);
	}
	
	// initializing cbcc-agent context
	if (cbcc_agent_ctx_init(&ctx) != 0)
	{
		CBCC_DEBUG_ERR(CBCC_DEBUG_LEVEL_NOR, "Main: Could not initialize CBCC agent context");
		
		cbcc_agent_ctx_finalize(&ctx);
		cbcc_dbg_finalize();
		
		exit(1);
	}
	
	// main proc
	while (!end_flag)
	{
		sleep(1);
	}
	
	// finalize cbcc agent context
	cbcc_agent_ctx_finalize(&ctx);
	
	// finalize debugging
	cbcc_dbg_finalize();
	
	return 0;
}
