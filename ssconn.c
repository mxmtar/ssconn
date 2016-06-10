/* ssconn.c */

#include "autoconfig.h"

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ss_ctrl_msg.h"
#include "ss_data_msg.h"
#include "ss_status.h"
#include "x_sllist.h"
#include "x_timer.h"

#include "polygator/simcard-def.h"

#define mmax(_lhs, _rhs) ((_lhs > _rhs) ? _lhs : _rhs)
#define mmin(_lhs, _rhs) ((_lhs < _rhs) ? _lhs : _rhs)

enum {
	ATR_BYTE_UNKNOWN = 0,
	ATR_BYTE_TS,
	ATR_BYTE_T0,
	ATR_BYTE_TABCD,
	ATR_BYTE_HISTORICAL,
	ATR_BYTE_TCK,
};

#define ATR_MAXLEN 33

struct atr {
	u_int8_t data[ATR_MAXLEN];
	size_t length;

	size_t __expected;
	int __next;
	u_int8_t __y;
	u_int8_t __i;
	u_int8_t __abcd;
	u_int8_t __historical;
	u_int16_t __proto;
	int __proto_deafult;
};

void atr_init(struct atr *atr)
{
	atr->length = 0;
	atr->__expected = 2;
	atr->__next = ATR_BYTE_TS;
	atr->__y = 0;
	atr->__i = 0;
	atr->__abcd = 4;
	atr->__historical = 0;
	atr->__proto = 0;
	atr->__proto_deafult = 1;
}

int atr_is_complete(struct atr *atr)
{
	if (atr->length == atr->__expected) {
		return -1;
	} else {
		return 0;
	}
}

int atr_need_tck(struct atr *atr)
{
	u_int16_t proto;

	if (atr->__proto_deafult) {
		proto = 1;
	} else {
		proto = atr->__proto;
	}

	proto >>= 1;

	if (proto) {
		return -1;
	} else {
		return 0;
	}
}

int atr_read_byte(struct atr *atr, u_int8_t byte)
{
	size_t i;
	u_int8_t chk;
	u_int8_t proto;
	int ext;

	atr->data[atr->length++] = byte;

	switch (atr->__next) {
		case ATR_BYTE_TS:
			if (byte == 0x3b) {
				atr->__next = ATR_BYTE_T0;
			} else {
				return -1;
			}
			break;
		case ATR_BYTE_T0:
			// get historical bytes length
			atr->__historical = byte & 0xf;
			atr->__expected += atr->__historical;
		case ATR_BYTE_TABCD:
			if (atr->__abcd == 4) {
				// reset TX counter
				atr->__abcd = 0;
				// store T indicator
				proto = byte & 0xf;
				if (atr->__i) {
					// check proto number
					if ((1 << proto) >= atr->__proto) {
						atr->__proto_deafult = 0;
						atr->__proto |= (1 << proto); // set proto number
					} else {
						return -1;
					}
				}
				// store Y indicator
				atr->__y = (byte >> 4) & 0xf;
				// increment Y index
				atr->__i++;
			}
			// get next byte type
			if (atr->__y) {
				while (atr->__abcd < 4) {
					atr->__abcd++;
					ext = atr->__y & 1;
					atr->__y >>= 1;
					if (ext) {
						atr->__next = ATR_BYTE_TABCD;
						atr->__expected++;
						break;
					}
				}
			} else if (atr->__historical) {
				atr->__next = ATR_BYTE_HISTORICAL;
			} else if (atr_need_tck(atr)) {
				atr->__next = ATR_BYTE_TCK;
				atr->__expected += 1;
			} else {
				atr->__next = ATR_BYTE_UNKNOWN;
			}
			break;
		case ATR_BYTE_HISTORICAL:
			if (atr->__historical--) {
				atr->__next = ATR_BYTE_HISTORICAL;
				if ((!atr->__historical) && (atr_need_tck(atr))) {
					atr->__next = ATR_BYTE_TCK;
					atr->__expected += 1;
				}
			} else {
				atr->__next = ATR_BYTE_UNKNOWN;
			}
			break;
		case ATR_BYTE_TCK:
			chk = 0;
			for (i = 1; i < atr->length; i++) {
				chk ^= atr->data[i];
			}
			if (chk) {
				return -1;
			}
			atr->__next = ATR_BYTE_UNKNOWN;
			break;
		default:
			return -1;
	}

	return 0;
}

int string_is_digit(const char *str)
{
	int len;
	char *test;

	if (!(test = (char *)str)) {
		return 0;
	}
	if (!(len = strlen(test))) {
		return 0;
	}
	while (len--) {
		if (!isdigit(*test++)) {
			return 0;
		}
	}
	return -1;
}

int is_int_value_in_set(int value, const char *set)
{
	int res;
	int min, max;
	char *chunk, *next, *input, *minp, *maxp;

	res = 0; // out of set
	input = strdup(set);

	if (!input) {
		res = -1; // in set
		goto is_int_value_in_set_end;
	}
	next = input;
	while (next) {
		chunk = strsep(&next, ",");
		if (chunk) {
			if (!strcasecmp("all", chunk)) {
				res = -1; // in set
				goto is_int_value_in_set_end;
			}
			min = max = -1;
			maxp = chunk;
			minp = strsep(&maxp, "-");
			if (string_is_digit(minp)) {
				min = max = atoi(minp);
			}
			if (string_is_digit(maxp)) {
				max = atoi(maxp);
			}
			if ((max >= min) && (value >= min) && (value <= max)) {
				res = -1; // in set
				goto is_int_value_in_set_end;
			}
		}
	}

is_int_value_in_set_end:
	if (input) {
		free(input);
	}
	return res;
}

void dumphex(FILE *fp, int hl, const void *data, size_t length)
{
	size_t i;
	const unsigned char *tp = data;

	for (i = 0; i < length; i++) {
		if ((i % 16) == 0) {
			if (i) {
				fprintf(fp, "\n");
			}
			fprintf(fp, "%0*x: ", hl, (unsigned int)i);
		} else if ((i) && ((i % 8) == 0)) {
			fprintf(fp, "  ");
		} else if (i) {
			fprintf(fp, " ");
		}
		fprintf(fp, "%02x", tp[i]);
	}
	fprintf(fp, "\n");
}

void dumptime(FILE *fp)
{
	struct timeval tv;
	struct tm *tmptr;

	gettimeofday(&tv, NULL);
	tmptr = localtime(&tv.tv_sec);
	fprintf(fp, "%4d/%02d/%02d %02d:%02d:%02d.%06u: ",
		tmptr->tm_year + 1900,
		tmptr->tm_mon + 1,
		tmptr->tm_mday,
		tmptr->tm_hour,
		tmptr->tm_min,
		tmptr->tm_sec,
		(unsigned int)(tv.tv_usec));
}

static int get_gsm_module_vio(const char *board, unsigned int channel)
{
	FILE *fp;
	char buf[256];
	char name[64];
	char sim[64];
	char type[64];
	unsigned int pos;
	unsigned int vin_num;
	char vc_type[4];
	unsigned int vc_slot;
	unsigned int vio;
	int res = -1;

	if (board) {
		if ((fp = fopen(board, "r"))) {
			while (fgets(buf, sizeof(buf), fp)) {
				if (sscanf(buf, "GSM%u %[0-9A-Za-z-] %[0-9A-Za-z/!-] %[0-9A-Za-z/!-] VIN%u%[ACMLP]%u VIO=%u", &pos, type, name, sim, &vin_num, vc_type, &vc_slot, &vio) == 8) {
					if (pos == channel) {
						res = vio;
						break;
					}
				}
			}
			fclose(fp);
		} else {
			errno = ENODEV;
		}
	} else {
		errno = ENODEV;
	}

	return res;
}

static int set_gsm_module_power(const char *board, unsigned int channel, int state)
{
	FILE *fp;
	int res = -1;

	if (board) {
		if ((fp = fopen(board, "w"))) {
			fprintf(fp, "GSM%u PWR=%d", channel, state);
			fclose(fp);
			res = 0;
		} else {
			errno = ENODEV;
		}
	} else {
		errno = ENODEV;
	}

	return res;
}

static int press_gsm_module_key(const char *board, unsigned int channel, int state)
{
	FILE *fp;
	int res = -1;

	if (board) {
		if ((fp = fopen(board, "w"))) {
			fprintf(fp, "GSM%u KEY=%d", channel, state);
			fclose(fp);
			res = 0;
		} else {
			errno = ENODEV;
		}
	} else {
		errno = ENODEV;
	}

	return res;
}

static int set_gsm_module_serial_port(const char *board, unsigned int channel, int port)
{
	FILE *fp;
	int res = -1;

	if (board) {
		if ((fp = fopen(board, "w"))) {
			fprintf(fp, "GSM%u SERIAL=%d", channel, port);
			fclose(fp);
			res = 0;
		} else {
			errno = ENODEV;
		}
	} else {
		errno = ENODEV;
	}

	return res;
}

static int set_board_simbank_mode(const char *board)
{
	FILE *fp;
	int res = -1;

	if (board) {
		if ((fp = fopen(board, "w"))) {
			fprintf(fp, "SIMBANK MODE=0");
			fclose(fp);
			res = 0;
		} else {
			errno = ENODEV;
		}
	} else {
		errno = ENODEV;
	}

	return res;
}

int run = 1;
int daemonize = 1;

char *log_dump_dir = "/var/log/ssconn";
char *log_file = NULL;
char *pid_file = "/var/run/ssconn.pid";

char *prefix = "ssconn";
static char options[] = "c:d:efi:l:p:s:u:v";
static char usage[] = "Usage: ssconn [options]\n"
"Options:\n"
"\t-c <port> - control server port (default:9005)\n"
"\t-d <unit> [<set>] - dump data \"control\", \"data\", \"channel\"\n"
"\t-e - erase dump & log file(s)\n"
"\t-f - foreground mode\n"
"\t-i <id> - server id (32bit hex notation) (default:random)\n"
"\t-l <unit> [<set>] - log \"general\", \"control\", \"data\", \"channel\"\n"
"\t-p <password> - user password (default:password)\n"
"\t-s <port> - SIM-data server port (default:9006)\n"
"\t-u <user> - user login (default:login)\n"
"\t-v - print version\n";

#define LOG(_fmt, _args...) \
do { \
	FILE *__fp; \
	if ((log_file) && (__fp = fopen(log_file, "a"))) { \
		dumptime(__fp); \
		fprintf(__fp, _fmt, ##_args); \
		fflush(__fp); \
		fclose(__fp); \
	} \
	if (!daemonize) { \
		dumptime(stdout); \
		fprintf(stdout, _fmt, ##_args); \
		fflush(stdout); \
	} \
} while(0)

struct board;
struct channel {
	size_t id;
	unsigned int position;
	struct board *board;
	char *device;
	char *tty_data_path;
	char *sim_data_path;

	int sim_data_fd;

	struct atr atr;

	u_int8_t sim_cmd[512];
	u_int8_t sim_cmd_ack;
	size_t sim_cmd_length;
	size_t sim_cmd_wait;
	size_t sim_cmd_proc;

	struct channel_timers {
		struct x_timer wait;
		struct x_timer atr;
		struct x_timer command;
		struct x_timer start;
		struct x_timer poweron;
		struct x_timer keypress;
		struct x_timer wait_vio_up;
		struct x_timer check_vio_up;
		struct x_timer wait_vio_down;
		struct x_timer check_vio_down;
		struct x_timer reset;
	} timers;

	struct channel_flags {
		unsigned int run:1;
		unsigned int check_vio_up:1;
		unsigned int check_vio_down:1;
	} flags;

	struct channel_signals {
		unsigned int enable:1;
		unsigned int shutdown:1;
		unsigned int restart:1;
	} signals;


	char *dump;
	char *log;

	struct channel *next; // list entry
};
struct board {
	char *type;
	char *name;
	char *path;

	x_sllist_struct_declare(channel_list, struct channel);

	struct board *next; // list entry
};

char *default_user = "login";
char *default_password = "password";
int default_tcp_cs_port = 9005;
int default_tcp_ds_port = 9006;

void main_exit(int signal)
{
	LOG("%s: catch signal \"%d\"\n", prefix, signal);
	switch (signal) {
		case SIGSEGV:
			exit(EXIT_FAILURE);
			break;
		default:
			run = 0;
			break;
	}
}

int main(int argc, char **argv)
{
	size_t i;

	int tmpi;
	char *tmpcp;
	int tmp_flags;
	int tmp_opt;
	u_int16_t tmpu16;

	char buf[256];
	char type[64];
	char name[64];
	char tty_data_path[64];
	char sim_data_path[64];

	char tcp_cs_prefix[64];
	int tcp_cs_sock = -1;
	int tcp_cs_port = 0;
	struct sockaddr_in tcp_cs_addr;
	socklen_t tcp_cs_addrlen;

	char tcp_cc_prefix[64];
	int tcp_cc_sock = -1;
	struct sockaddr_in tcp_cc_addr;
// 	socklen_t tcp_cc_addrlen;
	u_int8_t tcp_cc_recv_buf[0x10000];
	size_t tcp_cc_recv_length = 0;
	size_t tcp_cc_recv_wait = 0;
	u_int8_t tcp_cc_xmit_buf[0x10000];
	size_t tcp_cc_xmit_length;
	char *tcp_cc_dump = NULL;
	char *tcp_cc_log = NULL;
	struct tcp_cc_timers {
		struct x_timer watchdog;
	} tcp_cc_timers;
	struct tcp_cc_flags {
		unsigned int close:1;
	} tcp_cc_flags;
	struct ss_ctrl_msg_req_hdr *ptr_ss_ctrl_msg_req_hdr;
	struct ss_ctrl_msg_resp_hdr *ptr_ss_ctrl_msg_resp_hdr;

	char tcp_ds_prefix[64];
	int tcp_ds_sock = -1;
	int tcp_ds_port = 0;
	struct sockaddr_in tcp_ds_addr;
	socklen_t tcp_ds_addrlen;

	char tcp_dc_prefix[64];
	int tcp_dc_sock = -1;
	struct sockaddr_in tcp_dc_addr;
// 	socklen_t tcp_dc_addrlen;
	u_int8_t tcp_dc_recv_buf[0x10000];
	size_t tcp_dc_recv_length = 0;
	size_t tcp_dc_recv_wait = 0;
	u_int8_t tcp_dc_xmit_buf[0x10000];
	size_t tcp_dc_xmit_length = 0;
	char *tcp_dc_dump = NULL;
	char *tcp_dc_log = NULL;
	struct tcp_dc_timers {
		struct x_timer auth;
		struct x_timer watchdog;
	} tcp_dc_timers;
	struct tcp_dc_flags {
		unsigned int close:1;
	} tcp_dc_flags;
	struct ss_data_msg_generic *ptr_ss_data_msg_generic;
	struct ss_data_msg_auth_req *ptr_ss_data_msg_auth_req;
	struct ss_data_msg_auth_resp *ptr_ss_data_msg_auth_resp;
	struct ss_data_msg_comb_hdr *ptr_ss_data_msg_comb_hdr;
	struct ss_data_msg_comb_chunk_hdr *ptr_ss_data_msg_comb_chunk_hdr;

	struct sockaddr_in tcp_rem_addr;
	socklen_t tcp_rem_addrlen;

	unsigned int pos;
	unsigned int vin_num;
	char vc_type[4];
	unsigned int vc_slot;
	unsigned int vio;

	struct simcard_data sc_data;

	unsigned short status;

	struct timespec ts_contest, ts_planned;

	char path[PATH_MAX];
	pid_t pid;
	FILE *fp;
	struct timeval timeout;
	fd_set rfds;
	int maxfd;
	int res;

	char *channel_dump = NULL;
	char *channel_log = NULL;

	int log_dump_erase = 0;
	char *log_general = NULL;
	char *user = NULL;
	char *password = NULL;

	size_t channel_count = 0;
	u_int32_t id = 0;

	struct channel *chnl, *t_chnl;
	struct board *brd, *t_brd;
	x_sllist_struct_declare(board_list, struct board);
	x_sllist_init(board_list);

	// get options
	while ((tmpi = getopt(argc, argv, options)) != -1) {
		switch (tmpi) {
			case 'c':
				tcp_cs_port = atoi(optarg);
				break;
			case 'd':
				if (!strcmp(optarg, "control")) {
					tcp_cc_dump = "all";
				} else if (!strcmp(optarg, "data")) {
					tcp_dc_dump = "all";
				} else if (!strcmp(optarg, "channel")) {
					channel_dump = argv[optind];
					if ((!channel_dump) || (*channel_dump == '-')) {
						channel_dump = "all";
					}
				}
				break;
			case 'e':
				log_dump_erase = 1;
				break;
			case 'f':
				daemonize = 0;
				log_dump_dir = ".";
				break;
			case 'i':
				if (sscanf(optarg, "%08x", &id) != 1) {
					id = 0;
				}
				break;
			case 'l':
				if (!strcmp(optarg, "general")) {
					log_general = "all";
				} else if (!strcmp(optarg, "control")) {
					tcp_cc_log = "all";
				} else if (!strcmp(optarg, "data")) {
					tcp_dc_log = "all";
				} else if (!strcmp(optarg, "channel")) {
					channel_log = argv[optind];
					if ((!channel_log) || (*channel_log == '-')) {
						channel_log = "all";
					}
				}
				break;
			case 'p':
				password = optarg;
				break;
			case 's':
				tcp_ds_port = atoi(optarg);
				break;
			case 'u':
				user = optarg;
				break;
			case 'v':
				printf("%s: version %s\n", prefix, VERSION);
				exit(EXIT_SUCCESS);
				break;
			default:
				printf("%s", usage);
				exit(EXIT_FAILURE);
		}
	}
	// check parameters
	if ((tcp_cs_port < 1) || (tcp_cs_port > 65535)) {
		tcp_cs_port = default_tcp_cs_port;
	}
	if ((tcp_ds_port < 1) || (tcp_ds_port > 65535)) {
		tcp_ds_port = default_tcp_ds_port;
	}
	if (!user) {
		user = default_user;
	}
	if (!password) {
		password = default_password;
	}
	if (!id) {
		id = random();
	}
	// prepare log path
	if (log_general) {
		if ((!mkdir(log_dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
			snprintf(path, sizeof(path), "%s/general.log", log_dump_dir);
			log_file = strdup(path);
			if (log_dump_erase) {
				unlink(path);
			}
		}
	}
	// check for daemonize
	if (daemonize) {
		// change current working directory
		if (chdir("/") < 0) {
			LOG("%s: can't change working directory to \"/\": %s\n", prefix, strerror(errno));
			goto main_end;
		}
		setbuf(stdout, 0);
		setbuf(stderr, 0);
		pid = -1;
		if ((pid = fork()) < 0) {
			LOG("%s: fork(): %s\n", prefix, strerror(errno));
			goto main_end;
		} else if (pid != 0) {
			// parent process
			exit(EXIT_SUCCESS);
		}
		// create new session to drop controlling tty terminal
		if (setsid() < 0) {
			LOG("%s: setsid(): %s\n", prefix, strerror(errno));
		}
		// try fork again to drop leader status in new process group
		pid = -1;
		if ((pid = fork()) < 0) {
			LOG("%s: fork(): %s\n", prefix, strerror(errno));
			goto main_end;
		} else if (pid != 0) {
			// parent process
			exit(EXIT_SUCCESS);
		}
		// create pid file
		pid = getpid();
		if ((fp = fopen(pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)pid);
			fclose(fp);
		} else {
			LOG("%s: can't create pid file \"%s\": %s\n", prefix, pid_file, strerror(errno));
			goto main_end;
		}
		if (!freopen("/dev/null", "r", stdin)) {
			LOG("%s: can't reopen \"%s\" file: %s\n", prefix, "stdin", strerror(errno));
			goto main_end;
		}
		if (!freopen("/dev/null", "w", stdout)) {
			LOG("%s: can't reopen \"%s\" file: %s\n", prefix, "stdout", strerror(errno));
			goto main_end;
		}
		if (!freopen("/dev/null", "w", stderr)) {
			LOG("%s: can't reopen \"%s\" file: %s\n", prefix, "stderr", strerror(errno));
			goto main_end;
		}
	}

	setbuf(stdout, 0);
	setbuf(stderr, 0);

	// register signal handler
	signal(SIGTERM, main_exit);
	signal(SIGINT, main_exit);
	signal(SIGSEGV, main_exit);
	signal(SIGALRM, main_exit);
	signal(SIGPIPE, SIG_IGN);

	LOG("%s: version %s started\n", prefix, VERSION);

	// scan polygator subsystem
	snprintf(path, PATH_MAX, "/dev/%s", "polygator/subsystem");
	if ((fp = fopen(path, "r"))) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (sscanf(buf, "%64[0-9a-z-] %64[0-9a-z/!-]", type, name) == 2) {
				for (i = 0; i < strlen(name); i++) {
					if (name[i] == '!') {
						name[i] = '/';
					}
				}
				tmpcp =  strrchr(name, '/');
				LOG("%s: found board type=\"%s\" name=\"%s\"\n", prefix, type, (tmpcp)?(tmpcp + 1):(name));
				if (!(brd = calloc(1, sizeof(struct board)))) {
					LOG("can't get memory for struct board\n");
					goto main_end;
				}
				// add board into general board list
				x_sllist_insert_tail(board_list, brd);
				// init board
				brd->type = strdup(type);
				brd->name = strdup((tmpcp)?(tmpcp + 1):(name));
				snprintf(path, PATH_MAX, "/dev/%s", name);
				brd->path = strdup(path);
				set_board_simbank_mode(brd->path);
			}
		}
		fclose(fp);
		fp = NULL;
	} else {
		if (errno != ENOENT) {
			LOG("unable to scan Polygator subsystem: %d %s\n", errno, strerror(errno));
			goto main_end;
		} else {
			LOG("%s: subsystem not found\n", prefix);
		}
	}
	for (brd = board_list.head; brd; brd = brd->next) {
		if (!(fp = fopen(brd->path, "r"))) {
			LOG("unable to scan Polygator board \"%s\": %s\n", brd->name, strerror(errno));
			goto main_end;
		} else {
			while (fgets(buf, sizeof(buf), fp)) {
				if (sscanf(buf, "GSM%u %[0-9A-Za-z-] %64[0-9A-Za-z/!-] %64[0-9A-Za-z/!-] VIN%u%[ACMLP]%u VIO=%u", &pos, type, tty_data_path, sim_data_path, &vin_num, vc_type, &vc_slot, &vio) == 8) {
					snprintf(buf, sizeof(buf), "%s-gsm%u", brd->name, pos);
					LOG("%s: found GSM channel=\"%s\"\n", prefix, buf);
					if (!(chnl = calloc(1, sizeof(struct channel)))) {
						LOG("can't get memory for struct channel\n");
						goto main_end;
					}
					// add channel into board channel list
					x_sllist_insert_tail(brd->channel_list, chnl);
					// init GSM channel
					chnl->position = pos;
					chnl->board = brd;
					chnl->device = strdup(buf);
					for (i = 0; i < strlen(tty_data_path); i++) {
						if (tty_data_path[i] == '!') {
							tty_data_path[i] = '/';
						}
					}
					snprintf(path, sizeof(path), "/dev/%s", tty_data_path);
					chnl->tty_data_path = strdup(path);
					for (i = 0; i < strlen(sim_data_path); i++) {
						if (sim_data_path[i] == '!') {
							sim_data_path[i] = '/';
						}
					}
					snprintf(path, sizeof(path), "/dev/%s", sim_data_path);
					chnl->sim_data_path = strdup(path);
					// open SIM-data file
					if ((chnl->sim_data_fd = open(chnl->sim_data_path, O_RDWR | O_NONBLOCK)) < 0) {
						LOG("%s: open(%s): %s\n", chnl->device, chnl->sim_data_path, strerror(errno));
						goto main_end;
					}
					// increment channel count
					chnl->id = channel_count++;
					// disable GSM module power supply
					set_gsm_module_power(brd->path, pos, 0);
					// release GSM module control key
					press_gsm_module_key(brd->path, pos, 0);
					// set 0 serial port
					set_gsm_module_serial_port(brd->path, pos, 0);
					// dump
					if ((channel_dump) && (is_int_value_in_set(chnl->id, channel_dump))) {
						if ((!mkdir(log_dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
							snprintf(path, sizeof(path), "%s/chnl%03lu.dump", log_dump_dir, (unsigned long int)chnl->id);
							chnl->dump = strdup(path);
							if (log_dump_erase) {
								unlink(path);
							}
						}
					}
					// log
					if ((channel_log) && (is_int_value_in_set(chnl->id, channel_log))) {
						if ((!mkdir(log_dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
							snprintf(path, sizeof(path), "%s/chnl%03lu.log", log_dump_dir, (unsigned long int)chnl->id);
							chnl->log = strdup(path);
							if (log_dump_erase) {
								unlink(path);
							}
						}
					}
				}
			}
			fclose(fp);
		}
	}
	// start TCP control server
	snprintf(tcp_cs_prefix, sizeof(tcp_cs_prefix), "Control Server(%d)", tcp_cs_port);
	if ((tcp_cs_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		LOG("%s: socket(PF_INET, SOCK_STREAM, 0) failed - %s\n", tcp_cs_prefix, strerror(errno));
		goto main_end;
	}
	if ((tmp_flags = fcntl(tcp_cs_sock, F_GETFL)) < 0) {
		LOG("%s: fcntl(tcp_cs_sock, F_GETFL) failed - %s\n", tcp_cs_prefix, strerror(errno));
		goto main_end;
	}
	if (fcntl(tcp_cs_sock, F_SETFL, tmp_flags|O_NONBLOCK) < 0) {
		LOG("%s: fcntl(tcp_cs_sock, F_SETFL) failed - %s\n", tcp_cs_prefix, strerror(errno));
		goto main_end;
	}
	tmp_opt = 1;
	if (setsockopt(tcp_cs_sock, SOL_SOCKET, SO_REUSEADDR, &tmp_opt, sizeof(tmp_opt)) < 0) {
		LOG("%s: setsockopt(tcp_cs_sock, SOL_SOCKET, SO_REUSEADDR) failed - %s\n", tcp_cs_prefix, strerror(errno));
		goto main_end;
	}
	memset(&tcp_cs_addr, 0, sizeof(struct sockaddr_in));
	tcp_cs_addr.sin_family = AF_INET;
	tcp_cs_addr.sin_port = htons(tcp_cs_port);
	tcp_cs_addr.sin_addr.s_addr = ntohl(INADDR_ANY);
	tcp_cs_addrlen = sizeof(struct sockaddr_in);
	if (bind(tcp_cs_sock, (struct sockaddr *)&tcp_cs_addr, tcp_cs_addrlen) < 0) {
		LOG("%s: bind() failed - %s\n", tcp_cs_prefix, strerror(errno));
		goto main_end;
	}
	if (listen(tcp_cs_sock, 4) < 0) {
		LOG("%s: listen() failed - %s\n", tcp_cs_prefix, strerror(errno));
		goto main_end;
	}
	// start TCP SIM-data server
	snprintf(tcp_ds_prefix, sizeof(tcp_ds_prefix), "SIM-data Server(%d)", tcp_ds_port);
	if ((tcp_ds_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		LOG("%s: socket(PF_INET, SOCK_STREAM, 0) failed - %s\n", tcp_ds_prefix, strerror(errno));
		goto main_end;
	}
	if ((tmp_flags = fcntl(tcp_ds_sock, F_GETFL)) < 0) {
		LOG("%s: fcntl(tcp_ds_sock, F_GETFL) failed - %s\n", tcp_ds_prefix, strerror(errno));
		goto main_end;
	}
	if (fcntl(tcp_ds_sock, F_SETFL, tmp_flags|O_NONBLOCK) < 0) {
		LOG("%s: fcntl(tcp_ds_sock, F_SETFL) failed - %s\n", tcp_ds_prefix, strerror(errno));
		goto main_end;
	}
	tmp_opt = 1;
	if (setsockopt(tcp_ds_sock, SOL_SOCKET, SO_REUSEADDR, &tmp_opt, sizeof(tmp_opt)) < 0) {
		LOG("%s: setsockopt(tcp_ds_sock, SOL_SOCKET, SO_REUSEADDR) failed - %s\n", tcp_ds_prefix, strerror(errno));
		goto main_end;
	}
	memset(&tcp_ds_addr, 0, sizeof(struct sockaddr_in));
	tcp_ds_addr.sin_family = AF_INET;
	tcp_ds_addr.sin_port = htons(tcp_ds_port);
	tcp_ds_addr.sin_addr.s_addr = ntohl(INADDR_ANY);
	tcp_ds_addrlen = sizeof(struct sockaddr_in);
	if (bind(tcp_ds_sock, (struct sockaddr *)&tcp_ds_addr, tcp_ds_addrlen) < 0) {
		LOG("%s: bind() failed - %s\n", tcp_ds_prefix, strerror(errno));
		goto main_end;
	}
	if (listen(tcp_ds_sock, 4) < 0) {
		LOG("%s: listen() failed - %s\n", tcp_ds_prefix, strerror(errno));
		goto main_end;
	}
	// init TCP control client
	// socket
	tcp_cc_sock = -1;
	// timers
	memset(&tcp_cc_timers, 0, sizeof(struct tcp_cc_timers));
	// flags
	memset(&tcp_cc_flags, 0, sizeof(struct tcp_cc_flags));
	// receiving buffer
	tcp_cc_recv_length = 0;
	tcp_cc_recv_wait = 1;
	// transmiting buffer
	tcp_cc_xmit_length = 0;
	// dump
	if (tcp_cc_dump) {
		if ((!mkdir(log_dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
			snprintf(path, sizeof(path), "%s/control.dump", log_dump_dir);
			tcp_cc_dump = strdup(path);
			if (log_dump_erase) {
				unlink(path);
			}
		}
	}
	// log
	if (tcp_cc_log) {
		if ((!mkdir(log_dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
			snprintf(path, sizeof(path), "%s/control.log", log_dump_dir);
			tcp_cc_log = strdup(path);
			if (log_dump_erase) {
				unlink(path);
			}
		}
	}
	// init TCP SIM-data client
	// socket
	tcp_dc_sock = -1;
	// timers
	memset(&tcp_dc_timers, 0, sizeof(struct tcp_dc_timers));
	// flags
	memset(&tcp_dc_flags, 0, sizeof(struct tcp_dc_flags));
	// receiving buffer
	tcp_dc_recv_length = 0;
	tcp_dc_recv_wait = 1;
	// transmiting buffer
	tcp_dc_xmit_length = 0;
	// dump
	if (tcp_dc_dump) {
		if ((!mkdir(log_dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
			snprintf(path, sizeof(path), "%s/data.dump", log_dump_dir);
			tcp_dc_dump = strdup(path);
			if (log_dump_erase) {
				unlink(path);
			}
		}
	}
	// log
	if (tcp_dc_log) {
		if ((!mkdir(log_dump_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) || (errno == EEXIST))) {
			snprintf(path, sizeof(path), "%s/data.log", log_dump_dir);
			tcp_dc_log = strdup(path);
			if (log_dump_erase) {
				unlink(path);
			}
		}
	}
	// main loop
	while (run) {
		// check control client for action
		// xmit data
		if (tcp_cc_xmit_length) {
			if (tcp_cc_sock > 0) {
				// dump
				if ((tcp_cc_dump) && (fp = fopen(tcp_cc_dump, "a"))) {
					dumptime(fp);
					fprintf(fp, "Data send length=%lu\n", (unsigned long int)tcp_cc_xmit_length);
					dumphex(fp, 4, tcp_cc_xmit_buf, tcp_cc_xmit_length);
					fclose(fp);
				}
				// send data
				if (send(tcp_cc_sock, tcp_cc_xmit_buf, tcp_cc_xmit_length, 0) < 0) {
					LOG("%s: send(tcp_cc_sock) failed - %s\n", tcp_cc_prefix, strerror(errno));
					// set close flag
					tcp_cc_flags.close = 1;
				}
			}
			tcp_cc_xmit_length = 0;
		}
		// timers
#if 0
		// watchdog
		if (is_x_timer_enable(tcp_cc_timers.watchdog) && is_x_timer_fired(tcp_cc_timers.watchdog)) {
			x_timer_stop(tcp_cc_timers.watchdog);
			LOG("%s: watchdog timer fired\n", tcp_cc_prefix);
			// set close flag
			tcp_cc_flags.close = 1;
		}
#endif
		// flags
		// close
		if (tcp_cc_flags.close) {
			tcp_cc_flags.close = 0;
// 			LOG("%s: Connection with \"%s:%u\" closed\n", tcp_cs_prefix, inet_ntoa(tcp_cc_addr.sin_addr), ntohs(tcp_cc_addr.sin_port));
			// on close action
			x_timer_stop(tcp_cc_timers.watchdog);
			close(tcp_cc_sock);
			tcp_cc_sock = -1;
			tcp_cc_recv_length = 0;
			tcp_cc_recv_wait = sizeof(struct ss_ctrl_msg_req_hdr);
			tcp_cc_xmit_length = 0;
		}
		// check SIM-data client for action
		// xmit data
		if (tcp_dc_xmit_length) {
			if (tcp_dc_sock > 0) {
				// dump
				if ((tcp_dc_dump) && (fp = fopen(tcp_dc_dump, "a"))) {
					dumptime(fp);
					fprintf(fp, "Data send length=%lu\n", (unsigned long int)tcp_dc_xmit_length);
					dumphex(fp, 4, tcp_dc_xmit_buf, tcp_dc_xmit_length);
					fclose(fp);
				}
				// send data
				if (send(tcp_dc_sock, tcp_dc_xmit_buf, tcp_dc_xmit_length, 0) < 0) {
					LOG("%s: send(tcp_dc_sock) failed - %s\n", tcp_dc_prefix, strerror(errno));
					// set close flag
					tcp_dc_flags.close = 1;
				}
			}
			tcp_dc_xmit_length = 0;
		}
		// timers
		// auth
		if (is_x_timer_enable(tcp_dc_timers.auth) && is_x_timer_fired(tcp_dc_timers.auth)) {
			x_timer_stop(tcp_dc_timers.auth);
			LOG("%s: time for authorization expired\n", tcp_dc_prefix);
			// set close flag
			tcp_dc_flags.close = 1;
		}
#if 0
		// watchdog
		if (is_x_timer_enable(tcp_dc_timers.watchdog) && is_x_timer_fired(tcp_dc_timers.watchdog)) {
			x_timer_stop(tcp_dc_timers.watchdog);
			LOG("%s: watchdog timer fired\n", tcp_dc_prefix);
			// set close flag
			tcp_dc_flags.close = 1;
		}
#endif
		// flags
		// close
		if (tcp_dc_flags.close) {
			tcp_dc_flags.close = 0;
			LOG("%s: Connection with \"%s:%u\" closed\n", tcp_ds_prefix, inet_ntoa(tcp_dc_addr.sin_addr), ntohs(tcp_dc_addr.sin_port));
			// on close action
			x_timer_stop(tcp_dc_timers.auth);
			x_timer_stop(tcp_dc_timers.watchdog);
			close(tcp_dc_sock);
			tcp_dc_sock = -1;
			tcp_dc_recv_length = 0;
			tcp_dc_recv_wait = 1;
			tcp_dc_xmit_length = 0;
			// disable all channel
			for (brd = board_list.head; brd; brd = brd->next) {
				for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
					if (chnl->flags.run) {
						chnl->flags.run = 0;
						chnl->signals.shutdown = 1;
						// delete ATR
						chnl->atr.length = 0;
						// stop wait timer
						x_timer_stop(chnl->timers.wait);
						// stop command timer
						x_timer_stop(chnl->timers.command);
						// stop atr timer
						x_timer_stop(chnl->timers.atr);
					}
				}
			}
		}
		// check channel for action
		for (brd = board_list.head; brd; brd = brd->next) {
			for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
				// timers
				// wait
				if (is_x_timer_enable(chnl->timers.wait) && is_x_timer_fired(chnl->timers.wait)) {
					// write 0x60
					sc_data.header.type = SIMCARD_CONTAINER_TYPE_DATA;
					sc_data.header.length = 1;
					sc_data.container.data[0] = 0x60;
					if (write(chnl->sim_data_fd, &sc_data, sizeof(sc_data.header) + sc_data.header.length) < 0) {
						LOG("%s: write(sim_data_fd): %s\n", chnl->device, strerror(errno));
						goto main_end;
					}
					// dump
					if ((chnl->dump) && (fp = fopen(chnl->dump, "a"))) {
						dumptime(fp);
						fprintf(fp, "Write data length=%u\n", sc_data.header.length);
						dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
						fclose(fp);
					}
					// restart wait timer
					x_timer_set_ms(chnl->timers.wait, 500);
				}
				// command
				if (is_x_timer_enable(chnl->timers.command) && is_x_timer_fired(chnl->timers.command)) {
					LOG("%s: Command timer expired\n", chnl->device);
					x_timer_stop(chnl->timers.command);
					// restart GSM module
					chnl->signals.restart = 1;
				}
				// atr
				if (is_x_timer_enable(chnl->timers.atr) && is_x_timer_fired(chnl->timers.atr)) {
					LOG("%s: ATR timer expired\n", chnl->device);
					x_timer_stop(chnl->timers.atr);
					// restart GSM module
					chnl->signals.restart = 1;
				}
				// start
				if (is_x_timer_enable(chnl->timers.start) && is_x_timer_fired(chnl->timers.start)) {
					x_timer_stop(chnl->timers.start);
					// get GSM module vio
					if ((res = get_gsm_module_vio(chnl->board->path, chnl->position)) < 0) {
						LOG("%s: write(%s, %u): %s\n", chnl->device, chnl->board->path, chnl->position, strerror(errno));
						goto main_end;
					} else {
						if (res) {
							// restart GSM module
							chnl->signals.restart = 1;
						} else {
							// enable GSM module power supply
							set_gsm_module_power(chnl->board->path, chnl->position, 1);
							LOG("%s: PWR=1\n", chnl->device);
							// start poweron timer
							x_timer_set_second(chnl->timers.poweron, 3);
						}
					}
				}
				// poweron
				if (is_x_timer_enable(chnl->timers.poweron) && is_x_timer_fired(chnl->timers.poweron)) {
					x_timer_stop(chnl->timers.poweron);
					// press GSM module control key
					press_gsm_module_key(chnl->board->path, chnl->position, 1);
					LOG("%s: KEY=1\n", chnl->device);
					// start keypress timer
					x_timer_set_second(chnl->timers.keypress, 1);
					// set checking for vio_up
					chnl->flags.check_vio_up = 1;
				}
				// keypress
				if (is_x_timer_enable(chnl->timers.keypress) && is_x_timer_fired(chnl->timers.keypress)) {
					x_timer_stop(chnl->timers.keypress);
					// release GSM module control key
					press_gsm_module_key(chnl->board->path, chnl->position, 0);
					LOG("%s: KEY=0\n", chnl->device);
					// check for vio_up
					if (chnl->flags.check_vio_up) {
						chnl->flags.check_vio_up = 0;
						// start check_vio_up timer
						x_timer_set_ms(chnl->timers.check_vio_up, 100);
						// start wait_vio_up timer
						x_timer_set_second(chnl->timers.wait_vio_up, 10);
					}
					// check for vio_down
					if (chnl->flags.check_vio_down) {
						chnl->flags.check_vio_down = 0;
						// start check_vio_down timer
						x_timer_set_ms(chnl->timers.check_vio_down, 100);
						// start wait_vio_down timer
						x_timer_set_second(chnl->timers.wait_vio_down, 10);
					}
				}
				// check_vio_up
				if (is_x_timer_enable(chnl->timers.check_vio_up) && is_x_timer_fired(chnl->timers.check_vio_up)) {
					// get GSM module vio
					if ((res = get_gsm_module_vio(chnl->board->path, chnl->position)) < 0) {
						LOG("%s: write(%s, %u): %s\n", chnl->device, chnl->board->path, chnl->position, strerror(errno));
						goto main_end;
					} else {
						if (res) {
							// vio is up
							x_timer_stop(chnl->timers.wait_vio_up);
							x_timer_stop(chnl->timers.check_vio_up);
							LOG("%s: VIO UP\n", chnl->device);
						} else {
							// restart check_vio_down timer
							x_timer_set_ms(chnl->timers.check_vio_down, 500);
						}
					}
				}
				// wait vio up
				if (is_x_timer_enable(chnl->timers.wait_vio_up) && is_x_timer_fired(chnl->timers.wait_vio_up)) {
					LOG("%s: VIO not turn to UP\n", chnl->device);
					x_timer_stop(chnl->timers.wait_vio_up);
					x_timer_stop(chnl->timers.check_vio_up);
					// check for channel running state
					if (chnl->flags.run) {
						chnl->signals.enable = 1;
					}
				}
				// check_vio_down
				if (is_x_timer_enable(chnl->timers.check_vio_down) && is_x_timer_fired(chnl->timers.check_vio_down)) {
					// get GSM module vio
					if ((res = get_gsm_module_vio(chnl->board->path, chnl->position)) < 0) {
						LOG("%s: write(%s, %u): %s\n", chnl->device, chnl->board->path, chnl->position, strerror(errno));
						goto main_end;
					} else {
						if (res) {
							// restart check_vio_down timer
							x_timer_set_ms(chnl->timers.check_vio_down, 500);
						} else {
							// vio is down
							x_timer_stop(chnl->timers.wait_vio_down);
							x_timer_stop(chnl->timers.check_vio_down);
							LOG("%s: VIO DOWN\n", chnl->device);
							// disable GSM module power supply
							set_gsm_module_power(chnl->board->path, chnl->position, 0);
							LOG("%s: PWR=0\n", chnl->device);
							// check for channel running state
							if (chnl->flags.run) {
								chnl->signals.enable = 1;
							}
						}
					}
				}
				// wait vio down
				if (is_x_timer_enable(chnl->timers.wait_vio_down) && is_x_timer_fired(chnl->timers.wait_vio_down)) {
					LOG("%s: VIO not turn to DOWN\n", chnl->device);
					x_timer_stop(chnl->timers.wait_vio_down);
					x_timer_stop(chnl->timers.check_vio_down);
					// disable GSM module power supply
					set_gsm_module_power(chnl->board->path, chnl->position, 0);
					LOG("%s: PWR=0\n", chnl->device);
					// check for channel running state
					if (chnl->flags.run) {
						chnl->signals.enable = 1;
					}
				}
				// reset
				if (is_x_timer_enable(chnl->timers.reset) && is_x_timer_fired(chnl->timers.reset)) {
					LOG("%s: RESET timer fired\n", chnl->device);
					x_timer_stop(chnl->timers.reset);
					// check for channel running state
					if (chnl->flags.run) {
						chnl->signals.restart = 1;
					}
				}
				// signals
				// enable
				if (chnl->signals.enable) {
					LOG("%s: received enable signal\n", chnl->device);
					chnl->signals.enable = 0;
					// set start timer
					clock_gettime(CLOCK_MONOTONIC, &ts_planned);
					for (t_brd = board_list.head; t_brd; t_brd = t_brd->next) {
						for (t_chnl = t_brd->channel_list.head; t_chnl; t_chnl = t_chnl->next) {
							ts_contest = get_x_timer_expires(t_chnl->timers.start);
							if (tv_cmp(ts_contest, ts_planned) > 0) {
								tv_cpy(ts_planned, ts_contest);
							}
						}
					}
					tv_set(ts_contest, 1, 0);
					ts_planned = tv_add(ts_planned, ts_contest);
					x_timer_schedule(chnl->timers.start, ts_planned);
				}
				// shutdown
				if (chnl->signals.shutdown) {
					LOG("%s: received shutdown signal\n", chnl->device);
					chnl->signals.shutdown = 0;
					// stop timers
					x_timer_stop(chnl->timers.start);
					x_timer_stop(chnl->timers.poweron);
					x_timer_stop(chnl->timers.keypress);
					x_timer_stop(chnl->timers.wait_vio_up);
					x_timer_stop(chnl->timers.check_vio_up);
					// reset flags
					chnl->flags.check_vio_up = 0;
					chnl->flags.check_vio_down = 0;
					// get GSM module vio
					if ((res = get_gsm_module_vio(chnl->board->path, chnl->position)) < 0) {
						LOG("%s: write(%s, %u): %s\n", chnl->device, chnl->board->path, chnl->position, strerror(errno));
						goto main_end;
					} else {
						if (res) {
							// press GSM module control key
							press_gsm_module_key(chnl->board->path, chnl->position, 1);
							LOG("%s: KEY=1\n", chnl->device);
							// start keypress timer
							x_timer_set_second(chnl->timers.keypress, 1);
							// set checking for vio_down
							chnl->flags.check_vio_down = 1;
						} else {
							// vio is down
							x_timer_stop(chnl->timers.wait_vio_down);
							// disable GSM module power supply
							set_gsm_module_power(chnl->board->path, chnl->position, 0);
							LOG("%s: PWR=0\n", chnl->device);
						}
					}
				}
				// restart
				if (chnl->signals.restart) {
					LOG("%s: received restart signal\n", chnl->device);
					chnl->signals.restart = 0;
					// stop timers
					x_timer_stop(chnl->timers.start);
					x_timer_stop(chnl->timers.poweron);
					x_timer_stop(chnl->timers.keypress);
					x_timer_stop(chnl->timers.wait_vio_up);
					x_timer_stop(chnl->timers.check_vio_up);
					// reset flags
					chnl->flags.check_vio_up = 0;
					chnl->flags.check_vio_down = 0;
					// get GSM module vio
					if ((res = get_gsm_module_vio(chnl->board->path, chnl->position)) < 0) {
						LOG("%s: write(%s, %u): %s\n", chnl->device, chnl->board->path, chnl->position, strerror(errno));
						goto main_end;
					} else {
						if (res) {
							// press GSM module control key
							press_gsm_module_key(chnl->board->path, chnl->position, 1);
							LOG("%s: KEY=1\n", chnl->device);
							// start keypress timer
							x_timer_set_second(chnl->timers.keypress, 1);
							// set checking for vio_down
							chnl->flags.check_vio_down = 1;
						} else {
							// vio is down
							x_timer_stop(chnl->timers.wait_vio_down);
							// disable GSM module power supply
							set_gsm_module_power(chnl->board->path, chnl->position, 0);
							LOG("%s: PWR=0\n", chnl->device);
							// emit enable signal
							chnl->signals.enable = 1;
						}
					}
				}
			}
		}
		// prepare select
		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;
		maxfd = 0;
		FD_ZERO(&rfds);
		// TCP control server socket
		if (tcp_cs_sock > 0) {
			FD_SET(tcp_cs_sock, &rfds);
			maxfd = mmax(tcp_cs_sock, maxfd);
		}
		// TCP control client socket
		if (tcp_cc_sock > 0) {
			FD_SET(tcp_cc_sock, &rfds);
			maxfd = mmax(tcp_cc_sock, maxfd);
		}
		// TCP SIM-data server socket
		if (tcp_ds_sock > 0) {
			FD_SET(tcp_ds_sock, &rfds);
			maxfd = mmax(tcp_ds_sock, maxfd);
		}
		// TCP SIM-data client socket
		if (tcp_dc_sock > 0) {
			FD_SET(tcp_dc_sock, &rfds);
			maxfd = mmax(tcp_dc_sock, maxfd);
		}
		// SIM-data device files
		for (brd = board_list.head; brd; brd = brd->next) {
			for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
				if (chnl->sim_data_fd > 0) {
					FD_SET(chnl->sim_data_fd, &rfds);
					maxfd = mmax(chnl->sim_data_fd, maxfd);
				}
			}
		}
		res = select(maxfd + 1, &rfds, NULL, NULL, &timeout);
		if (res > 0) {
			// TCP control server socket
			if ((tcp_cs_sock > 0) && (FD_ISSET(tcp_cs_sock, &rfds))) {
				tcp_rem_addrlen = sizeof(tcp_rem_addr);
				if ((res = accept(tcp_cs_sock, (struct sockaddr *)&tcp_rem_addr, &tcp_rem_addrlen)) < 0) {
					LOG("%s: accept(tcp_cs_sock) failed - %s\n", tcp_cs_prefix, strerror(errno));
				} else {
					// set socket to non-block operation
					if ((tmp_flags = fcntl(res, F_GETFL)) < 0) {
						LOG("%s: Discard connection from \"%s:%u\" - fcntl(res, F_GETFL) failed - %s\n", tcp_cs_prefix, inet_ntoa(tcp_rem_addr.sin_addr), ntohs(tcp_rem_addr.sin_port), strerror(errno));
						close(res);
					} else if (fcntl(res, F_SETFL, tmp_flags | O_NONBLOCK) < 0) {
						LOG("%s: Discard connection from \"%s:%u\" - fcntl(res, F_SETFL) failed - %s\n", tcp_cs_prefix, inet_ntoa(tcp_rem_addr.sin_addr), ntohs(tcp_rem_addr.sin_port), strerror(errno));
						close(res);
					} else {
						// check client for busy
						if (tcp_cc_sock == -1) {
							// accept new client connection
// 							LOG("%s: Connection from \"%s:%u\" accepted\n", tcp_cs_prefix, inet_ntoa(tcp_rem_addr.sin_addr), ntohs(tcp_rem_addr.sin_port));
							// set client data
							tcp_cc_sock = res;
							memcpy(&tcp_cc_addr, &tcp_rem_addr, tcp_rem_addrlen);
// 							tcp_cc_addrlen = tcp_rem_addrlen;
							snprintf(tcp_cc_prefix, sizeof(tcp_cc_prefix), "Control Client(%s:%u)", inet_ntoa(tcp_cc_addr.sin_addr), ntohs(tcp_cc_addr.sin_port));
							// init TCP client data buffer
							tcp_cc_recv_length = 0;
							tcp_cc_recv_wait = sizeof(struct ss_ctrl_msg_req_hdr);
							tcp_cc_xmit_length = 0;
							// start watchdog timer
							x_timer_set_second(tcp_cc_timers.watchdog, 60);
						} else {
							LOG("%s: Discard connection from \"%s:%u\" - free slot not found\n", tcp_cs_prefix, inet_ntoa(tcp_rem_addr.sin_addr), ntohs(tcp_rem_addr.sin_port));
							close(res);
						}
					}
				}
			}
			// TCP control client socket
			if ((tcp_cc_sock > 0) && (FD_ISSET(tcp_cc_sock, &rfds))) {
				res = recv(tcp_cc_sock, &tcp_cc_recv_buf[tcp_cc_recv_length], tcp_cc_recv_wait - tcp_cc_recv_length, 0);
				if (res > 0) {
					// restart watchdog timer
					x_timer_set_second(tcp_cc_timers.watchdog, 60);
					// dump
					if ((tcp_cc_dump) && (fp = fopen(tcp_cc_dump, "a"))) {
						dumptime(fp);
						fprintf(fp, "Data received length=%lu\n", (unsigned long int)res);
						dumphex(fp, 4, &tcp_cc_recv_buf[tcp_cc_recv_length], res);
						fclose(fp);
					}
					tcp_cc_recv_length += res;
					// check for request header
					if (tcp_cc_recv_length >= sizeof(struct ss_ctrl_msg_req_hdr)) {
						ptr_ss_ctrl_msg_req_hdr = (struct ss_ctrl_msg_req_hdr *)tcp_cc_recv_buf;
						// correct wait length
						tcp_cc_recv_wait = sizeof(struct ss_ctrl_msg_req_hdr) + ptr_ss_ctrl_msg_req_hdr->length;
						// check for full message
						if (tcp_cc_recv_length >= sizeof(struct ss_ctrl_msg_req_hdr) + ptr_ss_ctrl_msg_req_hdr->length) {
							// check for match id
							if (ptr_ss_ctrl_msg_req_hdr->id == id) {
								// select command action
								switch (ptr_ss_ctrl_msg_req_hdr->cmd) {
									case SS_CTRL_MSG_STATUS:
										// prepare response
										ptr_ss_ctrl_msg_resp_hdr = (struct ss_ctrl_msg_resp_hdr *)&tcp_cc_xmit_buf[tcp_cc_xmit_length];
										ptr_ss_ctrl_msg_resp_hdr->length = channel_count * sizeof(unsigned short);
										ptr_ss_ctrl_msg_resp_hdr->flags = ptr_ss_ctrl_msg_req_hdr->flags;
										ptr_ss_ctrl_msg_resp_hdr->cmd = ptr_ss_ctrl_msg_req_hdr->cmd;
										ptr_ss_ctrl_msg_resp_hdr->status = 0; // successfull
										tcp_cc_xmit_length += sizeof(struct ss_ctrl_msg_resp_hdr);
										for (brd = board_list.head; brd; brd = brd->next) {
											for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
												// get GSM module vio
												if ((res = get_gsm_module_vio(chnl->board->path, chnl->position)) < 0) {
													LOG("%s: write(%s, %u): %s\n", chnl->device, chnl->board->path, chnl->position, strerror(errno));
													goto main_end;
												} else {
													if (res == 1) {
														status = 0x0000;
													} else {
														status = 0x0003;
													}
												}
												memcpy(&tcp_cc_xmit_buf[tcp_cc_xmit_length], &status, sizeof(unsigned short));
												tcp_cc_xmit_length += sizeof(unsigned short);
											}
										}
										// wait for next request
										tcp_cc_recv_length = 0;
										tcp_cc_recv_wait = sizeof(struct ss_ctrl_msg_req_hdr);
										break;
									case SS_CTRL_MSG_ENABLE:
										res = RESPONSE_WRONG_CHANNEL; // unknown channel
										for (brd = board_list.head; brd; brd = brd->next) {
											for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
												if (chnl->id == ptr_ss_ctrl_msg_req_hdr->chnl) {
													// get ATR
													atr_init(&chnl->atr);
													for (i = 0; i < ATR_MAXLEN; i++) {
														if (atr_read_byte(&chnl->atr, tcp_cc_recv_buf[sizeof(struct ss_ctrl_msg_req_hdr) + i]) < 0) {
#if 0
															LOG("%s: ENABLE channel=%u failed: bad byte in ATR[%lu]=0x%02x\n", tcp_cc_prefix, ptr_ss_ctrl_msg_req_hdr->chnl, (unsigned long int)i, tcp_cc_recv_buf[sizeof(struct ss_ctrl_msg_req_hdr) + i]);
															chnl->atr.length = 0;
															res = RESPONSE_WRONG_ATR; // bad ATR
#else
															LOG("%s: ENABLE channel=%u: bad byte in ATR[%lu]=0x%02x - set ATR to default [0x3b, 0x10, 0x96]\n", tcp_cc_prefix, ptr_ss_ctrl_msg_req_hdr->chnl, (unsigned long int)i, tcp_cc_recv_buf[sizeof(struct ss_ctrl_msg_req_hdr) + i]);
															chnl->atr.data[0] = 0x3b;
															chnl->atr.data[1] = 0x10;
															chnl->atr.data[2] = 0x96;
															chnl->atr.length = 3;
#endif
															break;
														} else if (atr_is_complete(&chnl->atr)) {
															break;
														}
													}
													if (chnl->atr.length) {
														if (chnl->flags.run) {
															LOG("%s: ENABLE channel=%u failed: channel already enabled\n", tcp_cc_prefix, ptr_ss_ctrl_msg_req_hdr->chnl);
															res = 0; // 4 - already
														} else {
															LOG("%s: ENABLE channel=%u succeeded\n", tcp_cc_prefix, ptr_ss_ctrl_msg_req_hdr->chnl);
															res = 0;
															chnl->flags.run = 1;
															// enable channel
															chnl->signals.enable = 1;
														}
													}
												}
											}
										}
										// prepare response
										ptr_ss_ctrl_msg_resp_hdr = (struct ss_ctrl_msg_resp_hdr *)&tcp_cc_xmit_buf[tcp_cc_xmit_length];
										ptr_ss_ctrl_msg_resp_hdr->length = 0;
										ptr_ss_ctrl_msg_resp_hdr->flags = ptr_ss_ctrl_msg_req_hdr->flags;
										ptr_ss_ctrl_msg_resp_hdr->cmd = ptr_ss_ctrl_msg_req_hdr->cmd;
										ptr_ss_ctrl_msg_resp_hdr->status = res;
										tcp_cc_xmit_length += sizeof(struct ss_ctrl_msg_resp_hdr);
										// wait for next request
										tcp_cc_recv_length = 0;
										tcp_cc_recv_wait = sizeof(struct ss_ctrl_msg_req_hdr);
										break;
									case SS_CTRL_MSG_DISABLE:
										res = RESPONSE_WRONG_CHANNEL; // unknown channel
										for (brd = board_list.head; brd; brd = brd->next) {
											for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
												if (chnl->id == ptr_ss_ctrl_msg_req_hdr->chnl) {
													if (chnl->flags.run) {
														LOG("%s: DISABLE channel=%u succeeded\n", tcp_cc_prefix, ptr_ss_ctrl_msg_req_hdr->chnl);
														res = 0;
														chnl->flags.run = 0;
														chnl->signals.shutdown = 1;
														// delete ATR
														chnl->atr.length = 0;
														// stop wait timer
														x_timer_stop(chnl->timers.wait);
														// stop command timer
														x_timer_stop(chnl->timers.command);
														// stop atr timer
														x_timer_stop(chnl->timers.atr);
													} else {
														LOG("%s: DISABLE channel=%u failed: channel already disabled\n", tcp_cc_prefix, ptr_ss_ctrl_msg_req_hdr->chnl);
														res = 0; // 4 - already
													}
												}
											}
										}
										// prepare response
										ptr_ss_ctrl_msg_resp_hdr = (struct ss_ctrl_msg_resp_hdr *)&tcp_cc_xmit_buf[tcp_cc_xmit_length];
										ptr_ss_ctrl_msg_resp_hdr->length = 0;
										ptr_ss_ctrl_msg_resp_hdr->flags = ptr_ss_ctrl_msg_req_hdr->flags;
										ptr_ss_ctrl_msg_resp_hdr->cmd = ptr_ss_ctrl_msg_req_hdr->cmd;
										ptr_ss_ctrl_msg_resp_hdr->status = res;
										tcp_cc_xmit_length += sizeof(struct ss_ctrl_msg_resp_hdr);
										// wait for next request
										tcp_cc_recv_length = 0;
										tcp_cc_recv_wait = sizeof(struct ss_ctrl_msg_req_hdr);
										break;
									default:
										LOG("%s: Unknown command=0x%02x\n", tcp_cc_prefix, ptr_ss_ctrl_msg_req_hdr->cmd);
										// prepare failure response
										ptr_ss_ctrl_msg_resp_hdr = (struct ss_ctrl_msg_resp_hdr *)&tcp_cc_xmit_buf[tcp_cc_xmit_length];
										ptr_ss_ctrl_msg_resp_hdr->length = 0;
										ptr_ss_ctrl_msg_resp_hdr->flags = ptr_ss_ctrl_msg_req_hdr->flags;
										ptr_ss_ctrl_msg_resp_hdr->cmd = ptr_ss_ctrl_msg_req_hdr->cmd;
										ptr_ss_ctrl_msg_resp_hdr->status = RESPONSE_GATE_NOTSUPPORTED;
										tcp_cc_xmit_length += sizeof(struct ss_ctrl_msg_resp_hdr);
#if 0
										// set close flag
										tcp_dc_flags.close = 1;
#endif
										break;
								}
							} else {
								// id don't match
								LOG("%s: Request id don't match received=0x%08x - expected=0x%08x\n", tcp_cc_prefix, ptr_ss_ctrl_msg_req_hdr->id, id);
								// prepare failure response
								ptr_ss_ctrl_msg_resp_hdr = (struct ss_ctrl_msg_resp_hdr *)&tcp_cc_xmit_buf[tcp_cc_xmit_length];
								ptr_ss_ctrl_msg_resp_hdr->length = 0;
								ptr_ss_ctrl_msg_resp_hdr->flags = ptr_ss_ctrl_msg_req_hdr->flags;
								ptr_ss_ctrl_msg_resp_hdr->cmd = ptr_ss_ctrl_msg_req_hdr->cmd;
								ptr_ss_ctrl_msg_resp_hdr->status = RESPONSE_WRONG_SESSION_ID;
								tcp_cc_xmit_length += sizeof(struct ss_ctrl_msg_resp_hdr);
								// set close flag
								tcp_cc_flags.close = 1;
							}
						}
					}
				} else if (res < 0) {
					if (errno != EAGAIN) {
						LOG("%s: recv(tcp_cc_sock) failed - %s\n", tcp_cc_prefix, strerror(errno));
						// set close flag
						tcp_cc_flags.close = 1;
					}
				} else {
// 					LOG("%s: Client \"%s:%u\" disconnected\n", tcp_cs_prefix, inet_ntoa(tcp_cc_addr.sin_addr), ntohs(tcp_cs_addr.sin_port));
					// on disconnect action
					close(tcp_cc_sock);
					tcp_cc_sock = -1;
					x_timer_stop(tcp_cc_timers.watchdog);
					tcp_cc_recv_length = 0;
					tcp_cc_recv_wait = sizeof(struct ss_ctrl_msg_req_hdr);
					tcp_cc_xmit_length = 0;
				}
			}
			// TCP SIM-data server socket
			if ((tcp_ds_sock > 0) && (FD_ISSET(tcp_ds_sock, &rfds))) {
				tcp_rem_addrlen = sizeof(tcp_rem_addr);
				if ((res = accept(tcp_ds_sock, (struct sockaddr *)&tcp_rem_addr, &tcp_rem_addrlen)) < 0) {
					LOG("%s: accept(tcp_ds_sock) failed - %s\n", tcp_ds_prefix, strerror(errno));
				} else {
					// set socket to non-block operation
					if ((tmp_flags = fcntl(res, F_GETFL)) < 0) {
						LOG("%s: Discard connection from \"%s:%u\" - fcntl(res, F_GETFL) failed - %s\n", tcp_ds_prefix, inet_ntoa(tcp_rem_addr.sin_addr), ntohs(tcp_rem_addr.sin_port), strerror(errno));
						close(res);
					} else if (fcntl(res, F_SETFL, tmp_flags | O_NONBLOCK) < 0) {
						LOG("%s: Discard connection from \"%s:%u\" - fcntl(res, F_SETFL) failed - %s\n", tcp_ds_prefix, inet_ntoa(tcp_rem_addr.sin_addr), ntohs(tcp_rem_addr.sin_port), strerror(errno));
						close(res);
					} else {
						// check client for busy
						if (tcp_dc_sock == -1) {
							// accept new client connection
							LOG("%s: Connection from \"%s:%u\" accepted\n", tcp_ds_prefix, inet_ntoa(tcp_rem_addr.sin_addr), ntohs(tcp_rem_addr.sin_port));
							// set client data
							tcp_dc_sock = res;
							memcpy(&tcp_dc_addr, &tcp_rem_addr, tcp_rem_addrlen);
// 							tcp_dc_addrlen = tcp_rem_addrlen;
							snprintf(tcp_dc_prefix, sizeof(tcp_dc_prefix), "SIM-data Client(%s:%u)", inet_ntoa(tcp_dc_addr.sin_addr), ntohs(tcp_dc_addr.sin_port));
							// init TCP client data buffer
							tcp_dc_recv_length = 0;
							tcp_dc_recv_wait = 1;
							tcp_dc_xmit_length = 0;
							// start auth timer
							x_timer_set_second(tcp_dc_timers.auth, 5);
							// start watchdog timer
							x_timer_set_second(tcp_dc_timers.watchdog, 60);
						} else {
							LOG("%s: Discard connection from \"%s:%u\" - server already in use\n", tcp_ds_prefix, inet_ntoa(tcp_rem_addr.sin_addr), ntohs(tcp_rem_addr.sin_port));
							close(res);
						}
					}
				}
			}
			// TCP SIM-data client socket
			if ((tcp_dc_sock > 0) && (FD_ISSET(tcp_dc_sock, &rfds))) {
				res = recv(tcp_dc_sock, &tcp_dc_recv_buf[tcp_dc_recv_length], tcp_dc_recv_wait - tcp_dc_recv_length, 0);
				if (res > 0) {
					// restart watchdog timer
					x_timer_set_second(tcp_dc_timers.watchdog, 60);
					// dump
					if ((tcp_dc_dump) && (fp = fopen(tcp_dc_dump, "a"))) {
						dumptime(fp);
						fprintf(fp, "Data received length=%lu\n", (unsigned long int)res);
						dumphex(fp, 4, &tcp_dc_recv_buf[tcp_dc_recv_length], res);
						fclose(fp);
					}
					tcp_dc_recv_length += res;
					// select message type
					switch (tcp_dc_recv_buf[0]) {
						case SS_DATA_MSG_AUTHORIZATION:
							if (tcp_dc_recv_wait < sizeof(struct ss_data_msg_auth_req)) {
								tcp_dc_recv_wait = sizeof(struct ss_data_msg_auth_req);
							} else {
								if (tcp_dc_recv_length >= sizeof(struct ss_data_msg_auth_req)) {
									ptr_ss_data_msg_auth_req = (struct ss_data_msg_auth_req *)tcp_dc_recv_buf;
									tmpu16 = 0;
									for (i = 0; i < sizeof(ptr_ss_data_msg_auth_req->user); i++) {
										tmpu16 += ptr_ss_data_msg_auth_req->user[i];
										if (ptr_ss_data_msg_auth_req->user[i] == 0x20) {
											ptr_ss_data_msg_auth_req->user[i] = 0x00;
										}
									}
									for (i = 0; i < sizeof(ptr_ss_data_msg_auth_req->password); i++) {
										tmpu16 += ptr_ss_data_msg_auth_req->password[i];
										if (ptr_ss_data_msg_auth_req->password[i] == 0x20) {
											ptr_ss_data_msg_auth_req->password[i] = 0x00;
										}
									}
									// verify checksum
									if (ptr_ss_data_msg_auth_req->checksum == tmpu16) {
										if (!strcmp((char *)ptr_ss_data_msg_auth_req->user, user) && !strcmp((char *)ptr_ss_data_msg_auth_req->password, password)) {
											// successfull authorization
											LOG("%s: Authorization succeeded\n", tcp_dc_prefix);
											// prepare successfull authorization response
											ptr_ss_data_msg_auth_resp = (struct ss_data_msg_auth_resp *)&tcp_dc_xmit_buf[tcp_dc_xmit_length];
											ptr_ss_data_msg_auth_resp->hex01 = SS_DATA_MSG_AUTHORIZATION;
											ptr_ss_data_msg_auth_resp->status = 0; // successfull
											ptr_ss_data_msg_auth_resp->reserved = 0;
											ptr_ss_data_msg_auth_resp->id = id;
											ptr_ss_data_msg_auth_resp->number = channel_count;
											tcp_dc_xmit_length += sizeof(struct ss_data_msg_auth_resp);
											// stop auth timer
											x_timer_stop(tcp_dc_timers.auth);
										} else {
											// prepare failure authorization response
											ptr_ss_data_msg_auth_resp = (struct ss_data_msg_auth_resp *)&tcp_dc_xmit_buf[tcp_dc_xmit_length];
											ptr_ss_data_msg_auth_resp->hex01 = SS_DATA_MSG_AUTHORIZATION;
											if (!strcmp((char *)ptr_ss_data_msg_auth_req->user, user)) {
												LOG("%s: Authorization failed: login incorrect\n", tcp_dc_prefix);
												ptr_ss_data_msg_auth_resp->status = RESPONSE_WRONG_LOGIN;
											} else if(!strcmp((char *)ptr_ss_data_msg_auth_req->password, password)) {
												LOG("%s: Authorization failed: password incorrect\n", tcp_dc_prefix);
												ptr_ss_data_msg_auth_resp->status = RESPONSE_WRONG_PASSWORD;
											} else {
												LOG("%s: Authorization failed: bad authorization\n", tcp_dc_prefix);
												ptr_ss_data_msg_auth_resp->status = RESPONSE_WRONG_AUTH;
											}
											ptr_ss_data_msg_auth_resp->reserved = 0;
											ptr_ss_data_msg_auth_resp->id = 0;
											ptr_ss_data_msg_auth_resp->number = 0;
											tcp_dc_xmit_length += sizeof(struct ss_data_msg_auth_resp);
											// set close flag
											tcp_dc_flags.close = 1;
										}
									} else {
										// bad checksum
										LOG("%s: Authorization failed: bad checksum received=0x%04x - calculated=0x%04x\n", tcp_dc_prefix, ptr_ss_data_msg_auth_req->checksum, tmpu16);
										// prepare failure authorization response
										ptr_ss_data_msg_auth_resp = (struct ss_data_msg_auth_resp *)&tcp_dc_xmit_buf[tcp_dc_xmit_length];
										ptr_ss_data_msg_auth_resp->hex01 = SS_DATA_MSG_AUTHORIZATION;
										ptr_ss_data_msg_auth_resp->status = RESPONSE_WRONG_AUTH;
										ptr_ss_data_msg_auth_resp->reserved = 0;
										ptr_ss_data_msg_auth_resp->id = 0;
										ptr_ss_data_msg_auth_resp->number = 0;
										tcp_dc_xmit_length += sizeof(struct ss_data_msg_auth_resp);
										// set close flag
										tcp_dc_flags.close = 1;
									}
									tcp_dc_recv_length = 0;
									tcp_dc_recv_wait = 1;
								}
							}
							break;
						case SS_DATA_MSG_COMBINED:
							if (tcp_dc_recv_wait < sizeof(struct ss_data_msg_comb_hdr)) {
								tcp_dc_recv_wait = sizeof(struct ss_data_msg_comb_hdr);
							} else {
								if (tcp_dc_recv_length >= sizeof(struct ss_data_msg_comb_hdr)) {
									ptr_ss_data_msg_comb_hdr = (struct ss_data_msg_comb_hdr *)tcp_dc_recv_buf;
									// check for full length
									if (tcp_dc_recv_wait < (sizeof(struct ss_data_msg_comb_hdr) + ptr_ss_data_msg_comb_hdr->length)) {
										tcp_dc_recv_wait = sizeof(struct ss_data_msg_comb_hdr) + ptr_ss_data_msg_comb_hdr->length;
									} else {
										if (tcp_dc_recv_length >= (sizeof(struct ss_data_msg_comb_hdr) + ptr_ss_data_msg_comb_hdr->length)) {
											// traverse all data chunks
											for (i = sizeof(struct ss_data_msg_comb_hdr); i < sizeof(struct ss_data_msg_comb_hdr) + ptr_ss_data_msg_comb_hdr->length; ) {
												ptr_ss_data_msg_comb_chunk_hdr = (struct ss_data_msg_comb_chunk_hdr *)&tcp_dc_recv_buf[i];
												i += sizeof(struct ss_data_msg_comb_chunk_hdr);
												if (ptr_ss_data_msg_comb_chunk_hdr->length) {
													for (brd = board_list.head; brd; brd = brd->next) {
														for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
															if (chnl->id == ptr_ss_data_msg_comb_chunk_hdr->chnl) {
																// check for command is runing
																if (is_x_timer_enable(chnl->timers.command)) {
																	// stop command timer
																	x_timer_stop(chnl->timers.command);
																	// stop wait timer
																	x_timer_stop(chnl->timers.wait);
																	// transmit response from SIM to device
																	sc_data.header.type = SIMCARD_CONTAINER_TYPE_DATA;
																	if (ptr_ss_data_msg_comb_chunk_hdr->length == 2) {
																		sc_data.header.length = ptr_ss_data_msg_comb_chunk_hdr->length;
																		memcpy(sc_data.container.data, &tcp_dc_recv_buf[i], ptr_ss_data_msg_comb_chunk_hdr->length);
																	} else {
																		sc_data.header.length = ptr_ss_data_msg_comb_chunk_hdr->length + 1;
																		sc_data.container.data[0] = chnl->sim_cmd_ack;
																		memcpy(&sc_data.container.data[1], &tcp_dc_recv_buf[i], ptr_ss_data_msg_comb_chunk_hdr->length);
																	}
																	if (write(chnl->sim_data_fd, &sc_data, sizeof(sc_data.header) + sc_data.header.length) < 0) {
																		LOG("%s: write(sim_data_fd): %s\n", chnl->device, strerror(errno));
																		goto main_end;
																	}
																	// dump
																	if ((chnl->dump) && (fp = fopen(chnl->dump, "a"))) {
																		dumptime(fp);
																		fprintf(fp, "Write data length=%u\n", sc_data.header.length);
																		dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
																		fclose(fp);
																	}
																}
															}
														}
													}
												}
												i += ptr_ss_data_msg_comb_chunk_hdr->length;
											}
											tcp_dc_recv_length = 0;
											tcp_dc_recv_wait = 1;
										}
									}
								}
							}
							break;
						default:
							LOG("%s: Unknown command=0x%02x\n", tcp_dc_prefix, tcp_dc_recv_buf[0]);
							// prepare failure generic response
							ptr_ss_data_msg_generic = (struct ss_data_msg_generic *)&tcp_dc_xmit_buf[tcp_dc_xmit_length];
							ptr_ss_data_msg_generic->cmd = tcp_dc_recv_buf[0];
							ptr_ss_data_msg_generic->status = RESPONSE_GATE_NOTSUPPORTED;
							ptr_ss_data_msg_generic->reserved = 0;
							tcp_dc_xmit_length += sizeof(struct ss_data_msg_generic);
							// set close flag
							tcp_dc_flags.close = 1;
							break;
					}
				} else if (res < 0) {
					if (errno != EAGAIN) {
						LOG("%s: recv(tcp_dc_sock) failed - %s\n", tcp_dc_prefix, strerror(errno));
						// set close flag
						tcp_dc_flags.close = 1;
					}
				} else {
					LOG("%s: Client \"%s:%u\" disconnected\n", tcp_ds_prefix, inet_ntoa(tcp_dc_addr.sin_addr), ntohs(tcp_ds_addr.sin_port));
					// on disconnect action
					close(tcp_dc_sock);
					tcp_dc_sock = -1;
					x_timer_stop(tcp_dc_timers.auth);
					x_timer_stop(tcp_dc_timers.watchdog);
					tcp_dc_recv_length = 0;
					tcp_dc_recv_wait = 1;
					tcp_dc_xmit_length = 0;
					// disable all channel
					for (brd = board_list.head; brd; brd = brd->next) {
						for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
							if (chnl->flags.run) {
								chnl->flags.run = 0;
								chnl->signals.shutdown = 1;
								// delete ATR
								chnl->atr.length = 0;
								// stop wait timer
								x_timer_stop(chnl->timers.wait);
								// stop command timer
								x_timer_stop(chnl->timers.command);
								// stop atr timer
								x_timer_stop(chnl->timers.atr);
							}
						}
					}
				}
			}
			for (brd = board_list.head; brd; brd = brd->next) {
				for (chnl = brd->channel_list.head; chnl; chnl = chnl->next) {
					if ((chnl->sim_data_fd > 0) && (FD_ISSET(chnl->sim_data_fd, &rfds))) {
						res = read(chnl->sim_data_fd, &sc_data, sizeof(struct simcard_data));
						if (res > 0) {
							switch (sc_data.header.type) {
								case SIMCARD_CONTAINER_TYPE_DATA:
									// dump
									if ((chnl->dump) && (fp = fopen(chnl->dump, "a"))) {
										dumptime(fp);
										fprintf(fp, "Read data length=%u\n", sc_data.header.length);
										dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
										fclose(fp);
									}
									memcpy(&chnl->sim_cmd[chnl->sim_cmd_length], sc_data.container.data, sc_data.header.length);
									chnl->sim_cmd_length += sc_data.header.length;
									// select command type
									if (chnl->sim_cmd[0] == 0xff) {
										// PPS
										if (chnl->sim_cmd_proc == 0) {
											chnl->sim_cmd_proc = 1;
											chnl->sim_cmd_wait = 3;
										}
										if (chnl->sim_cmd_length >= chnl->sim_cmd_wait) {
											if (chnl->sim_cmd_proc == 1) {
												chnl->sim_cmd_proc = 2;
												if (chnl->sim_cmd[1] & 0x10) {
													chnl->sim_cmd_wait++;
												}
												if (chnl->sim_cmd[1] & 0x20) {
													chnl->sim_cmd_wait++;
												}
												if (chnl->sim_cmd[1] & 0x40) {
													chnl->sim_cmd_wait++;
												}
											}
											if (chnl->sim_cmd_length >= chnl->sim_cmd_wait) {
												// log
												if ((chnl->log) && (fp = fopen(chnl->log, "a"))) {
													dumptime(fp);
													fprintf(fp, "PPS request length=%u\n", sc_data.header.length);
													dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
													fclose(fp);
												}
												// write PPS response
												sc_data.header.type = SIMCARD_CONTAINER_TYPE_DATA;
												sc_data.header.length = chnl->sim_cmd_wait;
												memcpy(sc_data.container.data, chnl->sim_cmd, chnl->sim_cmd_wait);
												if (write(chnl->sim_data_fd, &sc_data, sizeof(sc_data.header) + sc_data.header.length) < 0) {
													LOG("%s: write(sim_data_fd): %s\n", chnl->device, strerror(errno));
													goto main_end;
												}
												// dump
												if ((chnl->dump) && (fp = fopen(chnl->dump, "a"))) {
													dumptime(fp);
													fprintf(fp, "Write data length=%u\n", sc_data.header.length);
													dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
													fclose(fp);
												}
												// log
												if ((chnl->log) && (fp = fopen(chnl->log, "a"))) {
													dumptime(fp);
													fprintf(fp, "PPS response length=%u\n", sc_data.header.length);
													dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
													fclose(fp);
												}
												// set data speed
												if (chnl->sim_cmd[1] & 0x10) {
													sc_data.header.type = SIMCARD_CONTAINER_TYPE_SPEED;
													sc_data.header.length = sizeof(sc_data.container.speed);
													sc_data.container.speed = chnl->sim_cmd[2];
													if (write(chnl->sim_data_fd, &sc_data, sizeof(sc_data.header) + sc_data.header.length) < 0) {
														LOG("%s: write(sim_data_fd): %s\n", chnl->device, strerror(errno));
														goto main_end;
													}
												}
												// reset command index
												chnl->sim_cmd_length = 0;
												chnl->sim_cmd_wait = 0;
												chnl->sim_cmd_proc = 0;
											}
										}
									} else if ((chnl->sim_cmd[0] == 0x00) || (chnl->sim_cmd[0] == 0x80) || (chnl->sim_cmd[0] == 0xA0)) {
										// Command
										if (chnl->sim_cmd_proc == 0) {
											chnl->sim_cmd_proc = 1;
											chnl->sim_cmd_wait = 5;
										}
										if (chnl->sim_cmd_length >= chnl->sim_cmd_wait) {
											if (chnl->sim_cmd_proc == 1) {
												chnl->sim_cmd_proc = 5;
												if (((chnl->sim_cmd[0] == 0x00) && ((chnl->sim_cmd[1] == 0x84) || (chnl->sim_cmd[1] == 0xb0) || (chnl->sim_cmd[1] == 0xb2) || (chnl->sim_cmd[1] == 0xc0) || (chnl->sim_cmd[1] == 0xca) || (chnl->sim_cmd[4] == 0x00))) ||
													((chnl->sim_cmd[0] == 0x80) && ((chnl->sim_cmd[1] == 0xf2) || (chnl->sim_cmd[1] == 0xcb) || (chnl->sim_cmd[1] == 0x12) || (chnl->sim_cmd[4] == 0x00))) ||
													((chnl->sim_cmd[0] == 0xa0) && ((chnl->sim_cmd[1] == 0x12) || (chnl->sim_cmd[1] == 0xb0) || (chnl->sim_cmd[1] == 0xb2) || (chnl->sim_cmd[1] == 0xc0) || (chnl->sim_cmd[1] == 0xf2) || (chnl->sim_cmd[4] == 0x00)))) {
													// check for unexpected data in command buffer
													if (chnl->sim_cmd_length == chnl->sim_cmd_wait) {
														// set wait timer
														x_timer_set_ms(chnl->timers.wait, 500);
														// set command timer
														x_timer_set_second(chnl->timers.command, 30);
														// set ACK byte
														chnl->sim_cmd_ack = chnl->sim_cmd[1];
														// prepare SIM-data for simbank
														ptr_ss_data_msg_comb_hdr = (struct ss_data_msg_comb_hdr *)&tcp_dc_xmit_buf[tcp_dc_xmit_length];
														ptr_ss_data_msg_comb_hdr->hex83 = SS_DATA_MSG_COMBINED;
														ptr_ss_data_msg_comb_hdr->length = sizeof(struct ss_data_msg_comb_chunk_hdr) + chnl->sim_cmd_length;
														tcp_dc_xmit_length += sizeof(struct ss_data_msg_comb_hdr);
														ptr_ss_data_msg_comb_chunk_hdr = (struct ss_data_msg_comb_chunk_hdr *)&tcp_dc_xmit_buf[tcp_dc_xmit_length];
														ptr_ss_data_msg_comb_chunk_hdr->chnl = chnl->id;
														ptr_ss_data_msg_comb_chunk_hdr->length = chnl->sim_cmd_length;
														tcp_dc_xmit_length += sizeof(struct ss_data_msg_comb_chunk_hdr);
														memcpy(&tcp_dc_xmit_buf[tcp_dc_xmit_length], chnl->sim_cmd, chnl->sim_cmd_length);
														tcp_dc_xmit_length += chnl->sim_cmd_length;
														// reset command index
														chnl->sim_cmd_length = 0;
														chnl->sim_cmd_wait = 0;
														chnl->sim_cmd_proc = 0;
														// stop atr timer
														x_timer_stop(chnl->timers.atr);
													} else {
														LOG("%s: SIM-command has length=%lu but expected=%lu\n", chnl->device, (unsigned long int)chnl->sim_cmd_length, (unsigned long int)chnl->sim_cmd_wait);
														// reset command index
														chnl->sim_cmd_length = 0;
														chnl->sim_cmd_wait = 0;
														chnl->sim_cmd_proc = 0;
														// stop wait timer
														x_timer_stop(chnl->timers.wait);
														// stop command timer
														x_timer_stop(chnl->timers.command);
														// stop atr timer
														x_timer_stop(chnl->timers.atr);
														// restart GSM module
														chnl->signals.restart = 1;
													}
												} else {
													// get command data length
													chnl->sim_cmd_wait += chnl->sim_cmd[4];
													// write ACK
													sc_data.header.type = SIMCARD_CONTAINER_TYPE_DATA;
													sc_data.header.length = 1;
													sc_data.container.data[0] = chnl->sim_cmd[1];
													if (write(chnl->sim_data_fd, &sc_data, sizeof(sc_data.header) + sc_data.header.length) < 0) {
														LOG("%s: write(sim_data_fd): %s\n", chnl->device, strerror(errno));
														goto main_end;
													}
													// dump
													if ((chnl->dump) && (fp = fopen(chnl->dump, "a"))) {
														dumptime(fp);
														fprintf(fp, "Write data length=%u\n", sc_data.header.length);
														dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
														fclose(fp);
													}
													// stop atr timer
													x_timer_stop(chnl->timers.atr);
												}
											} else if (chnl->sim_cmd_proc == 5) {
												// check for unexpected data in command buffer
												if (chnl->sim_cmd_length == chnl->sim_cmd_wait) {
													// set wait timer
													x_timer_set_ms(chnl->timers.wait, 500);
													// set command timer
													x_timer_set_second(chnl->timers.command, 30);
													// prepare SIM-data for simbank
													ptr_ss_data_msg_comb_hdr = (struct ss_data_msg_comb_hdr *)&tcp_dc_xmit_buf[tcp_dc_xmit_length];
													ptr_ss_data_msg_comb_hdr->hex83 = SS_DATA_MSG_COMBINED;
													ptr_ss_data_msg_comb_hdr->length = sizeof(struct ss_data_msg_comb_chunk_hdr) + chnl->sim_cmd_length;
													tcp_dc_xmit_length += sizeof(struct ss_data_msg_comb_hdr);
													ptr_ss_data_msg_comb_chunk_hdr = (struct ss_data_msg_comb_chunk_hdr *)&tcp_dc_xmit_buf[tcp_dc_xmit_length];
													ptr_ss_data_msg_comb_chunk_hdr->chnl = chnl->id;
													ptr_ss_data_msg_comb_chunk_hdr->length = chnl->sim_cmd_length;
													tcp_dc_xmit_length += sizeof(struct ss_data_msg_comb_chunk_hdr);
													memcpy(&tcp_dc_xmit_buf[tcp_dc_xmit_length], chnl->sim_cmd, chnl->sim_cmd_length);
													tcp_dc_xmit_length += chnl->sim_cmd_length;
													// reset command index
													chnl->sim_cmd_length = 0;
													chnl->sim_cmd_wait = 0;
													chnl->sim_cmd_proc = 0;
													// stop atr timer
													x_timer_stop(chnl->timers.atr);
												} else {
													LOG("%s: SIM-command has length=%lu but expected=%lu\n", chnl->device, (unsigned long int)chnl->sim_cmd_length, (unsigned long int)chnl->sim_cmd_wait);
													// reset command index
													chnl->sim_cmd_length = 0;
													chnl->sim_cmd_wait = 0;
													chnl->sim_cmd_proc = 0;
													// stop wait timer
													x_timer_stop(chnl->timers.wait);
													// stop command timer
													x_timer_stop(chnl->timers.command);
													// stop atr timer
													x_timer_stop(chnl->timers.atr);
													// restart GSM module
													chnl->signals.restart = 1;
												}
											} else {
												LOG("%s: SIM-command processed wrong bytes count=%lu\n", chnl->device, (unsigned long int)chnl->sim_cmd_proc);
												// reset command index
												chnl->sim_cmd_length = 0;
												chnl->sim_cmd_wait = 0;
												chnl->sim_cmd_proc = 0;
												// stop wait timer
												x_timer_stop(chnl->timers.wait);
												// stop command timer
												x_timer_stop(chnl->timers.command);
												// stop atr timer
												x_timer_stop(chnl->timers.atr);
												// restart GSM module
												chnl->signals.restart = 1;
											}
										}
									} else {
										LOG("%s: unknown/unsupoorted SIM-command class=%02x\n", chnl->device, chnl->sim_cmd[0]);
										// reset command index
										chnl->sim_cmd_length = 0;
										chnl->sim_cmd_wait = 0;
										chnl->sim_cmd_proc = 0;
										// stop wait timer
										x_timer_stop(chnl->timers.wait);
										// stop command timer
										x_timer_stop(chnl->timers.command);
										// stop atr timer
										x_timer_stop(chnl->timers.atr);
										// restart GSM module
										chnl->signals.restart = 1;
									}
									break;
								case SIMCARD_CONTAINER_TYPE_RESET:
									LOG("%s: RESET %s\n", chnl->device, sc_data.container.reset?"high":"low (active)");
									// dump
									if ((chnl->dump) && (fp = fopen(chnl->dump, "a"))) {
										dumptime(fp);
										fprintf(fp, "RESET %s\n", sc_data.container.reset?"high":"low (active)");
										fclose(fp);
									}
									// log
									if ((chnl->log) && (fp = fopen(chnl->log, "a"))) {
										dumptime(fp);
										fprintf(fp, "RESET %s\n", sc_data.container.reset?"high":"low (active)");
										fclose(fp);
									}
									if (sc_data.container.reset) {
										// stop reset timer
										x_timer_stop(chnl->timers.reset);
										// set default speed
										sc_data.header.type = SIMCARD_CONTAINER_TYPE_SPEED;
										sc_data.header.length = sizeof(sc_data.container.speed);
										sc_data.container.speed = 0x11;
										if (write(chnl->sim_data_fd, &sc_data, sizeof(sc_data.header) + sc_data.header.length) < 0) {
											LOG("%s: write(sim_data_fd): %s\n", chnl->device, strerror(errno));
											goto main_end;
										}
										if (chnl->atr.length) {
											// write ATR
											sc_data.header.type = SIMCARD_CONTAINER_TYPE_DATA;
											sc_data.header.length = chnl->atr.length;
											memcpy(sc_data.container.data, chnl->atr.data, chnl->atr.length);
											if (write(chnl->sim_data_fd, &sc_data, sizeof(sc_data.header) + sc_data.header.length) < 0) {
												LOG("%s: write(sim_data_fd): %s\n", chnl->device, strerror(errno));
												goto main_end;
											}
											// dump
											if ((chnl->dump) && (fp = fopen(chnl->dump, "a"))) {
												dumptime(fp);
												fprintf(fp, "Write data length=%u\n", sc_data.header.length);
												dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
												fclose(fp);
											}
											// log
											if ((chnl->log) && (fp = fopen(chnl->log, "a"))) {
												dumptime(fp);
												fprintf(fp, "ATR length=%u\n", sc_data.header.length);
												dumphex(fp, 4, sc_data.container.data, sc_data.header.length);
												fclose(fp);
											}
											// start atr timer
											x_timer_set_second(chnl->timers.atr, 4);
										}
									} else {
										// reset command index
										chnl->sim_cmd_length = 0;
										chnl->sim_cmd_wait = 0;
										chnl->sim_cmd_proc = 0;
										// stop wait timer
										x_timer_stop(chnl->timers.wait);
										// stop command timer
										x_timer_stop(chnl->timers.command);
										// stop atr timer
										x_timer_stop(chnl->timers.atr);
										// start reset timer
										if (chnl->flags.run) {
											x_timer_set_second(chnl->timers.reset, 4);
										}
									}
									break;
								case SIMCARD_CONTAINER_TYPE_SPEED:
									printf("SIM speed=%02x\n", sc_data.container.speed);
									break;
								default:
									printf("SIM data container unknown type=%u\n", sc_data.header.type);
									break;
							}
						}
					}
				}
			}
		} else if (res > 0) {
			LOG("%s: select() failed - %s\n", prefix, strerror(errno));
			goto main_end;
		}
	}

main_end:
	// start TCP control server
	close(tcp_cs_sock);
	// start SIM-data control server
	close(tcp_ds_sock);
	// destroy board list
	while ((brd = x_sllist_remove_head(board_list))) {
		while ((chnl = x_sllist_remove_head(brd->channel_list))) {
			if (chnl->device) {
				free(chnl->device);
			}
			if (chnl->tty_data_path) {
				free(chnl->tty_data_path);
			}
			if (chnl->sim_data_path) {
				free(chnl->sim_data_path);
			}
			if (chnl->dump) {
				free(chnl->dump);
			}
			if (chnl->log) {
				free(chnl->log);
			}
			close(chnl->sim_data_fd);
			free(chnl);
		}
		if (brd->type) {
			free(brd->type);
		}
		if (brd->name) {
			free(brd->name);
		}
		if (brd->path) {
			free(brd->path);
		}
		free(brd);
	}
	LOG("%s: exit\n", prefix);
	if (log_file) {
		free(log_file);
	}
	if (daemonize) {
		unlink(pid_file);
	}
	exit(EXIT_SUCCESS);
}
