#ifndef AFCSH_H
#define AFCSH_H

#include "MobileDevice.h"
#include "error.h"
#include "ext_string.h"
#include "core_foundation_utils.h"

/* Constants */
#define VERSION "1.1.0"
#define JAILED_DIR "/"
#define AFCSH_CWD_BUFSIZE 256
#define AFCSH_PREFIX_BUFSIZE 512
#define AFCSH_RL_BUFSIZE 1024
#define AFCSH_TOK_BUFSIZE 64
#define AFCSH_PATH_TOK_BUFSIZE 64
#define TOK_DELIM " \t\r\n\a\""
#define PATH_DELIM "/"

/* status_t return values */
#define AFCSH_EXIT_SUCCESS 1
#define AFCSH_QUIT 0
#define AFCSH_EXIT_FAILURE -1
#define AFCSH_NOT_FOUND -2

/* Macros */
#define ASSERT_ALLOC(ptr) if(ptr == NULL) { (void)fprintf(stderr, "afcsh: allocation error\n"); exit(EXIT_FAILURE); }
#define ASSERT_OVERFLOW() (void)fprintf(stderr, "afcsh: value is too large for assigned buffer\n"); exit(EXIT_FAILURE);
#define ASSERT_MD_ERROR(ret) if(ret != MDERR_OK) { (void)fprintf(stderr, "afcsh: mobile device framework error\n"); exit(EXIT_FAILURE); }


/* MobileDeviceFramework stuff */
struct afc_connection *afc;
static void device_notification_callback(am_device_notification_callback_info *info, void *unused);

/* Shell helpers */
static char *read_line(size_t *line_capacity);
static char **split_line(char *line);

/* Shell depiction */
static char *get_shell_prefix(const char* device_name, const char* cwd);
static void afcsh_loop(void);

/* Shell functionallity */
static int afcsh_execute(char **args, char *cwd);


#endif
