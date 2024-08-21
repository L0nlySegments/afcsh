#ifndef AFCSH_H
#define AFCSH_H

#include "MobileDevice.h"
#include "error.h"

/* Constants */
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

/* MobileDeviceFramework stuff */
static void device_notification_callback(am_device_notification_callback_info *info, void *unused);

/* Shell helpers */
static char *read_line(void);
static char **split_line(char *line);
static char **tokenize_path(char *path, size_t *num_tokens);

/* Shell depiction */
static char *get_shell_prefix(const char* device_name, const char* cwd);
static status_t set_cwd(char *cwd, char *path);
static void afcsh_loop(void);


/* Helpers */
static int afcsh_num_commands(void);
static int afcsh_execute(char **args, char *cwd);

static char *create_full_path(const char *filename, const char *cwd);

static status_t read_file_at_path(uint8_t *bytes, size_t size, const char *path);
static status_t create_file_info(afc_file_info *file_info, const char *path);
static status_t create_file_at_path(uint8_t *bytes, size_t size, const char *path);

/* Internal builtins */
static status_t afcsh_change_directory(char **args, char *cwd);
static status_t afcsh_print_working_directory(char **args, char *cwd);
static status_t afcsh_list(char **args, char *cwd);
static status_t afcsh_file(char **args, char *cwd);
static status_t afcsh_touch(char **args, char *cwd);
static status_t afcsh_make_directory(char **args, char *cwd);
static status_t afcsh_copy(char **args, char *cwd);
static status_t afcsh_move(char **args, char *cwd);
static status_t afcsh_remove(char **args, char *cwd);
static status_t afcsh_download(char **args, char *cwd);
static status_t afcsh_upload(char **args, char *cwd);
static status_t afcsh_exit(char **args, char *cwd);
static status_t afcsh_clear(char **args, char *cwd);
static status_t afcsh_help(char **args, char *cwd);


#endif
