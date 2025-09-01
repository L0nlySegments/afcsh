#ifndef AFCSH_COMMANDS_H
#define AFCSH_COMMANDS_H

#include <sys/stat.h>

#include "error.h"
#include "afcsh.h"
#include "afcsh_helpers.h"

/* Internal builtins */
extern status_t afcsh_change_directory(char **args, char *cwd);
extern status_t afcsh_print_working_directory(char **args, char *cwd);
extern status_t afcsh_list(char **args, char *cwd);
extern status_t afcsh_file(char **args, char *cwd);
extern status_t afcsh_touch(char **args, char *cwd);
extern status_t afcsh_make_directory(char **args, char *cwd);
extern status_t afcsh_copy(char **args, char *cwd);
extern status_t afcsh_move(char **args, char *cwd);
extern status_t afcsh_remove(char **args, char *cwd);
extern status_t afcsh_download(char **args, char *cwd);
extern status_t afcsh_upload(char **args, char *cwd);
extern status_t afcsh_exit(char **args, char *cwd);
extern status_t afcsh_clear(char **args, char *cwd);
extern status_t afcsh_help(char **args, char *cwd);

#endif