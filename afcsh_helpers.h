#ifndef AFCSH_HELPERS_H
#define AFCSH_HELPERS_H

#include "afcsh.h"
#include "MobileDevice.h"
#include "error.h"

/* Internal Helpers */
static char **tokenize_path(char *path, size_t *num_tokens);

/* External Helpers */
extern char *create_full_path(const char *filename, const char *cwd);
extern status_t set_cwd(char *cwd, char *new_path);
extern status_t read_file_at_path(uint8_t *bytes, size_t size, const char *path);
extern status_t create_file_info(afc_file_info *file_info, const char *path);
extern status_t create_file_at_path(uint8_t *bytes, size_t size, const char *path);

#endif