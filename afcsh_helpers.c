#include "afcsh_helpers.h"

static char **tokenize_path(char *path, size_t *num_tokens) {
    int token_capacity = AFCSH_PATH_TOK_BUFSIZE, position = 0;
    
    char **tokens = calloc(token_capacity, sizeof(char*));
    ASSERT_ALLOC(tokens);

    //Tokenize the entered path
    char *token = strtok(path, PATH_DELIM);
    while(token != NULL) {
        tokens[position] = token;
        position++;

        if(position >= token_capacity) {
            token_capacity += AFCSH_PATH_TOK_BUFSIZE;
            tokens = realloc(tokens, token_capacity * sizeof(char*));
            ASSERT_ALLOC(tokens);
        }

        token = strtok(NULL, PATH_DELIM);
    }

    tokens[position] = NULL;
    *num_tokens = position;

    return tokens;
}

extern char *create_full_path(const char *filename, const char *cwd) {
    size_t len_filename = strlen(filename), len_cwd = strlen(cwd);

    char *full_path = calloc(AFCSH_CWD_BUFSIZE + 1, sizeof(char));
    ASSERT_ALLOC(full_path);
    
    //If path starts with '/', use the absolute path
    if(filename[0] == '/') {
        (void)strlcpy(full_path, filename, AFCSH_CWD_BUFSIZE);
    } else {
        //... else create a relative path
        (void)strlcpy(full_path, cwd, AFCSH_CWD_BUFSIZE);
        
        //Append traling '/' unless we are in root already
        if(strcmp(cwd, JAILED_DIR) != 0) {
            (void)strcat(full_path, PATH_DELIM);
        }

        //Append the current path to cwd
        if(len_filename + 1 > AFCSH_CWD_BUFSIZE - strlen(full_path)) {
            ASSERT_OVERFLOW();
        }

        (void)strlcat(full_path, filename, AFCSH_CWD_BUFSIZE - strlen(full_path) - 1);
    }

    //Tokenize the path and parse the special tokens (e.g ., ..) later
    size_t num_tokens = 0;
    char **tokens = tokenize_path(full_path, &num_tokens);

    char *new_path = calloc(AFCSH_CWD_BUFSIZE + 1, sizeof(char));
    ASSERT_ALLOC(new_path); 

    (void)strcpy(new_path, PATH_DELIM);

    bool is_last = false;
    for(int i = 0; i < num_tokens; i++) {
        is_last = (i + 1) == num_tokens;

        if(strcmp(tokens[i], ".") == 0) {
            //Special case e.g "/test/test2/." needs to trim trailing '/'
            if(is_last && num_tokens != 1) {
                new_path = rtrim(new_path, 1);
            }

            tokens[i] = NULL;
            continue;
        }

        if(strcmp(tokens[i], "..") == 0) {
            if(i == 0) continue;

            char *last_token = NULL;
            int position = i, dec = 1;
            while(last_token == NULL && position > 0) {
                last_token = tokens[position - dec];
                
                position--;
                dec++;
            }

            //We reached the root of this path
            if(last_token == NULL) {
                break;
            }

            new_path = rtrim(new_path, strlen(last_token) + 1); //Account for the '/'

            //Special case e.g "/test/test2/.." needs to trim trailing '/'
            if(is_last && i != 1) {
                new_path = rtrim(new_path, 1);
            }


            tokens[i] = NULL;
            continue;
        }

        //Append token to new_path (+2 to account for the potential last '/' during size check)
        size_t len_token = strlen(tokens[i]);
        if(len_token + 2 > AFCSH_CWD_BUFSIZE - strlen(new_path)) {
            ASSERT_OVERFLOW();
        }
        
        (void)strlcat(new_path, tokens[i], AFCSH_CWD_BUFSIZE - len_token - 1);

        //Do not append traling '/' for last token
        if(!is_last) {
            (void)strcat(new_path, PATH_DELIM);
        }
    }

    //Re append '/' if we reached the root
    if(new_path[0] == '\0') {
        (void)strcpy(new_path, JAILED_DIR);
    }

    free(tokens);
    free(full_path);

    return new_path;
}

extern status_t create_file_info(afc_file_info *file_info, const char *path) {
    struct afc_dictionary* file_attributes;
    if(AFCFileInfoOpen(afc, path, &file_attributes) != MDERR_OK){
        return E_NO_SUCH_FILE_OR_DIRECTORY;
    }

    char *key, *value;
    int position = 0;
    while(AFCKeyValueRead(file_attributes, &key, &value) == MDERR_OK && key && value && position <= 6) {
        if(strcmp(key, ST_IFMT) == 0) {

            if(strcmp(value, "S_IFREG") == 0) {
                file_info->a_st_ifmt = S_IFREG;
            } else if(strcmp(value, "S_IFDIR") == 0) {
                file_info->a_st_ifmt = S_IFDIR;
            } else if(strcmp(value, "S_IFLNK") == 0) {
                file_info->a_st_ifmt = S_IFLNK;
            } else {
                (void)fprintf(stderr, "create_file_info: unknown file format %s\n", value);
                return E_NOT_IMPLEMENTED;
            }

        } else if(strcmp(key, ST_NLINK) == 0) {
            file_info->a_st_nlink = atoi(value);
        } else if(strcmp(key, ST_SIZE) == 0) {
            file_info->a_st_size = strtoul(value, NULL, 10);
        } else if(strcmp(key, ST_BLOCKS) == 0) {
            file_info->a_st_blocks = atoi(value);
        } else if(strcmp(key, ST_MTIME) == 0) {  
            file_info->a_st_mtime = strtol(value, NULL, 10) / 1000000000; //Convert from nanoseconds to seconds
        } else if(strcmp(key, ST_BIRTHTIME) == 0) {
            file_info->a_st_birthtime = strtol(value, NULL, 10) / 1000000000; //Convert from nanoseconds to seconds
        } else {
            (void)fprintf(stderr, "create_file_info: unknown attribute %s\n", key);
            return E_NOT_IMPLEMENTED;
        }

        position++;
    }

    ASSERT_MD_ERROR(AFCKeyValueClose(file_attributes));
    return SUCCESS;
}

extern status_t set_cwd(char *cwd, char *new_path) {
    //If new_path is our home directory, simply go there directly
    if(strcmp(new_path, JAILED_DIR) == 0){
        (void)strcpy(cwd, JAILED_DIR);
        return SUCCESS;
    }

    if(strlen(new_path) + 1 > AFCSH_CWD_BUFSIZE) {
        return E_VALUE_TOO_LONG;
    }

    //Try to open the new cwd
    struct afc_directory* directory;
    if(AFCDirectoryOpen(afc, new_path, &directory) != MDERR_OK) {
        struct afc_file_info file_info;
        
        status_t status_file_info = create_file_info(&file_info, new_path);
        if(status_file_info != SUCCESS) {
            return status_file_info;
        }

        //If AFCDirectoryOpen() fails, check if it is due to cwd beeing a regular file
        status_t status_directory = E_NO_SUCH_FILE_OR_DIRECTORY;
        if(status_file_info == SUCCESS) {
            if(file_info.a_st_ifmt != S_IFDIR) {
                status_directory = E_NOT_A_DIRECTORY;
            }
        }
        
        return status_directory;
    }

    //Finally, copy the new path into cwd.
    (void)strlcpy(cwd, new_path, AFCSH_CWD_BUFSIZE);
    return SUCCESS;
}

extern status_t read_file_at_path(uint8_t *bytes, size_t size, const char *path) {
    status_t status = SUCCESS;

    //Prepare and open remote file
    struct afc_file remote_file;
    remote_file.mode = 1;

    if(AFCFileRefOpen(afc, path, 1, &remote_file.file_ref) != MDERR_OK) {
        status = E_COULD_NOT_OPEN_FILE;
        goto read_file_end;
    }

    uint64_t items = (uint64_t)size;
    if(AFCFileRefRead(afc, remote_file.file_ref, bytes, &items) != MDERR_OK){
        status = E_COULD_NOT_READ_FILE;
        goto read_file_end;
    }

read_file_end:
    ASSERT_MD_ERROR(AFCFileRefClose(afc, remote_file.file_ref));
    return status;
}

extern status_t create_file_at_path(uint8_t* bytes, size_t size, const char *path) {
    status_t status = SUCCESS;

    //Prepare and open remote file
    struct afc_file remote_file;
    remote_file.mode = 2;
    
    if(AFCFileRefOpen(afc, path, 2, &remote_file.file_ref) != MDERR_OK) {
        status = E_COULD_NOT_OPEN_FILE;
        goto create_file_end;
    }

    if(size > 0) {
        if(AFCFileRefWrite(afc, remote_file.file_ref, bytes, size) != MDERR_OK) {
            status = E_COULD_NOT_WRITE_FILE;
            goto create_file_end;
        }
    }

create_file_end:
    ASSERT_MD_ERROR(AFCFileRefClose(afc, remote_file.file_ref));
    return status;
}