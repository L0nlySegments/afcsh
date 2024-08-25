#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/stat.h>

#include "afcsh.h"
#include "core_foundation_utils.h"
#include "ext_string.h"

#define VERSION "1.0.0"

#define ASSERT_ALLOC(ptr) if(ptr == NULL) { (void)fprintf(stderr, "afcsh: allocation error\n"); exit(EXIT_FAILURE); }
#define ASSERT_OVERFLOW() (void)fprintf(stderr, "afcsh: value is too large for assigned buffer\n"); exit(EXIT_FAILURE);
#define ASSERT_MD_ERROR(ret) if(ret != MDERR_OK) { (void)fprintf(stderr, "afcsh: mobile device framework error\n"); exit(EXIT_FAILURE); }

// Relevant info of our current device
const char* device_name;

// Relevant structs for AFC
struct afc_connection *afc;


int main(void) {
    void *mobile_device_framework = dlopen("/System/Library/PrivateFrameworks/MobileDevice.framework/MobileDevice", RTLD_NOW);

    AMDeviceNotificationSubscribe = dlsym(mobile_device_framework, "AMDeviceNotificationSubscribe");
	AMDeviceConnect = dlsym(mobile_device_framework, "AMDeviceConnect");
	AMDeviceStartSession = dlsym(mobile_device_framework, "AMDeviceStartSession");
    AMDeviceCopyValue = dlsym(mobile_device_framework, "AMDeviceCopyValue");
    AMDeviceStartService = dlsym(mobile_device_framework, "AMDeviceStartService");
    AMDeviceCopyDeviceIdentifier = dlsym(mobile_device_framework, "AMDeviceCopyDeviceIdentifier");
    AFCConnectionOpen = dlsym(mobile_device_framework, "AFCConnectionOpen");
    AFCConnectionClose = dlsym(mobile_device_framework, "AFCConnectionClose");
    AFCDirectoryCreate = dlsym(mobile_device_framework, "AFCDirectoryCreate"); 
    AFCDirectoryOpen = dlsym(mobile_device_framework, "AFCDirectoryOpen");
    AFCDirectoryRead = dlsym(mobile_device_framework, "AFCDirectoryRead");
    AFCDirectoryClose = dlsym(mobile_device_framework, "AFCDirectoryClose");
    AFCFileRefOpen = dlsym(mobile_device_framework, "AFCFileRefOpen");
    AFCFileRefWrite = dlsym(mobile_device_framework, "AFCFileRefWrite");
    AFCFileRefRead = dlsym(mobile_device_framework, "AFCFileRefRead");
    AFCFileRefClose = dlsym(mobile_device_framework, "AFCFileRefClose");
    AFCFileRefSeek = dlsym(mobile_device_framework, "AFCFileRefSeek");
    AFCFileInfoOpen = dlsym(mobile_device_framework, "AFCFileInfoOpen");
    AFCKeyValueRead = dlsym(mobile_device_framework, "AFCKeyValueRead");
    AFCKeyValueClose = dlsym(mobile_device_framework, "AFCKeyValueClose");
    AFCRemovePath = dlsym(mobile_device_framework, "AFCRemovePath"); 
    AFCRenamePath = dlsym(mobile_device_framework, "AFCRenamePath");

    (void)fprintf(stdout, "afcsh: waiting for iOS device\n");

    struct am_device_notification *notification;
	
    ASSERT_MD_ERROR(AMDeviceNotificationSubscribe(device_notification_callback, 0, 0, NULL, &notification));
    CFRunLoopRun();

    return EXIT_SUCCESS;
}

char *afcsh_cmd_str[] = {
  "cd",
  "pwd",
  "ls",
  "file",
  "touch",
  "mkdir",
  "cp",
  "mv",
  "rm",
  "dl",
  "ul",
  "exit",
  "clear",
  "help"
};

status_t (*afcsh_cmd_func[]) (char **, char *) = {
  &afcsh_change_directory,
  &afcsh_print_working_directory,
  &afcsh_list,
  &afcsh_file,
  &afcsh_touch,
  &afcsh_make_directory,
  &afcsh_copy,
  &afcsh_move,
  &afcsh_remove,
  &afcsh_download,
  &afcsh_upload,
  &afcsh_exit,
  &afcsh_clear,
  &afcsh_help
};

static void device_notification_callback(am_device_notification_callback_info *info, void *unused) 
{
	if (info->msg != ADNCI_MSG_CONNECTED) { 
        (void)fprintf(stderr, "afcsh: device disconnected");
        exit(EXIT_FAILURE);
    }

    static am_device *device;
    device = info->dev;
    
    //Establish apple mobile device connection 
    ASSERT_MD_ERROR(AMDeviceConnect(device));
	ASSERT_MD_ERROR(AMDeviceStartSession(device));

    //Get some device information (product name and firmware version)
    CFStringRef deviceInfo;
    deviceInfo = cf_create_string_with_format(
        CFSTR("%@ %@"),
        AMDeviceCopyValue(device, 0, CFSTR("ProductType")),
        AMDeviceCopyValue(device, 0, CFSTR("ProductVersion")));
    device_name = cf_create_c_string(deviceInfo);

    //Start apple file conduit on the device and open a connection
    service_conn_t afc_conn;
    ASSERT_MD_ERROR(AMDeviceStartService(device, CFSTR("com.apple.afc"), &afc_conn, NULL));
    ASSERT_MD_ERROR(AFCConnectionOpen(afc_conn, 0, &afc));

    afcsh_loop();

    (void)fprintf(stdout, "afcsh: terminating connection to %s\n", device_name);
    (void)close(afc_conn);

    CFRelease(deviceInfo);
    exit(EXIT_SUCCESS);
}


static char *read_line(size_t *line_capacity) {
    char *line_buffer = NULL;

    //Get one line from stdin (for valid delimiters see "man getline")
    if(getline(&line_buffer, line_capacity, stdin) == -1){
        if(feof(stdin)) {
            exit(EXIT_SUCCESS);
        } else {
            perror("readline");
            exit(EXIT_FAILURE);
        }
    }

    return line_buffer;
}

static char **split_line(char *line) {
    size_t token_capacity = AFCSH_TOK_BUFSIZE, position = 0;
    
    char **tokens = calloc(token_capacity, sizeof(char*));
    ASSERT_ALLOC(tokens);

    //Tokenize the entered line
    char *token = strtok(line, TOK_DELIM);
    while(token != NULL) {
        tokens[position] = token;
        position++;

        if(position >= token_capacity) {
            token_capacity += AFCSH_TOK_BUFSIZE;
            tokens = realloc(tokens, token_capacity * sizeof(char*));
            ASSERT_ALLOC(tokens);
        }

        token = strtok(NULL, TOK_DELIM);
    }

    tokens[position] = NULL;
    return tokens;
}

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


static char *get_shell_prefix(const char *device_name, const char *cwd) {
    char *prefix = calloc(AFCSH_PREFIX_BUFSIZE + 1, sizeof(char));
    ASSERT_ALLOC(prefix);

    bool is_home = (strcmp(cwd, JAILED_DIR) == 0);
    snprintf(prefix, AFCSH_PREFIX_BUFSIZE - 1, "%s %s $ ", device_name, is_home ? "~" : cwd);

    return prefix;
}

static status_t create_file_info(afc_file_info *file_info, const char *path) {
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

static status_t set_cwd(char *cwd, char *new_path) {
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

static status_t read_file_at_path(uint8_t *bytes, size_t size, const char *path) {
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

static status_t create_file_at_path(uint8_t* bytes, size_t size, const char *path) {
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

static int afcsh_num_commands(void) {
    return sizeof(afcsh_cmd_str) / sizeof(char*);
}


static int afcsh_execute(char **args, char *cwd) {
    if(args[0] == NULL)
        return AFCSH_EXIT_SUCCESS;
    
    for(int i = 0; i < afcsh_num_commands(); i++) {
        if(strcmp(args[0], afcsh_cmd_str[i]) == 0) {
            return (*afcsh_cmd_func[i])(args, cwd);
        }
    }

    return AFCSH_NOT_FOUND; 
}

static void afcsh_loop(void) {

    //Initialize and set the current working directory
    char *cwd = calloc(AFCSH_CWD_BUFSIZE + 1, sizeof(char));
    ASSERT_ALLOC(cwd);

    (void)set_cwd(cwd, JAILED_DIR);

    bool execute = true;
    do {
        size_t line_capacity = AFCSH_RL_BUFSIZE;

        char *shell_prefix = get_shell_prefix(device_name, cwd);  
        (void)printf("%s", shell_prefix);

        char *line = read_line(&line_capacity);
        if(line_capacity > AFCSH_RL_BUFSIZE) {
            (void)fprintf(stderr, "afcsh: command too long\n");
            free(line);
            continue;
        }

        char **args = split_line(line);

        status_t status = afcsh_execute(args, cwd);
        switch(status) {
            case AFCSH_QUIT:
                execute = false;
                break;
            case AFCSH_NOT_FOUND:
                (void)fprintf(stderr, "afcsh: command not found: %s\n", line);
                break;
            case AFCSH_EXIT_FAILURE:
                //(void)fprintf(stderr, "afcsh: last command had an error\n");
                break;
        }

        free(shell_prefix);
        free(line);
        free(args);
    } while(execute);

    free(cwd);
}


static char *create_full_path(const char *filename, const char *cwd) {
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

//Command implementaions
static status_t afcsh_change_directory(char **args, char *cwd) {
    if(args[1] == NULL) {
        (void)set_cwd(cwd, JAILED_DIR);
        return AFCSH_EXIT_SUCCESS;
    }

    status_t status = AFCSH_EXIT_SUCCESS;
    char *full_path = create_full_path(args[1], cwd);

    status_t cwd_status = set_cwd(cwd, full_path);
    if(cwd_status != SUCCESS) {
        display_error(cwd_status, args[1], "cd");
        status = AFCSH_EXIT_FAILURE;
    }

    free(full_path);
    return status;
}

static status_t afcsh_print_working_directory(char **args, char *cwd) {
    (void)fprintf(stdout, "%s\n", cwd);
    return AFCSH_EXIT_SUCCESS;
}

static status_t afcsh_list(char **args, char *cwd) {
    char *full_path = NULL, *effective_path = cwd;

    if(args[1] != NULL) {
        full_path = create_full_path(args[1], cwd);
        effective_path = full_path;
    }

    struct afc_file_info file_info;

    status_t file_info_status = create_file_info(&file_info, effective_path);
    if(file_info_status != SUCCESS) {
        display_error(E_NO_SUCH_FILE_OR_DIRECTORY, effective_path, "ls");
        if(full_path != NULL) free(full_path);
        return AFCSH_EXIT_FAILURE;
    }

    struct afc_directory* directory;
    if(file_info.a_st_ifmt != S_IFDIR) {
        display_error(E_NOT_A_DIRECTORY, effective_path, "ls");
        if(full_path != NULL) free(full_path);
        return AFCSH_EXIT_FAILURE;
    }

    if(AFCDirectoryOpen(afc, effective_path, &directory) != MDERR_OK) {
        (void)fprintf(stderr, "rm: remove failed internally for path %s\n", full_path);
        if(full_path != NULL) free(full_path);
        return AFCSH_EXIT_FAILURE;
    }

    char* entry;
    while(AFCDirectoryRead(afc, directory, &entry) == MDERR_OK && entry) {
        //Skip . and ..
        if(strcmp(entry, ".") == 0 || strcmp(entry, "..") == 0) {
            continue;
        }

        (void)fprintf(stdout, "%s\n", entry); 
    }

    if(full_path != NULL) free(full_path);

    return AFCSH_EXIT_SUCCESS;
}

static status_t afcsh_file(char **args, char *cwd) {
    if(args[1] == NULL) {
        (void)fprintf(stdout, "usage: file file_path\n");
        return AFCSH_EXIT_FAILURE;
    }

    char *full_path = create_full_path(args[1], cwd);
    struct afc_file_info file_info;

    status_t create_file_info_status = create_file_info(&file_info, full_path);
    if(create_file_info_status != SUCCESS) {
        display_error(create_file_info_status, args[1], "file");
        free(full_path);
        return AFCSH_EXIT_FAILURE;
    }

    (void)fprintf(stdout, "Format\t\t| ");
    switch(file_info.a_st_ifmt) {
        case S_IFREG:
            (void)fprintf(stdout, "Regular File\n");
            break;
        case S_IFDIR:
            (void)fprintf(stdout, "Directory\n");
            break;
        case S_IFLNK:
            (void)fprintf(stdout, "Symbolic Link\n");
            break;
        default:
            (void)fprintf(stdout, "Unknown\n");
    }

    (void)fprintf(stdout, "Links\t\t| %d\n", file_info.a_st_nlink);
    (void)fprintf(stdout, "Size\t\t| %lu\n", file_info.a_st_size);
    (void)fprintf(stdout, "Blocks\t\t| %d\n", file_info.a_st_blocks);
    (void)fprintf(stdout, "Last modified\t| %s", ctime(&file_info.a_st_mtime));
    (void)fprintf(stdout, "Created\t\t| %s", ctime(&file_info.a_st_birthtime));

    free(full_path);
    return AFCSH_EXIT_SUCCESS;
}

static status_t afcsh_touch(char **args, char *cwd) {
    if(args[1] == NULL) {
        (void)fprintf(stdout, "usage: touch file_path\n");
        return AFCSH_EXIT_FAILURE;
    }

    status_t status = AFCSH_EXIT_SUCCESS;
    char *full_path = create_full_path(args[1], cwd);

    status_t create_file_status = create_file_at_path(NULL, 0, full_path);
    if(create_file_status != SUCCESS) {
        display_error(create_file_status, args[1], "touch");
        status = AFCSH_EXIT_FAILURE;
    }

    free(full_path);
    return status;
}

static status_t afcsh_make_directory(char **args, char *cwd) {
    if(args[0] == NULL) {
        (void)fprintf(stdout, "usage: mkdir directory_path\n");
        return AFCSH_EXIT_FAILURE;
    }

    status_t status = AFCSH_EXIT_SUCCESS;
    char *full_path = create_full_path(args[1], cwd);

    if(AFCDirectoryCreate(afc, full_path) != MDERR_OK) {
        display_error(E_NO_SUCH_FILE_OR_DIRECTORY, full_path, "mkdir");
        status = AFCSH_EXIT_FAILURE;
    }

    free(full_path);
    return status;
}

static status_t afcsh_copy(char **args, char *cwd) {
    if(args[1] == NULL || args[2] == NULL) {
        (void)fprintf(stdout, "usage: cp source dest\n");
        return AFCSH_EXIT_FAILURE;
    }

    char *source_path = create_full_path(args[1], cwd);
    
    struct afc_file_info file_info;
    status_t file_info_status = create_file_info(&file_info, source_path);
    if(file_info_status != SUCCESS) {
        display_error(file_info_status, args[1], "cp");
        free(source_path);
        return AFCSH_EXIT_FAILURE; 
    }

    if(file_info.a_st_ifmt == S_IFDIR) {
        (void)fprintf(stderr, "cp: copying directories is not supported (yet)\n");
        free(source_path);
        return AFCSH_EXIT_FAILURE; 
    }

    uint8_t *source_data = calloc(file_info.a_st_size, sizeof(uint8_t));
    ASSERT_ALLOC(source_data);
    
    status_t read_file_status = read_file_at_path(source_data, file_info.a_st_size, source_path);
    if(read_file_status != SUCCESS) {
        display_error(read_file_status, args[1], "cp");
        free(source_path);
        free(source_data);
        return AFCSH_EXIT_FAILURE;
    } 

    status_t status = AFCSH_EXIT_SUCCESS;
    char *dest_path = create_full_path(args[2], cwd);

    status_t create_file_status = create_file_at_path(source_data, file_info.a_st_size, dest_path);
    if(create_file_status != SUCCESS){
        display_error(create_file_status, args[2], "cp");
        status = AFCSH_EXIT_FAILURE;
    }

    free(source_path);
    free(source_data);
    free(dest_path);

    return status;
}

status_t afcsh_move(char **args, char *cwd) {
    if(args[1] == NULL || args[2] == NULL) {
        (void)fprintf(stdout, "usage: mv from_path to_path\n");
        return AFCSH_EXIT_FAILURE;
    }

    status_t status = AFCSH_EXIT_SUCCESS;

    char *from = create_full_path(args[1], cwd);
    char *to = create_full_path(args[2], cwd);
    
    if(AFCRenamePath(afc, from, to) != MDERR_OK) {
        display_error(E_NO_SUCH_FILE_OR_DIRECTORY, args[1], "mv");
        status = AFCSH_EXIT_FAILURE;
    }

    free(from);
    free(to);
    return AFCSH_EXIT_SUCCESS;
}

static status_t afcsh_remove(char **args, char *cwd) {
    if(args[0] == NULL) {
        (void)fprintf(stdout, "usage: rm file_path\n");
        return AFCSH_EXIT_FAILURE;
    }

    status_t status = AFCSH_EXIT_SUCCESS;
    char *full_path = create_full_path(args[1], cwd);
    struct afc_file_info file_info;

    status_t file_info_status = create_file_info(&file_info, full_path);
    if(file_info_status != SUCCESS) {
        display_error(E_NO_SUCH_FILE_OR_DIRECTORY, args[1], "rm");
        free(full_path);
        return AFCSH_EXIT_FAILURE;
    }

    if(file_info.a_st_ifmt == S_IFDIR) {
        //Count . and .. as no "regular" files 
        if(file_info.a_st_nlink > 2) {
            (void)fprintf(stderr, "rm: directory has to be empty: %s\n", args[1]);
            free(full_path);
            return AFCSH_EXIT_FAILURE;
        }
    }

    if(AFCRemovePath(afc, full_path) != MDERR_OK) {
        (void)fprintf(stderr, "rm: remove failed internally for path %s\n", full_path);
        free(full_path);
        return AFCSH_EXIT_FAILURE;
    } 

    free(full_path);
    return AFCSH_EXIT_SUCCESS;
}

static status_t afcsh_download(char **args, char *cwd) {
    if(args[1] == NULL || args[2] == NULL) {
        (void)fprintf(stdout, "usage: download remote_path local_path\n");
        return AFCSH_EXIT_FAILURE;
    }

    char *full_path = create_full_path(args[1], cwd);

    struct afc_file_info file_info;
    status_t file_info_status = create_file_info(&file_info, full_path);
    if(file_info_status != SUCCESS) {
        display_error(file_info_status, args[1], "download");
        free(full_path);
        return AFCSH_EXIT_FAILURE; 
    }

    if(file_info.a_st_ifmt == S_IFDIR) {
        (void)fprintf(stderr, "download: downloading directories is not supported: %s\n", args[1]);
        free(full_path);
        return AFCSH_EXIT_FAILURE; 
    }

    uint8_t *remote_file_buffer = calloc(file_info.a_st_size, sizeof(uint8_t));
    ASSERT_ALLOC(remote_file_buffer);

    status_t read_status = read_file_at_path(remote_file_buffer, file_info.a_st_size, full_path);
    if(read_status != SUCCESS) {
        display_error(E_COULD_NOT_READ_FILE, args[1], "download");
        free(full_path);
        return AFCSH_EXIT_FAILURE;
    }

    //Open local file
    FILE *local_file = fopen(args[2], "wb");
    if(local_file == NULL) {
        (void)fprintf(stderr, "download: local file path does not exists or is not accessable\n");
        free(remote_file_buffer); 
        free(full_path);
        return AFCSH_EXIT_FAILURE;
    }

    (void)fprintf(stdout, "Downloading %lu bytes\n", file_info.a_st_size); 
    (void)fwrite(remote_file_buffer, file_info.a_st_size, 1, local_file);
    (void)fclose(local_file);

    free(remote_file_buffer);
    free(full_path);

    return AFCSH_EXIT_SUCCESS;
}

static status_t afcsh_upload(char **args, char *cwd) {
    if(args[1] == NULL || args[2] == NULL) {
        (void)fprintf(stdout, "usage: upload local_path remote_path\n");
        return AFCSH_EXIT_FAILURE;
    }

    char *full_path = create_full_path(args[2], cwd);

    //Open local file
    FILE *local_file = fopen(args[1], "rb");
    if(local_file == NULL) {
        (void)fprintf(stderr, "upload: local file path does not exists or is not accessable\n");
        free(full_path);
        return AFCSH_EXIT_FAILURE;
    }

    struct stat st;
    (void)fstat(fileno(local_file), &st);

    uint8_t *local_file_buffer = calloc(st.st_size, sizeof(uint8_t));
    ASSERT_ALLOC(local_file_buffer);

    (void)fread(local_file_buffer, st.st_size, 1, local_file);
    (void)fclose(local_file);

    status_t create_file_status = create_file_at_path(local_file_buffer, st.st_size, full_path);
    if(create_file_status != SUCCESS) {
        display_error(create_file_status, args[2], "upload");
        free(full_path);
        free(local_file_buffer);
        return AFCSH_EXIT_FAILURE;
    }

    (void)fprintf(stdout, "Wrote %lld bytes\n", st.st_size);
    
    free(full_path);
    free(local_file_buffer);

    return AFCSH_EXIT_SUCCESS;
}   

static status_t afcsh_exit(char **args, char *cwd) {
    return AFCSH_QUIT;
}

static status_t afcsh_clear(char **args, char *cwd) {
    (void)system("clear");
    return AFCSH_EXIT_SUCCESS;
}

static status_t afcsh_help(char **args, char *cwd) {
    (void)fprintf(stdout, "afcsh v%s\n\n", VERSION);
    (void)fprintf(stdout, "AVAILABLE COMMANDS:\n");
    (void)fprintf(stdout, "pwd\t\t\t\tPrints the current working directory\n");
    (void)fprintf(stdout, "cd\t[path]\t\t\tChanges the current working directory\n");
    (void)fprintf(stdout, "ls\t[path]\t\t\tLists the current working directory or specified path\n");
    (void)fprintf(stdout, "file\t[path]\t\t\tPrints information about the specified file\n");
    (void)fprintf(stdout, "touch\t[path]\t\t\tCreates a new empty file\n");
    (void)fprintf(stdout, "mkdir\t[path]\t\t\tCreates a new directory\n");
    (void)fprintf(stdout, "rm\t[path]\t\t\tRemoves a file (recursion not supported yet)\n");
    (void)fprintf(stdout, "cp\t[src]\t[dest]\t\tCopies a file (recursion not supported yet)\n");
    (void)fprintf(stdout, "mv\t[src]\t[dest]\t\tMoves (or renames) a path\n");
    (void)fprintf(stdout, "dl\t[src]\t[dest]\t\tDownloads a file to a specified local path\n");
    (void)fprintf(stdout, "ul\t[src]\t[dest]\t\tUploads a file from a specified local path\n");
    (void)fprintf(stdout, "exit\t\t\t\tTerminates the current session\n");
    (void)fprintf(stdout, "clear\t\t\t\tClears the screen\n");
    (void)fprintf(stdout, "help\t\t\t\tShows this help screen\n");
    return AFCSH_EXIT_SUCCESS;
}