#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <CoreFoundation/CoreFoundation.h>

#include "afcsh.h"
#include "afcsh_helpers.h"
#include "afcsh_commands.h"

// Relevant info of our current device
const char* device_name;

/* Command strings list */
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

#define AFCSH_NUM_CMDS sizeof(afcsh_cmd_str) / sizeof(char*)

/* Command functions list */
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


/// <summary>
/// Loads the mobile device framework dylib and symbolicates all the necessary methods for AFC.
/// It will then subscribe afcsh's device_notification_callback() as a callback method, which will fire when an AppleMobileDevice connects to the computer via usb.
/// We will await this event using CoreFoundation's CFRunLoopRun().
/// </summary>
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

/// <summary>
/// This callback method will be called when an AppleMobileDevice connects to this computer (subscribed via AMDeviceNotificationSubscribe()).
/// It will recive a struct *am_device_notification_callback_info, as well as an (not documented) void pointer.
/// The struct *am_device_notification_callback_info contains:
///     - A reference to an *am_device struct 
///     - A connection status message (e.g ADNCI_MSG_XX)  
///
/// Once a connection has been established, the device "ProductType" and "ProductVersion" are copied. They will later be displayed as a shell prefix.
/// It will then start the com.apple.afc service using AMDeviceStartService() and establish an AFC connetion, which is used to start the main loop (afcsh_loop()).
/// </summary>
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


static char *get_shell_prefix(const char *device_name, const char *cwd) {
    char *prefix = calloc(AFCSH_PREFIX_BUFSIZE + 1, sizeof(char));
    ASSERT_ALLOC(prefix);

    bool is_home = (strcmp(cwd, JAILED_DIR) == 0);
    snprintf(prefix, AFCSH_PREFIX_BUFSIZE - 1, "%s %s $ ", device_name, is_home ? "~" : cwd);

    return prefix;
}

static int afcsh_execute(char **args, char *cwd) {
    if(args[0] == NULL)
        return AFCSH_EXIT_SUCCESS;
    
    for(int i = 0; i < AFCSH_NUM_CMDS; i++) {
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
