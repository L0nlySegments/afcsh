#include "afcsh_commands.h"

// Command implementaions
extern status_t afcsh_change_directory(char **args, char *cwd) {
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

extern status_t afcsh_print_working_directory(char **args, char *cwd) {
    (void)fprintf(stdout, "%s\n", cwd);
    return AFCSH_EXIT_SUCCESS;
}

extern status_t afcsh_list(char **args, char *cwd) {
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

extern status_t afcsh_file(char **args, char *cwd) {
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

extern status_t afcsh_touch(char **args, char *cwd) {
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

extern status_t afcsh_make_directory(char **args, char *cwd) {
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

extern status_t afcsh_copy(char **args, char *cwd) {
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

extern status_t afcsh_remove(char **args, char *cwd) {
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

extern status_t afcsh_download(char **args, char *cwd) {
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

extern status_t afcsh_upload(char **args, char *cwd) {
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

extern status_t afcsh_exit(char **args, char *cwd) {
    return AFCSH_QUIT;
}

extern status_t afcsh_clear(char **args, char *cwd) {
    (void)system("clear");
    return AFCSH_EXIT_SUCCESS;
}

extern status_t afcsh_help(char **args, char *cwd) {
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