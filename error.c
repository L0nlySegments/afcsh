#include <stdio.h>
#include <errno.h>

#include "error.h"

extern void display_error(status_t status, char *offending, char *name) {
    switch(status) {
        case E_NOT_IMPLEMENTED:
            (void)fprintf(stderr, "%s: not implemented: %s\n", name, offending);
            break;

        case E_NO_SUCH_FILE_OR_DIRECTORY:
            (void)fprintf(stderr, "%s: no such file or directory: %s\n", name, offending);
            break;
        
        case E_NOT_A_DIRECTORY:
            (void)fprintf(stderr, "%s: not a directory: %s\n", name, offending);
            break;

        case E_IS_A_DIRECTORY:
            (void)fprintf(stderr, "%s: path is a directory: %s\n", name, offending);
            break;
        
        case E_COULD_NOT_OPEN_FILE:
            (void)fprintf(stderr, "%s: could not open file: %s\n", name, offending);
            break;
        case E_COULD_NOT_READ_FILE:
            (void)fprintf(stderr, "%s: could not read file: %s\n", name, offending);
            break;
        case E_COULD_NOT_WRITE_FILE:
            (void)fprintf(stderr, "%s: could not write to file: %s\n", name, offending);
            break;
        case E_VALUE_TOO_LONG:
            (void)fprintf(stderr, "%s: value too long: %s\n", name, offending);
            break;
    }
}