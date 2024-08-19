#ifndef ERROR_H
#define ERROR_H

/* status_t return values */
#define SUCCESS 0
#define E_NOT_IMPLEMENTED -1
#define E_NO_SUCH_FILE_OR_DIRECTORY -2
#define E_NOT_A_DIRECTORY -3
#define E_IS_A_DIRECTORY -4
#define E_COULD_NOT_OPEN_FILE -5
#define E_COULD_NOT_READ_FILE -6
#define E_COULD_NOT_WRITE_FILE -7
#define E_VALUE_TOO_LONG -8

/* Custom types */
typedef short status_t;

/* Methods */
extern void display_error(status_t status, char *offending, char *name);

#endif