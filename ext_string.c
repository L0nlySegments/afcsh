#include <string.h>

char *ltrim(char *s, int n) {
    int c = 0;
    while(c < n) {
        s++;
        c++;
    }
    return s;
}

char *rtrim(char *s, int n) {
    int c = 0;
    char *back = s + strlen(s) - 1;
    while(c < n) {
        back--;
        c++;
    }
    *(back+1) = '\0';
    return s;
}

char *rtrim_until(char *s, char chr) {
    char *back = s + strlen(s) - 1;
    while(*back != chr) {
        back--;
    }
    *(back+1) = '\0';
    return s;
}


void strip(char *s) {
    int non_space_count = 0;
    for(int i = 0; s[i] != '\0'; i++) {
        if(s[i] != ' ') {
            s[non_space_count] = s[i];
            non_space_count++;
        }
    }

    s[non_space_count] = '\0';
    //return s;
}

