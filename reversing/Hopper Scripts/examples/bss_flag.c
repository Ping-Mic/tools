#include <stdio.h>
#include <stdbool.h>
#include <string.h>

// char flag[] = "flag{gu3s1ng_fl4g_1s_h4rd!}";
char encrypted_flag[] = "f6s8g,ub5 r9z0`x3pe2q=%s;>_";
char* challenge __attribute__ ((section (".bss")));

char* encrypt(char* t) {
    int i;
    int len = strlen(t);
    for(i = 1; i < len; i++){
        t[i] = t[i-1] ^ (0xc0 + t[i]) + 0x24;
    }
    return t;
}

bool check(char* challenge) {
    if(strlen(challenge) != strlen(encrypted_flag)){
        return false;
    }
    if(strcmp(encrypt(challenge), encrypted_flag) == 0){
        return true;
    }
    else{
        return false;
    }
}

int main(int argc, char *argv[]) {
    // if(argc == 1){
    //     printf("encrypted flag = %s\n", encrypt(flag));
    //     return 0;
    // }
    if(argc != 2){
        printf("usage: %s <FLAG>\n", argv[0]);
        return 0;
    }
    challenge = argv[1];
    if(check(challenge)){
        printf("collect.\n");
    }
    else{
        printf("wrong.\n");
    }
    return 0;
}