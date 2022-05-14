#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "Common.h"

#define PORT 8080

static int g_sock = -1;
// static char in_buff[64] = {0};
// static char out_buff[64] = {0};

int connect_to_server() {
    struct sockaddr_in serv_addr;
    if ((g_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(g_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    return 0;
}

int get_message(uint8_t * buff, size_t length) {
    recv(g_sock, buff, length, 0);
    return 0;
}

void send_message(uint8_t * buff, size_t length) {
    send(g_sock, buff, length, 0);
}

void talk() {
    uint8_t token = TOKEN_TALK_START;
    uint8_t buff[0x20] = {0};
    send_message(&token, sizeof(token));
    do {
        get_message(buff, sizeof(buff));
    } while (buff[0] != COMMAND_NEXT);
    
    // printf("show message: %s", buff);
    token = TOKEN_TALKCMPLT;
    send_message(&token, sizeof(token));
}

void shell() {
    uint8_t token = TOKEN_SHELL_START;
    uint8_t buff[0x20] = {0};
    send_message(&token, sizeof(token));
    do {
        get_message(buff, sizeof(buff));
    } while (buff[0] != COMMAND_NEXT);

    // while (1) {
    memset(buff, 0, sizeof(buff));
    get_message(buff, sizeof(buff));
    memset(buff, 0x0, sizeof(buff));
        // ??
    send_message(buff, sizeof(buff));
    // }
        
}

void doGh0st() {
    uint8_t buffer[0x40];
    uint8_t token;
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        get_message(buffer, sizeof(buffer));

        switch (buffer[0])
        {
        case COMMAND_TALK:
            talk();
            break;
        case COMMAND_SHELL:
            shell();
            break;
        case COMMAND_BYE:
        case SERVER_EXIT:
            token = buffer[0];
            send_message((void*)&token, 1);
            break;
        default:
            break;
        }
    }
}


int main(int argc, char *argv[]) {

    int res = connect_to_server();
    if (res) {
        return res;
    }

    doGh0st();

    return 0;
}
