#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>


#define PORT 8080
#define LOGIN       "login"
#define OK1         "ok1"
#define OK2         "ok2"
#define LOGOUT1     "logout1"
#define LOGOUT2     "logout2"
#define BLOOP       "bloop"

int main(int argc, char *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char send_buff[64] = {0};
    char buffer[64] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    int magic_number;
    scanf("%d", &magic_number);
    memcpy(send_buff, LOGIN, strlen(LOGIN));
    memcpy(send_buff + strlen(LOGIN), &magic_number, sizeof(int));
    *(send_buff + strlen(LOGIN) + sizeof(int)) = 0x0;

    // hexdump(send_buff, 5 + sizeof(int) + 1);

    send(sock, send_buff, strlen(LOGIN) + sizeof(int) + 1, 0);

    while (1) {
        //    hexdump(buffer, 64);

        // Read number
        scanf("%d", &magic_number);

        if (magic_number > 5) {
            send(sock, BLOOP, strlen(BLOOP), 0);
            break;
        }

        recv(sock, buffer, 64, 0);
        if (strcmp(buffer, OK1) == 0) {
            send(sock, LOGOUT1, strlen(LOGOUT1), 0);
        } else if (strcmp(buffer, OK2) == 0) {
            send(sock, LOGOUT2, strlen(LOGOUT2), 0);
        } else {
            printf("\nError: %s\n", buffer);
            break;
        }
    }

    close(sock);

    return 0;
}