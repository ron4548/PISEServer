#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>


#define PORT 8080
#define LOGIN       "login"
#define OK          "ok"
#define DATA        "data"
#define ABORT       "abort"
#define FOUND       "backdoor is found!"

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
    int backdoorCounter = 0;
    while (1) {
        //    hexdump(buffer, 64);

        // Read number
        scanf("%d", &magic_number);

        if (magic_number > 5) {
            send(sock, ABORT, strlen(ABORT), 0);
            break;
        }

        recv(sock, buffer, sizeof(buffer), 0);
        if (strcmp(buffer, OK) != 0) { close(sock); exit(-1); }

        memset(send_buff, 0, sizeof(send_buff));
        memcpy(send_buff, DATA, strlen(DATA) + 1);

        int* version = (int*)&buffer[strlen(OK) + 1];
        if (*version == 1) {
            *(int*)&send_buff[strlen(DATA) + 1] = *version;
            send(sock, send_buff, strlen(DATA) + sizeof(int) + 1, 0);
        } else if (*version == 2) {
            *(int*)&send_buff[strlen(DATA) + 1] = *version;
            send(sock, send_buff, strlen(DATA) + sizeof(int) + 1, 0);

            if (backdoorCounter++ == 2) {
                send(sock, FOUND, strlen(FOUND) + 1, 0);
            }

        } else {
            printf("\nError: %s\n", buffer);
            close(sock);
            exit(-1);
        }
    }

    close(sock);

    exit(0);
}
