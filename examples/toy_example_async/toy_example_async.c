#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


#define PORT 8080
#define LOGIN       "login"
#define OK1         "ok1"
#define OK2         "ok2"
#define LOGOUT1     "logout1"
#define LOGOUT2     "logout2"
#define BLOOP       "bloop"
#define FOUND       "yeah, you found me!"

int sock = 0;


#define HELLO       "hello"
#define QUIT        "quit"
#define BYE         "bye"

void sendString(char* msg) {
    int len = strlen(msg);
    send(sock, &len, sizeof(len), 0);
    send(sock, msg, strlen(msg), 0);
}

bool onMessageReceived(char* data, int len) {
    if (strcmp(data, HELLO) == 0) {
        sendString(HELLO);
        return true;
    } else if (strcmp(data, QUIT) == 0) {
        sendString(BYE);
        return false;
    }

    return false;
}

bool recvAux() {
    int size;
    if (recv(sock, &size, sizeof(int), 0) != sizeof(int)) {
        return false;
    }
    char* data = malloc(size);
    int received = recv(sock, data, size, 0);
    if (received != size) {
        free(data);
        return false;
    }
    data[size] = '\x00';
    // Uncompress data etc....
    printf("Recieved %s\n", data);
    bool res = onMessageReceived(data, size);
    free(data);
    return res;
}

int main(int argc, char *argv[]) {
    struct sockaddr_in serv_addr;
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


    bool connectionActive = true;
    while (connectionActive) {
        connectionActive = recvAux();
    }

    close(sock);

    return 0;
}
