#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

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

bool has_message() {
    return true;
}

void get_message(uint8_t * buff, size_t length) {
    recv(g_sock, buff, length, 0);
}

void send_message(uint8_t * buff, size_t length) {
    send(g_sock, buff, length, 0);
}

void wait_for_dialog() {
    uint8_t buff[0x20] = {0};
    do {
        // if (has_message()) {
        get_message(buff, sizeof(buff));
        if (buff[0] == COMMAND_NEXT) break;
        // }
    } while (true);
}

void talk() {
    uint8_t token = TOKEN_TALK_START;
    send_message(&token, sizeof(token));
    wait_for_dialog();
    
    // printf("show message: %s", buff);
    token = TOKEN_TALKCMPLT;
    send_message(&token, sizeof(token));
}

void shell() {
    uint8_t token = TOKEN_SHELL_START;
    send_message(&token, sizeof(token));
    wait_for_dialog();

    // while (1) {
   // memset(buff, 0, sizeof(buff));
    // get_message(buff, sizeof(buff));
    // memset(buff, 0x0, sizeof(buff));
        // ??
    // send_message(buff, sizeof(buff));
    // }
        
}

void send_processes() {
    uint8_t buffer[0x20] = {0};
    buffer[0] = TOKEN_PSLIST;
    sprintf((char*)&buffer[1], "%s", "processlist");
    send_message((void*)buffer, 1 + strlen("processlist"));
}

void send_windows() {
    uint8_t buffer[0x20] = {0};
    buffer[0] = TOKEN_WSLIST;
    sprintf((char*)&buffer[1], "%s", "windowslist");
    send_message((void*)buffer, 1 + strlen("windowslist"));
}

enum {
    COMMAND_WINDOW_CLOSE,
    COMMAND_WINDOW_TEST
};

void do_system(uint8_t cmd) {
    uint8_t buffer[0x20] = {0};
    if (cmd == COMMAND_SYSTEM) {
        send_processes();
    } else {
        send_windows();
    }

    while(has_message()) {
        get_message(buffer, sizeof(buffer));
        switch (buffer[0]) {
            case COMMAND_KILLPROCESS:
            
            break;
            case COMMAND_PSLIST:
            send_processes();
            break;
            case COMMAND_WSLIST:
            send_windows();
            break;
            case COMMAND_WINDOW_CLOSE:
            send_windows();
            break;
            case COMMAND_WINDOW_TEST:

            break;
            default:
            exit(-1);
            break;
        }
    }

}

void do_screen_spy() {
    uint8_t buffer[0x20] = {0};
    buffer[0] = TOKEN_BITMAPINFO;
    sprintf((char*)&buffer[1], "%s", "screenbitmapinfo");
    send_message((void*)buffer, 1 + strlen("screenbitmapinfo"));
    wait_for_dialog();
    memset(buffer, 0, sizeof(buffer));
    buffer[0] = TOKEN_FIRSTSCREEN;
    sprintf((char*)&buffer[1], "%s", "first screen");
    send_message((void*)buffer,  1 + strlen("first screen"));
    while (has_message()) {
        while (has_message()){
            get_message(buffer, sizeof(buffer));
            switch (buffer[0]) {
                case COMMAND_SCREEN_GET_CLIPBOARD:
                    buffer[0] = TOKEN_CLIPBOARD_TEXT;
                    sprintf((char*)&buffer[1], "%s", "clipboard text");
                    send_message(buffer, 1 + strlen("clipboard text"));
                break;
                case COMMAND_SCREEN_SET_CLIPBOARD:
                    printf("set clipboard");
                break;
                case COMMAND_SCREEN_BLOCK_INPUT:
                    printf("block input");
                break;
                case COMMAND_SCREEN_CONTROL:
                    printf("control command");
                break;
            }
        }

        memset(buffer, 0, sizeof(buffer));
        buffer[0] = TOKEN_NEXTSCREEN;
        sprintf((char*)&buffer[1], "%s", "next screen");
        send_message(buffer, 1 + strlen("next screen"));

    }
}

void SendToken(uint8_t token) {
    send_message(&token, sizeof(token));
}

void StopTransfer() {
    SendToken(TOKEN_TRANSFER_FINISH);
}

typedef struct 
{
	int32_t	dwSizeHigh;
	int32_t	dwSizeLow;
}FILESIZE;

uint8_t m_nTransferMode = TRANSFER_MODE_NORMAL;

void GetFileData(){
    uint8_t	bToken[9] = {0};
    int	nTransferMode;
	switch (m_nTransferMode)
	{
	case TRANSFER_MODE_OVERWRITE_ALL:
		nTransferMode = TRANSFER_MODE_OVERWRITE;
		break;
	case TRANSFER_MODE_ADDITION_ALL:
		nTransferMode = TRANSFER_MODE_ADDITION;
		break;
	case TRANSFER_MODE_JUMP_ALL:
		nTransferMode = TRANSFER_MODE_JUMP;
		break;
	default:
		nTransferMode = m_nTransferMode;
	}

    bToken[0] = TOKEN_DATA_CONTINUE;

    	// 文件已经存在
	if (has_message())
	{
		// 提示点什么
		// 如果是续传
		if (nTransferMode == TRANSFER_MODE_ADDITION)
		{
			// memcpy(bToken + 1, &FindFileData.nFileSizeHigh, 4);
			// memcpy(bToken + 5, &FindFileData.nFileSizeLow, 4);
            sprintf((char*)&bToken[1], "%s", "filesz");
			// // dwCreationDisposition = OPEN_EXISTING;
		}
		// 覆盖
		else if (nTransferMode == TRANSFER_MODE_OVERWRITE)
		{
			// 偏移置0
			memset(bToken + 1, 0, 8);
			// 重新创建
			// dwCreationDisposition = CREATE_ALWAYS;
		}
		// 传送下一个
		else if (nTransferMode == TRANSFER_MODE_JUMP)
		{
			int32_t dwOffset = -1;
			memcpy(bToken + 5, &dwOffset, 4);
			// dwCreationDisposition = OPEN_EXISTING;
		}
	}
	else
	{
		// 偏移置0
		memset(bToken + 1, 0, 8);
		// 重新创建
		// dwCreationDisposition = CREATE_ALWAYS;
	}

    send_message(bToken, sizeof(bToken));
}

void CreateLocalRecvFile(uint8_t * lpBuffer) {
    // FILESIZE	*pFileSize = (FILESIZE *)lpBuffer;
	// 保存当前正在操作的文件名
	// memset(m_strCurrentProcessFileName, 0, sizeof(m_strCurrentProcessFileName));
	// strcpy(m_strCurrentProcessFileName, (char *)lpBuffer + 8);

	// 保存文件长度
	// m_nCurrentProcessFileLength = (pFileSize->dwSizeHigh * (INT_MAX + long long(1))) + pFileSize->dwSizeLow;
	
	// 创建多层目录
	// MakeSureDirectoryPathExists(m_strCurrentProcessFileName);

	// WIN32_FIND_DATA FindFileData;
	// HANDLE hFind = FindFirstFile(m_strCurrentProcessFileName, &FindFileData);
	
	if (has_message()
		&& m_nTransferMode != TRANSFER_MODE_OVERWRITE_ALL 
		&& m_nTransferMode != TRANSFER_MODE_ADDITION_ALL
		&& m_nTransferMode != TRANSFER_MODE_JUMP_ALL
		)
	{
		SendToken(TOKEN_GET_TRANSFER_MODE);
	}
	else
	{
		GetFileData();
	}
	// FindClose(hFind);
}


void SendFileSize() {
    uint8_t buffer [0x20] = {0};
    memset(buffer, 0, sizeof(buffer));
    buffer[0] = TOKEN_FILE_SIZE;
    sprintf((char*)&buffer[1], "%s", "filesizename");
    send_message(buffer, 1 + strlen("filesizename"));
}

void UploadToRemote() {
	if (has_message())
	{
		// FixedUploadList((char *)lpBuffer);
		if (has_message())
		{
			StopTransfer();
		}
	}
	else
	{
		// m_UploadList.push_back((char *)lpBuffer);
	}

	// list <string>::iterator it = m_UploadList.begin();
	// 发送第一个文件
	SendFileSize();

}

void WriteLocalRecvFile(uint8_t * lpBuffer, size_t nSize)
{
	// 传输完毕
	// uint8_t	*pData;
	// int32_t	dwBytesToWrite;
	// int32_t	dwBytesWrite;
	// int		nHeadLength = 9; // 1 + 4 + 4  数据包头部大小，为固定的9
	// FILESIZE	*pFileSize;
	// 得到数据的偏移
	// pData = lpBuffer + 8;
	
	// pFileSize = (FILESIZE *)lpBuffer;

	// 得到数据在文件中的偏移
	// long	dwOffsetHigh = pFileSize->dwSizeHigh;
	// long	dwOffsetLow = pFileSize->dwSizeLow;
	
	// dwBytesToWrite = nSize - 8;
	
	// HANDLE	hFile = 
	// 	CreateFile
	// 	(
	// 	m_strCurrentProcessFileName,
	// 	GENERIC_WRITE,
	// 	FILE_SHARE_WRITE,
	// 	NULL,
	// 	OPEN_EXISTING,
	// 	FILE_ATTRIBUTE_NORMAL,
	// 	0
	// 	);
	
	// SetFilePointer(hFile, dwOffsetLow, &dwOffsetHigh, FILE_BEGIN);
	
	// int nRet = 0;
	// 	// 写入文件
	// nRet = WriteFile
	// 	(
	// 	hFile,
	// 	pData, 
	// 	dwBytesToWrite, 
	// 	&dwBytesWrite,
	// 	NULL
	// 	);
	// CloseHandle(hFile);
	// 为了比较，计数器递增
	uint8_t	bToken[9] = {0};
	bToken[0] = TOKEN_DATA_CONTINUE;
	// dwOffsetLow += dwBytesWrite;
	// memcpy(bToken + 1, &dwOffsetHigh, sizeof(dwOffsetHigh));
	// memcpy(bToken + 5, &dwOffsetLow, sizeof(dwOffsetLow));
	send_message(bToken, sizeof(bToken));
}

void UploadNext()
{
	// list <string>::iterator it = m_UploadList.begin();
	// 删除一个任务
	// m_UploadList.erase(it);
	// 还有上传任务
	if(has_message())
	{
		SendToken(TOKEN_TRANSFER_FINISH);
	}
	else
	{
		// 上传下一个
		// it = m_UploadList.begin();
		SendFileSize();
	}
}

void SendFileData()
{
	uint8_t buffer [0x20] = {0};
	// pFileSize = (FILESIZE *)lpBuffer;
	// lpFileName = m_strCurrentProcessFileName;

	// 远程跳过，传送下一个
	if (has_message())
	{
		UploadNext();
		return;
	}
	// HANDLE	hFile;
	// hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	// if (hFile == INVALID_HANDLE_VALUE)
	// 	return -1;

	// SetFilePointer(hFile, pFileSize->dwSizeLow, (long *)&(pFileSize->dwSizeHigh), FILE_BEGIN);

	// int		nHeadLength = 9; // 1 + 4 + 4数据包头部大小
	// DWORD	nNumberOfBytesToRead = MAX_SEND_BUFFER - nHeadLength;
	// DWORD	nNumberOfBytesRead = 0;

	// LPBYTE	lpPacket = (LPBYTE)LocalAlloc(LPTR, MAX_SEND_BUFFER);
	// Token,  大小，偏移，文件名，数据
	buffer[0] = TOKEN_FILE_DATA;
	// memcpy(lpPacket + 1, pFileSize, sizeof(FILESIZE));
	// ReadFile(hFile, lpPacket + nHeadLength, nNumberOfBytesToRead, &nNumberOfBytesRead, NULL);
	// CloseHandle(hFile);

	if (has_message())
	{
		send_message(buffer, sizeof(buffer));
	}
	else
	{
		UploadNext();
	}

	// LocalFree(lpPacket);

	// return nRet;
}

void SetTransferMode(uint8_t * buffer) {
    if (buffer[0] > 7) exit(-1);
    m_nTransferMode = buffer[0];
    GetFileData();
}

void do_list_drive() {
    uint8_t buffer[0x20] = {0};
    buffer[0] = TOKEN_DRIVE_LIST;
    sprintf((char*)&buffer[1], "%s", "drive list");
    send_message(buffer, 1 + strlen("drive list"));
    m_nTransferMode = TRANSFER_MODE_NORMAL;
    int i = 0;
    while (i++<2) {
        get_message(buffer, sizeof(buffer));
         switch (buffer[0])
        {
        case COMMAND_LIST_FILES:// 获取文件列表
            memset(buffer, 0, sizeof(buffer));
            buffer[0] = TOKEN_FILE_LIST;
            sprintf((char*)&buffer[1], "%s", "file list");
            send_message(buffer, 1 + strlen("file list"));
            break;
        case COMMAND_DELETE_FILE:// 删除文件
            SendToken(TOKEN_DELETE_FINISH);
            break;
        case COMMAND_DELETE_DIRECTORY:// 删除文件
            SendToken(TOKEN_DELETE_FINISH);
            break;
        case COMMAND_DOWN_FILES: // 上传文件
            UploadToRemote();
            break;
        case COMMAND_CONTINUE: // 上传文件
            SendFileData();
            break;
        case COMMAND_CREATE_FOLDER:
            SendToken(TOKEN_CREATEFOLDER_FINISH);
            break;
        case COMMAND_RENAME_FILE:
            SendToken(TOKEN_RENAME_FINISH);
            break;
        case COMMAND_STOP:
            SendToken(TOKEN_TRANSFER_FINISH);
            break;
        case COMMAND_SET_TRANSFER_MODE:
            SetTransferMode(&buffer[1]);
            break;
        case COMMAND_FILE_SIZE:
            CreateLocalRecvFile(buffer + 1);
            break;
        case COMMAND_FILE_DATA:
            WriteLocalRecvFile(buffer + 1, sizeof(buffer)-1);
            break;
        case COMMAND_OPEN_FILE_SHOW:
            // OpenFile((char *)lpBuffer + 1, SW_SHOW);
            break;
        case COMMAND_OPEN_FILE_HIDE:
            // OpenFile((char *)lpBuffer + 1, SW_HIDE);
            break;
        default:
            exit(-1);
            break;
        }
    }

}

void do_webcam() {
    uint8_t buffer[0x20] = {0};
    bool isCompressed = false;
    buffer[0] = TOKEN_WEBCAM_BITMAPINFO;
    sprintf((char*)&buffer[1], "%s", "webcambitmapinfo");
    send_message(buffer, 1 + strlen("webcambitmapinfo"));

    wait_for_dialog();

    while (has_message()) {
        while (has_message()) {
            get_message(buffer, sizeof(buffer));
            if (buffer[0] == COMMAND_WEBCAM_ENABLECOMPRESS) {
                isCompressed = true;
            } else if (buffer[0] == COMMAND_WEBCAM_DISABLECOMPRESS) {
                isCompressed = false;
            } else {
                exit(-1);
            }
        }

        memset(buffer, 0, sizeof(buffer));
        buffer[0] = TOKEN_WEBCAM_DIB;
        buffer[1] = isCompressed; // isCompressed?
        sprintf((char*)&buffer[2], "%s", "bitmap DIB");
        send_message(buffer, 2 + strlen("bitmap DIB"));
    }

}

void do_audio() {
    uint8_t buffer[0x20] = {0};
    buffer[0] = TOKEN_AUDIO_START;
    send_message(buffer, 1);

    wait_for_dialog();

    while (has_message()) {
        while (has_message()) {
            get_message(buffer, sizeof(buffer));
            if (buffer[0] == COMMAND_AUDIO) {
                printf("play audio");
            }
        }

        memset(buffer, 0, sizeof(buffer));
        buffer[0] = TOKEN_AUDIO_DATA;
        sprintf((char*)&buffer[1], "%s", "audio data");
        send_message(buffer, 1 + strlen("audio data"));
    }
}

void do_regedit() {
    uint8_t buffer[0x20] = {0};
    buffer[0] = TOKEN_REGEDIT;
    send_message(buffer, 1);

    while (has_message()) {
        get_message(buffer, sizeof(buffer));
        if (buffer[0] == COMMAND_REG_FIND) {
            printf("register operation..");
        } else {
            exit(-1);
        }
    }
}

void service_config(uint8_t * buffer, size_t length) {
    switch(buffer[0]) {
        case 1:
        printf("start");
        break;
        case 2:
        printf("stop");
        break;
        case 3:
        printf("auto");
        break;
        case 4:
        printf("demand start");
        break;
        default:
        exit(-1);
        break;
    }
}

void send_services_list() {
    uint8_t buffer[0x20] = {0};
    buffer[0] = TOKEN_SERVERLIST;
    sprintf((char*)&buffer[1], "%s", "serviceslist");
    send_message(buffer, 1 + strlen("serviceslist"));
}

void do_services() {
    uint8_t buffer[0x20] = {0};
    send_services_list();
    while (has_message()) {
        get_message(buffer, sizeof(buffer));
        switch (buffer[0]) {
            case COMMAND_SERVICECONFIG:
                service_config(&buffer[1], sizeof(buffer)-1);
            case COMMAND_SERVICELIST:
                send_services_list();
            break;
            default:
            exit(-1);
            break;
        }
    }
}

void doGh0st() {
    uint8_t buffer[0x20];
    uint8_t token;
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
    case COMMAND_SCREEN_SPY:
        do_screen_spy();
        break;
    case COMMAND_SYSTEM:
        do_system(buffer[0]);
        break;
    case COMMAND_WSLIST:
        do_system(buffer[0]);
        break;
    case COMMAND_LIST_DRIVE:
        // do_list_drive();
        break;
    case COMMAND_WEBCAM:
        do_webcam();
        break;
    case COMMAND_AUDIO:
        do_audio();
        break;
    case COMMAND_REGEDIT:
        do_regedit();
        break;
    case COMMAND_SERVICES:
        do_services();
        break;
    case COMMAND_BYE:
        token = COMMAND_BYE;
        send_message((void*)&token, 1);
        break;
    case SERVER_EXIT:
        token = SERVER_EXIT;
        send_message((void*)&token, 1);
        break;
    default:
        exit(-1);
        break;
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
