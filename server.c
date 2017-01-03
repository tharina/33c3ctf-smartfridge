#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <errno.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PORT 12345
#define MAX_FDS 1024
#define BACKLOG 32
#define BUFFER_SIZE 132


struct pollfd fds[MAX_FDS];
struct client* clients[MAX_FDS];
int numfds = 1;
int randfd;
struct fridge fridge;



enum client_state {CONNECTED, CONFIRM_RECEIVED, BOX_CLOSED, BOX_OPEN };
struct client {
    enum client_state state;
    unsigned int socket;
    struct box* box;
    unsigned char srand[16];
    unsigned char mrand[16];
    unsigned char sconfirm[16];
    unsigned char mconfirm[16];
    unsigned char stk[16];
    unsigned char buffer[BUFFER_SIZE];
    unsigned int  buffer_offset;
    unsigned char aes_buffer[128];
    unsigned char user_id;
};


struct object {
    unsigned char name[16];
    unsigned char description[64];
};

struct box {
    struct object content[5];
};

struct fridge {
    struct box boxes[3];
    unsigned char passcodes[2][7];
};


void remove_client(int i) {
    printf("Disconnecting client %d\n", i);
    close(fds[i].fd);
    fds[i].fd = fds[numfds-1].fd;
    fds[i].events = fds[numfds-1].events;
    free(clients[i]);
    numfds--;
    fds[0].events = POLLIN;
}

void fridge_setup() {
    strcpy(fridge.boxes[0].content[0].name, "cake");
    strcpy(fridge.boxes[0].content[0].description, FLAG3);
    strcpy(fridge.boxes[1].content[0].name, "toast");
    strcpy(fridge.boxes[1].content[0].description, FLAG1);
    strcpy(fridge.boxes[2].content[0].name, "yoghurt");
    strcpy(fridge.boxes[2].content[0].description, FLAG2);

    strcpy(fridge.passcodes[0], PIN1);
    strcpy(fridge.passcodes[1], PIN2);
}




void new_client(unsigned int i, unsigned int socket) {
    clients[i] = (struct client*) malloc(sizeof(struct client));
    clients[i]->buffer_offset = 0;
    clients[i]->state = CONNECTED;
    clients[i]->socket = socket;
    if (read(randfd, clients[i]->srand, 16) != 16) {
        perror("Unable to read random bytes");
        exit(EXIT_FAILURE);
    }
}


void encrypt(const unsigned char* key, const unsigned char* plaintext, unsigned int length, unsigned char* cipher) {
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);
    AES_KEY enc_key;
	AES_set_encrypt_key(key, 128, &enc_key);
    AES_cbc_encrypt(plaintext, cipher, length, &enc_key, iv, AES_ENCRYPT);
}

void decrypt(const unsigned char* key, const unsigned char* cipher, unsigned int length, unsigned char* plaintext) {
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);
    AES_KEY dec_key;
	AES_set_decrypt_key(key, 128, &dec_key);
    AES_cbc_encrypt(cipher, plaintext, length, &dec_key, iv, AES_DECRYPT);
}

void e(const unsigned char* key, const unsigned char* plaintext, unsigned char* cipher) {
    AES_KEY enc_key;
	AES_set_encrypt_key(key, 128, &enc_key);
    AES_encrypt(plaintext, cipher, &enc_key);
}

void c1(const unsigned char* key, const unsigned char* rand, unsigned char* confirm) {
    unsigned long long k[2];
    k[0] = strtoll(key, NULL, 10);
    k[1] = 0;
    e((unsigned char*) k, rand, confirm);
}

void s1(const unsigned char* tk, const unsigned char* rand1, const unsigned char* rand2, unsigned char* stk) {
    unsigned char r[16];
    memcpy(r, rand1 + 8, 8);
    memcpy(r+8, rand2 + 8, 8);
    e(tk, r, stk);
}


bool send_message(struct client* c, char* msg) {
    bool retcode = true;

    unsigned int msglength = strlen(msg);
    unsigned int padlength = 16 - (msglength % 16);
    unsigned int length = msglength + padlength;

    char* buffer = malloc(length);
    memcpy(buffer, msg, msglength);
    memset(buffer + msglength, padlength, padlength);

    unsigned char* cipher = malloc(length + 4);
    encrypt(c->stk, buffer, length, cipher + 4);
    *(int*)cipher = length + 4;
    if (send(c->socket, cipher, length + 4, 0) < length) {
        perror("Unable to send()");
        retcode = false;
    }

    free(buffer);
    free(cipher);

    return retcode;
}


bool send_item(struct client* c, struct object* o) {
    char buf[256];
    memset(buf, 0, 256);
    strcat(buf, o->name);
    if (strlen(o->name) > 0)
        strcat(buf, ": ");
    strcat(buf, o->description);
    strcat(buf, "\n");
    return send_message(c, buf);
}



bool handle(unsigned int i) {
    struct client* c = clients[i];

    while (true) {
        unsigned int size;
        if (c->buffer_offset >= 4) {
            size = *((unsigned int*)c->buffer);
            //printf("Size = %d  Received = %d\n", size, c->buffer_offset);
            if (size > BUFFER_SIZE) {
                return false;
            }
            if (c->buffer_offset < size) {
                return true;
            }
        } else {
            return true;
        }
        printf("Valid packet of size %d received\n", size);

        unsigned char* data = c->buffer + 4;

        unsigned char* command;
        if (c->state != CONNECTED && c->state != CONFIRM_RECEIVED) {
            if ((size - 4) % 16 != 0) {
                puts("Invalid message length");
                return false;
            }
            decrypt(c->stk, data, size - 4, c->aes_buffer);
            unsigned char padlength = c->aes_buffer[size - 4 - 1];
            if (padlength > 16) {
                puts("Invalid padding");
                return false;
            }

            c->aes_buffer[size - 4 - padlength] = 0;
            command = strtok(c->aes_buffer, " ");
            if(command == NULL) {
                return false;
            }
            printf("Command: %s\n", command);
        }

        memmove(c->buffer, c->buffer + size, c->buffer_offset - size);
        c->buffer_offset -= size;

        switch (c->state) {
            case CONNECTED: {
                if (size < 21) {
                    return false;
                }
                // recv mConfirm and send sConfirm
                unsigned char user_id = data[0];
                if(user_id != 1 && user_id != 2) {
                    return false;
                }
                c->user_id = user_id;
                data = data + 1;
                memcpy(c->mconfirm, data, 16);

                puts("Received MConfirm");

                c1(fridge.passcodes[c->user_id - 1], c->srand, c->sconfirm);

                unsigned char buf[20];
                unsigned int size = 20;
                memcpy(buf, &size, 4);
                memcpy(buf + 4, c->sconfirm, 16);

                if (send(c->socket, buf, 20, 0) < 20) {
                    perror("Unable to send()");
                    return false;
                }

                puts("Sent SConfirm");

                c->state = CONFIRM_RECEIVED;
                break;
                }
            case CONFIRM_RECEIVED: {
                if (size < 20) {
                    return false;
                }
                // receive mRand, check mConfirm and send sRand
                memcpy(c->mrand, data, 16);

                puts("Received MRand");

                unsigned char checkmConfirm[16];

                c1(fridge.passcodes[c->user_id - 1], c->mrand, checkmConfirm);
                if (memcmp(checkmConfirm, c->mconfirm, 16) != 0) {
                    puts("Invalid pincode");
                    return false;
                }

                puts("MConfirm validated");

                unsigned char buf[20];
                unsigned int size = 20;
                memcpy(buf, &size, 4);
                memcpy(buf + 4, c->srand, 16);
                if (send(c->socket, buf, 20, 0) < 20) {
                    perror("Unable to send()");
                    return false;
                }

                puts("Sent SRand");

                unsigned long long k[2];
                k[0] = strtoll(fridge.passcodes[c->user_id - 1], NULL, 10);
                k[1] = 0;
                s1((unsigned char*) k , c->srand, c-> mrand, c->stk);

                c->state = BOX_CLOSED;
                puts("Paired");
                break;
                }
            case BOX_CLOSED:
                if (strcmp(command, "OPEN") == 0) {
                    unsigned char* option = strtok(NULL, " ");
                    printf("Option: %s\n", option);
                    if(option != NULL) {
                        int boxnum = option[0] - '0';
                        if (boxnum >= 0 && boxnum <= 2 && boxnum == c->user_id) {
                            c->box = &fridge.boxes[boxnum];
                        } else {
                            return false;
                        }
                        c->state = BOX_OPEN;
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
                break;
            case BOX_OPEN:
                if (strcmp(command, "LIST") == 0) {
                    char buf[256];
                    memset(buf, 0, 256);
                    for (int i = 0; i < 5; i++) {
                        buf[strlen(buf)] = '0' + i;
                        strcat(buf, ". ");
                        strcat(buf, c->box->content[i].name);
                        strcat(buf, "\n");
                    }
                    if (!send_message(c, buf))
                        return false;
                } else if (strcmp(command, "SHOW") == 0) {
                    unsigned char* option = strtok(NULL, " ");
                    if(option != NULL) {
                        int id = option[0] - '0';
                        if(id >= 0 && id < 5) {
                            if(!send_item(c, &(c->box->content[id])))
                                return false;
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                } else if (strcmp(command, "TAKE") == 0) {
                    unsigned char* option = strtok(NULL, " ");
                    if(option != NULL) {
                        int id = option[0] - '0';
                        if(id > 0 && id < 5) {
                            if (!send_item(c, &c->box->content[id]))
                                return false;
                            memset(&c->box->content[id], 0, sizeof(struct object));
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                } else if (strcmp(command, "PUT") == 0) {
                    unsigned char* option = strtok(NULL, " ");
                    if (option == NULL)
                        return false;
                    int id = option[0] - '0';
                    if (id < 0 || id > 4)
                        return false;
                    unsigned char* name = strtok(NULL, " ");
                    if (name == NULL || strlen(name) > 15)
                        return false;
                    unsigned char* description = strtok(NULL, "");
                    if (description == NULL || strlen(description) > 63)
                        return false;
                    if (strlen(c->box->content[id].name) == 0) {
                        strcpy(c->box->content[id].name, name);
                        strcpy(c->box->content[id].description, description);
                    }
                } else if (strcmp(command, "CLOSE") == 0) {
                    c->state = BOX_CLOSED;
                    c->box = NULL;
                } else {
                    return false;
                }

                break;
        }
    }

    return true;
}


int init_socket() {
    // create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket.");
        exit(EXIT_FAILURE);
    }

    // reusable sockfd
    int val = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*) &val, sizeof val) < 0) {
        perror("Unable to set socket option REUSEADDR.");
        exit(EXIT_FAILURE);
    }

    // bind socket
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if (bind(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        close(sockfd);
        perror("Unable to bind socket.");
        exit(EXIT_FAILURE);
    }

    // set backlog
    if (listen(sockfd, BACKLOG) < 0) {
        close(sockfd);
        perror("Unable to set backlog.");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}






int main() {
    fridge_setup();

    randfd = open("/dev/urandom", O_RDONLY);

    int sockfd = init_socket();

    // init poll() datastructure with listening socket
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;

    // poll loop
    do {
        int r = poll(fds, numfds, -1);
        if (r < 0) {
            close(sockfd);
            perror("poll() failed.");
            exit(EXIT_FAILURE);
        } else if (r == 0) {
            // timeout
        } else {
            // check for incoming connections
            if (fds[0].revents & POLLIN) {
                fds[0].revents = 0;
                if (numfds < MAX_FDS) {
                    int newsockfd = accept(sockfd, NULL, NULL);
                    if (newsockfd < 0) {
                        perror("Unable to create socket for incoming connection");
                        exit(EXIT_FAILURE);
                    }
                    fds[numfds].fd = newsockfd;
                    fds[numfds].events = POLLIN;
                    new_client(numfds, newsockfd);
                    numfds++;
                } else {
                    fds[0].events = 0;
                }
            }

            // handle incoming data
            for (int i = 1; i < numfds; i++) {
                if (fds[i].revents & POLLIN) {
                    printf("Data received on %d\n", i);
                    fds[i].revents = 0;
                    struct client* c = clients[i];
                    int r = recv(fds[i].fd, c->buffer + c->buffer_offset, BUFFER_SIZE - c->buffer_offset, 0);
                    if (r <= 0) {
                        remove_client(i);
                        break;
                    } else {
                        c->buffer_offset += r;
                        if (!handle(i)) {
                            remove_client(i);
                            break;
                        }
                    }
                }
            }
        }
    } while (true);
}
