/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements a simple CMU-TCP client. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmu_tcp.h"

#define BUF_SIZE (2 * 1024 * 1024 + 3)

uint8_t buf[BUF_SIZE];

void functionality(cmu_socket_t *sock, int index) {
  int read;
  FILE *fp;


  switch (index) {
    case 1:
      fp = fopen("/vagrant/project-2_15-441/test_files/1_512B.txt", "rb");
      read = fread(buf, 1, 513, fp);
      break;
    case 2:
      fp = fopen("/vagrant/project-2_15-441/test_files/2_4KB.txt", "rb");
      read = fread(buf, 1, 4097, fp);
      break;
    case 3:
      fp = fopen("/vagrant/project-2_15-441/test_files/3_32KB.txt", "rb");
      read = fread(buf, 1, 32769, fp);
      break;
    case 4:
      fp = fopen("/vagrant/project-2_15-441/test_files/4_256KB.txt", "rb");
      read = fread(buf, 1, 262145, fp);
      break;
    case 5:
      fp = fopen("/vagrant/project-2_15-441/test_files/5_2MB.txt", "rb");
      read = fread(buf, 1, 2097153, fp);
      break;
  }
  
  printf("read %d byte\n", read);
  cmu_write(sock, buf, read);
}

int main(int argc, char const *argv[]) {
  if (argc < 2)  {
    printf("usage: ./client [1-5]\n\
            1: 512B file\n\
            2: 4KB file\n\
            3: 32KB file\n\
            4: 256KB file\n\
            5: 2MB file\n");
    exit(EXIT_FAILURE);
  }

  int portno;
  char *serverip;
  char *serverport;
  cmu_socket_t socket;

  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }

  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }
  portno = (uint16_t)atoi(serverport);

  if (cmu_socket(&socket, TCP_INITIATOR, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket, atoi(argv[1]));

  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
