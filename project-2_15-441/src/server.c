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
 * This file implements a simple CMU-TCP server. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "cmu_tcp.h"

#define BUF_SIZE (2 * 1024 * 1024 + 3)

uint8_t buf[BUF_SIZE];
/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t *sock, int index) {
  FILE *fp;
  int read = 0, to_read = 512;
  int n;
  struct timeval start, end;

  n = cmu_read(sock, buf, BUF_SIZE, NO_FLAG);
  gettimeofday(&start, NULL);

  fp = fopen("/tmp/file.c", "w");
  for (int i = 1; i < index; i++)
    to_read *= 8;

  while (read < to_read) {
    n = cmu_read(sock, buf, BUF_SIZE, NO_WAIT);
    if (n > 0) {
      printf("N: %d\n", n);
      fwrite(buf, 1, n, fp);
    }
    read += n;
  }
  gettimeofday(&end, NULL);
  int interval = (end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec);
  printf("total read: %d\n", read);
  printf("time cost: %d ms\n", interval / 1000);
  fclose(fp);
}

int main(int argc, char const *argv[]) {
  if (argc < 2)  {
    printf("usage: ./server [1-5]\n\
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

  if (cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket, atoi(argv[1]));

  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
