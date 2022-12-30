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
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"
#include "rtt_estimator.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MIN3(X, Y, Z) MIN(MIN(X, Y), Z)

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0) {
  }
  result = after(sock->window.last_ack_received, seq);
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t pkt_flags = get_flags(hdr);

  switch (pkt_flags) {
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }
      break;
    }
  }

  if (get_payload_len(pkt) == 0)
    return;
  
  socklen_t conn_len = sizeof(sock->conn);
  uint32_t seq = sock->window.last_ack_received;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint8_t flags = ACK_FLAG_MASK;
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint8_t *response_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                    ext_len, ext_data, payload, payload_len);

  sendto(sock->socket, response_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
  free(response_packet);

  seq = get_seq(hdr);

  if (seq == sock->window.next_seq_expected) {
    sock->window.next_seq_expected = seq + get_payload_len(pkt);
    payload_len = get_payload_len(pkt);
    payload = get_payload(pkt);

    // Make sure there is enough space in the buffer to store the payload.
    sock->received_buf =
        realloc(sock->received_buf, sock->received_len + payload_len);
    memcpy(sock->received_buf + sock->received_len, payload, payload_len);
    sock->received_len += payload_len;
  }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after RTT * 2.
      if (poll(&ack_fd, 1, rtt_in_ms(sock->rtt) * 2) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void multi_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  if (buf_len <= 0)
    return;
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;

  while (buf_len > 0) {
    int unack_pkt_cnt = 0;
    uint32_t written_cnt = 0;
    uint32_t ack_before_send = sock->window.last_ack_received;
    struct timeval start_time, end_time;
    int has_recorded_end_time = 0;

    gettimeofday(&start_time, NULL);

    // send a window of pkts
    while (
            written_cnt < (uint32_t)buf_len && 
            written_cnt < WINDOW_INITIAL_WINDOW_SIZE
          ) {
      uint16_t payload_len = MIN3(
                                buf_len - written_cnt,
                                (uint16_t)(WINDOW_INITIAL_WINDOW_SIZE - written_cnt),
                                (uint16_t)MSS);
      uint32_t seq = sock->window.last_ack_received + written_cnt;
      uint8_t *payload = data_offset + written_cnt;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);

      written_cnt += payload_len;
      unack_pkt_cnt++;
    }

    // check the ack pkts
    for (int i = 0; i < unack_pkt_cnt; i++) {
      check_for_data(sock, TIMEOUT);
      
      // when successfully receiving the ack pkt of the first sending pkt
      // end the timer
      if (i == 0 && has_been_acked(sock, ack_before_send)) {
        gettimeofday(&end_time, NULL);
        has_recorded_end_time = 1;
      }

      // if received the final ack pkt in advance (i != unack_pkt - 1)
      // some of the in-between ack pkts were lost
      // but it doesn't matter, just break
      if (has_been_acked(sock, ack_before_send + written_cnt))
        break;
    }

    if (has_recorded_end_time) {
      update_rtt(sock->rtt, &start_time, &end_time);
    }

    // move foward the window with successed_written_cnt bytes
    int successed_written_cnt = sock->window.last_ack_received - ack_before_send;
    buf_len -= successed_written_cnt;
    data_offset += successed_written_cnt;
  }
}

void send_SYN(cmu_socket_t *sock) {
  uint8_t flags = SYN_FLAG_MASK;
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = 0;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint8_t *SYN_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                    ext_len, ext_data, payload, payload_len);

  sendto(sock->socket, SYN_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
  
  cmu_tcp_header_t *header = (cmu_tcp_header_t *)SYN_packet;
  printf("send SYN packet with seq=%d\n", get_seq(header));

  free(SYN_packet);
}

void send_SYN_ACK(cmu_socket_t *sock) {
  uint8_t flags = SYN_FLAG_MASK | ACK_FLAG_MASK;
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = sock->window.next_seq_expected;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint8_t *SYN_ACK_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                    ext_len, ext_data, payload, payload_len);

  sendto(sock->socket, SYN_ACK_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
  
  cmu_tcp_header_t *header = (cmu_tcp_header_t *)SYN_ACK_packet;
  printf("send SYN_ACK packet with seq=%d ack=%d\n", get_seq(header), get_ack(header));

  struct pollfd ack_fd;
  ack_fd.fd = sock->socket;
  ack_fd.events = POLLIN;
  // Timeout after 3 seconds.
  while (poll(&ack_fd, 1, rtt_in_ms(sock->rtt) * 2) == 0) {
    sendto(sock->socket, SYN_ACK_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
    printf("TIMEOUT resend SYN_ACK packet\n");
  }

  free(SYN_ACK_packet);
}

void send_ACK(cmu_socket_t *sock) {
  uint8_t flags = ACK_FLAG_MASK;
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = sock->window.next_seq_expected;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint8_t *ACK_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                    ext_len, ext_data, payload, payload_len);

  sendto(sock->socket, ACK_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
  
  cmu_tcp_header_t *header = (cmu_tcp_header_t *)ACK_packet;
  printf("send ACK packet with seq=%d ack=%d\n", get_seq(header), get_ack(header));

  free(ACK_packet);
}

int handshake(cmu_socket_t *sock) {
  ssize_t len;
  socklen_t conn_len = sizeof(sock->conn);
  cmu_tcp_header_t hdr;

  switch(sock->type) {
    case TCP_INITIATOR:
      // send SYN packet
      send_SYN(sock);

      // receive SYN_ACK packet
      // check ack
      // set both last_ack_received and next_seq_expected
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), 0,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      if (!(
        len > 0 && 
        (get_flags(&hdr) & (SYN_FLAG_MASK | ACK_FLAG_MASK)) &&
        (get_ack(&hdr) == sock->window.last_ack_received + 1)
      ))
        return EXIT_FAILURE;
      printf("recv SYN_ACK packet with seq=%d ack=%d\n", get_seq(&hdr), get_ack(&hdr));
      sock->window.last_ack_received = get_ack(&hdr);
      sock->window.next_seq_expected = get_seq(&hdr) + 1;

      // send ACK
      send_ACK(sock);

      break;
    
    case TCP_LISTENER:
      // receive SYN packet
      // set next_seq_expected
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), 0,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      if (!(len > 0 && (get_flags(&hdr) & SYN_FLAG_MASK)))
        return EXIT_FAILURE;
      printf("recv SYN packet with seq=%d\n", get_seq(&hdr));
      sock->window.next_seq_expected = get_seq(&hdr) + 1;

      // send SYN_ACK packet
      send_SYN_ACK(sock);

      // receive ACK packet
      // check ack
      // set last_ack_received
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), 0,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      if (!(
        len > 0 && 
        (get_flags(&hdr) & ACK_FLAG_MASK) &&
        (get_ack(&hdr) == sock->window.last_ack_received + 1)
      ))
        return EXIT_FAILURE;
      printf("recv ACK packet with seq=%d ack=%d\n", get_seq(&hdr), get_ack(&hdr));
      sock->window.last_ack_received = get_ack(&hdr);

      break;
  }
  return EXIT_SUCCESS;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  int ret = handshake(sock);
  if (ret != EXIT_SUCCESS) {
    printf("ERROR handshake\n");
    cmu_close(sock);
    pthread_exit(NULL);
    return NULL;
  }
  printf("handshake finish successly\n");
  printf("-------------------------------------\n");

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      multi_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
