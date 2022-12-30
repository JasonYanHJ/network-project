#include "rtt_estimator.h"

#include <stdlib.h>
#include <stdio.h>

#define abs(X) ((X) >= 0 ? (X) : -(X))

#define A 0.125
#define B 0.25
#define U 1
#define V 4

struct rtt_estimator *malloc_rtt_estimator() {
  struct rtt_estimator *rtt = malloc(sizeof(struct rtt_estimator));
  rtt->SRTT = rtt->DevRTT = RTT_INITIAL_IN_MS;
  return rtt;
}

void update_rtt(struct rtt_estimator *r, struct timeval *start, struct timeval *end) {
  double RTT = ((end->tv_sec * 1000000 + end->tv_usec) - (start->tv_sec * 1000000 + start->tv_usec)) / 1000;
  r->SRTT = r->SRTT + A * (RTT -  r->SRTT);
  r->DevRTT = (1 - B) * r->DevRTT + B * abs(RTT - r->SRTT);
}

int rto_in_ms(struct rtt_estimator *r) {
  // printf("RTO: %d\n", (int)(U * r->SRTT + V * r->DevRTT));
  return (int)(U * r->SRTT + V * r->DevRTT);
}