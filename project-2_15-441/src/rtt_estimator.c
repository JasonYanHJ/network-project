#include "rtt_estimator.h"

#include <stdlib.h>

struct rtt_estimator *malloc_rtt_estimator() {
  struct rtt_estimator *rtt = malloc(sizeof(struct rtt_estimator));
  for (int i = 0; i < 16; i++)
    rtt->records_in_us[i] = RTT_INITIAL_IN_MS * 1000;
  rtt->rtt_in_us = RTT_INITIAL_IN_MS * 1000;
  rtt->record_cursor = 0;
  return rtt;
}

void update_rtt(struct rtt_estimator *r, struct timeval *start, struct timeval *end) {
  int interval = (end->tv_sec * 1000000 + end->tv_usec) - (start->tv_sec * 1000000 + start->tv_usec);
  r->rtt_in_us = r->rtt_in_us - r->records_in_us[r->record_cursor] / 16 + interval / 16;
  r->records_in_us[r->record_cursor++] = interval;
  r->record_cursor %= 16;
}

int rtt_in_ms(struct rtt_estimator *r) {
  return r->rtt_in_us / 1000;
}