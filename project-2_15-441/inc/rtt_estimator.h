#ifndef PROJECT_2_15_441_INC_RTT_ESTIMATOR_H_
#define PROJECT_2_15_441_INC_RTT_ESTIMATOR_H_

#include <sys/time.h>

#define RTT_INITIAL_IN_MS 40

struct rtt_estimator
{
  double SRTT;
  double DevRTT;
};

struct rtt_estimator *malloc_rtt_estimator();
void update_rtt(struct rtt_estimator *r, struct timeval *start, struct timeval *end);
int rto_in_ms(struct rtt_estimator *r);


#endif  // PROJECT_2_15_441_INC_RTT_ESTIMATOR_H_