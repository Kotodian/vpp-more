/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_vpp_darwin_compat_h
#define included_vpp_darwin_compat_h
#if defined(__APPLE__) && !defined(__ASSEMBLER__)
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#define PTHREAD_MUTEX_ROBUST 1
static inline int
pthread_mutexattr_setrobust (pthread_mutexattr_t *attr, int robust)
{
  (void) attr;
  (void) robust;
  return ENOTSUP;
}
/* Darwin has no robust mutex recovery. Never report successful recovery. */
static inline int
pthread_mutex_consistent (pthread_mutex_t *mutex)
{
  (void) mutex;
  return ENOTSUP;
}
/* Explicitly unsupported Linux CPU pinning/scheduling APIs. */
#define CPU_SETSIZE 1024
typedef struct { unsigned long bits[CPU_SETSIZE / (8 * sizeof (unsigned long))]; } cpu_set_t;
#define CPU_ZERO(s) memset ((s), 0, sizeof (*(s)))
#define CPU_SET(c, s) ((s)->bits[(c) / (8 * sizeof (unsigned long))] |= 1UL << ((c) % (8 * sizeof (unsigned long))))
static inline int sched_getcpu (void) { return -1; }
static inline int
pthread_setaffinity_np (pthread_t t, size_t size, const cpu_set_t *set)
{
  (void) t; (void) size; (void) set;
  return ENOTSUP;
}
static inline int sched_getparam (pid_t p, struct sched_param *s)
{
  (void) p; (void) s; errno = ENOTSUP; return -1;
}
static inline int sched_getscheduler (pid_t p)
{
  (void) p; errno = ENOTSUP; return -1;
}
static inline int sched_setscheduler (pid_t p, int policy, const struct sched_param *s)
{
  (void) p; (void) policy; (void) s; errno = ENOTSUP; return -1;
}
static inline uint64_t vpp_darwin_thread_id (void)
{
  uint64_t id = 0;
  pthread_threadid_np (NULL, &id);
  return id;
}
#endif
#endif
