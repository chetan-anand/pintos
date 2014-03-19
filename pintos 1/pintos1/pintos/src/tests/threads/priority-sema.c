/* Tests that the highest-priority thread waiting on a semaphore
   is the first to wake up. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include<debug.h>

static thread_func priority_sema_thread;
static struct semaphore sema;
  int cnt =0;

void
test_priority_sema (void) 
{
  int i;
  
  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  sema_init (&sema, 0);
  thread_set_priority (PRI_MIN);
  for (i = 0; i < 10; i++) 
    {
      int priority = PRI_DEFAULT - (i + 3) % 10 - 1;
      char name[16];
      snprintf (name, sizeof name, "priority %d", priority);
      cnt++;
      thread_create (name, priority, priority_sema_thread, NULL);
    }

  for (i = 0; i < 10; i++) 
    {
      //printf("i=%d cnt= %d\n",i,cnt);
      sema_up (&sema);
      msg ("Back in main thread."); 
    }
}

static void
priority_sema_thread (void *aux UNUSED) 
{
  sema_down (&sema);
  //printf("cnt = %d",cnt);
  msg ("Thread %s woke up.", thread_name ());
}
