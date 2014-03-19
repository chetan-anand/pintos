#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/****************************
	Added Code starts.
	struct sleep_list defined in thread.c.
****************************/
//extern struct sleep_list;
/****************************
	Added Code ends.
****************************/

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);
static void real_time_delay (int64_t num, int32_t denom);
/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void
timer_init (void) 
{
  /* 8254 input frequency divided by TIMER_FREQ, rounded to
     nearest. */
  uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

  outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
  outb (0x40, count & 0xff);
  outb (0x40, count >> 8);

  intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) 
{
  unsigned high_bit, test_bit;

  ASSERT (intr_get_level () == INTR_ON);
  printf ("Calibrating timer...  ");

  /* Approximate loops_per_tick as the largest power-of-two
     still less than one timer tick. */
  loops_per_tick = 1u << 10;
  while (!too_many_loops (loops_per_tick << 1)) 
    {
      loops_per_tick <<= 1;
      ASSERT (loops_per_tick != 0);
    }

  /* Refine the next 8 bits of loops_per_tick. */
  high_bit = loops_per_tick;
  for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
    if (!too_many_loops (high_bit | test_bit))
      loops_per_tick |= test_bit;

  printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void) 
{
  enum intr_level old_level = intr_disable ();
  int64_t t = ticks;
  intr_set_level (old_level);
  barrier ();
  return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) 
{
  return timer_ticks () - then;
}

/* Sleeps for approximately TICKS timer ticks.  Interrupts must
   be turned on. */
void
timer_sleep (int64_t ticks) 
{
  //int64_t start = timer_ticks ();

  ASSERT (intr_get_level () == INTR_ON);
  //printf("Thread:%d is going to sleep for %"PRId64" ticks.\n",thread_current()->tid,ticks);
  //printf("Thread:%d is the head of the sleep_list.\n",list_entry(list_begin(&sleep_list),struct thread,elem)->tid);
 /* while (timer_elapsed (start) < ticks) 
    thread_yield ();*/
  /****************************
	Added Code starts.
	What follows is all the critical section code and it is solved by disabling interrupts.
	we do not want the sleep list to be changed arbitrarily i.e when a thread is changing it
	the thread should not be preempted under any circumstances.
	
	Did not use semaphore:
	because internally semaphores themselves disable interrupts for the while(adding a node to the sema->waiters list)
	which is equivalent to what we have done(adding a node to sleep list). 
****************************/
	struct thread *current=thread_current();
	/*
	If ticks are negative then immediately yield.
	*/
	if(ticks<0)
		thread_yield();
	else
	{
		enum intr_level old_level;
		old_level = intr_disable ();
		//list_insert_ordered(&sleep_list,&current->elem,time_less,NULL);
		struct list_elem *e;
		
  /*for (e = list_begin (&sleep_list); e != list_end (&sleep_list);e = list_next (e))
  {
  	printf("Time remaining:%"PRId64"->",list_entry(e,struct thread,elem)->time_remaining_for_sleep);
  }*/
  	//printf("\n");
		for (e = list_begin (&sleep_list); e != list_end (&sleep_list);e = list_next (e))
        	{
          		struct thread *f = list_entry (e, struct thread, elem);
          		//printf("%"PRId64":",f->time_remaining_for_sleep);
         		if((f->time_remaining_for_sleep)>ticks)
         			break;
       		}
       		list_insert(e,&current->elem);
		//current->status=THREAD_SLEEP;
		current->time_remaining_for_sleep=ticks;
		//thread_set_time_remaining_for_sleep(ticks);
		thread_block();
		intr_set_level (old_level);
	}
	/****************************
	Added Code ends.
****************************/
}

/* Sleeps for approximately MS milliseconds.  Interrupts must be
   turned on. */
void
timer_msleep (int64_t ms) 
{
  real_time_sleep (ms, 1000);
}

/* Sleeps for approximately US microseconds.  Interrupts must be
   turned on. */
void
timer_usleep (int64_t us) 
{
  real_time_sleep (us, 1000 * 1000);
}

/* Sleeps for approximately NS nanoseconds.  Interrupts must be
   turned on. */
void
timer_nsleep (int64_t ns) 
{
  real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Busy-waits for approximately MS milliseconds.  Interrupts need
   not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_msleep()
   instead if interrupts are enabled. */
void
timer_mdelay (int64_t ms) 
{
  real_time_delay (ms, 1000);
}

/* Sleeps for approximately US microseconds.  Interrupts need not
   be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_usleep()
   instead if interrupts are enabled. */
void
timer_udelay (int64_t us) 
{
  real_time_delay (us, 1000 * 1000);
}

/* Sleeps execution for approximately NS nanoseconds.  Interrupts
   need not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_nsleep()
   instead if interrupts are enabled.*/
void
timer_ndelay (int64_t ns) 
{
  real_time_delay (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) 
{
  printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
static void
timer_interrupt (struct intr_frame *args UNUSED)
{
  /*
  Since it is an external interrupt therefore it should not be interrupted
  and should not be put to sleep.
  */
  enum intr_level old_level;
  old_level = intr_disable ();
  ticks++;
  thread_tick ();
  struct list_elem *e;
  /****************************
	Added Code starts.
	With each tick we first decrement the node
	time_remaining_for_sleep and then see the list's minimum element if 
	that has execeeded the time_remaining_for_sleep
	we then remove it from sleep_list and insert it into the ready_list.
	and check for the subsequent nodes.
	if the minimum element has not execeeded the time_remaining_for_sleep
	then it is easy to see that no other node has completed.
****************************/
   //struct list_elem *e;
   //printf("Thread:%d is the head of the sleep_list.\n",list_entry(list_begin(&sleep_list),struct thread,elem)->tid);
   for (e = list_begin (&sleep_list); e != list_end (&sleep_list);e = list_next (e))
   {
   	//printf("Size:%d\n",list_size(&sleep_list));
   	//printf("inside list\n");
	struct thread *f = list_entry (e, struct thread, elem);
	if(f->time_remaining_for_sleep>0)
		f->time_remaining_for_sleep--;
	//printf("Thread:%d\n",f->tid);
   }
   struct thread *min;
   if(!list_empty(&sleep_list))
   {
   	e=list_front(&sleep_list);
   	/*Returns the minimum element in the list.*/
   	min=list_entry(e,struct thread,elem);
   	/*
   	If it is time for the thread to wake up.
   	*/
   	if(min->time_remaining_for_sleep<=0)
   	{
   		/*First add this thread to the ready_list and remove it from sleep_list.*/
   		/*For priority scheduling later in the project.
   		list_insert_ordered(&ready_list,&min->elem,priority_more,NULL);*/
   		list_remove(e);
   		//printf("Thread:%d waking up.pehle\n",min->tid);
   		thread_unblock(min);
   		for (e = list_begin (&sleep_list); e != list_end (&sleep_list);)
   		{
			min = list_entry (e, struct thread, elem);
			if(min->time_remaining_for_sleep<=0)
			{
				e=list_remove(e);
				//printf("Thread:%d waking up.\n",min->tid);
				thread_unblock(min);
			}
			else
				break;
   		}
   	}
   }
   intr_set_level (old_level);
  /****************************
	Added Code ends.
****************************/
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) 
{
  /* Wait for a timer tick. */
  int64_t start = ticks;
  while (ticks == start)
    barrier ();

  /* Run LOOPS loops. */
  start = ticks;
  busy_wait (loops);

  /* If the tick count changed, we iterated too long. */
  barrier ();
  return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) 
{
  while (loops-- > 0)
    barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) 
{
  /* Convert NUM/DENOM seconds into timer ticks, rounding down.
          
        (NUM / DENOM) s          
     ---------------------- = NUM * TIMER_FREQ / DENOM ticks. 
     1 s / TIMER_FREQ ticks
  */
  int64_t ticks = num * TIMER_FREQ / denom;

  ASSERT (intr_get_level () == INTR_ON);
  if (ticks > 0)
    {
      /* We're waiting for at least one full timer tick.  Use
         timer_sleep() because it will yield the CPU to other
         processes. */                
      timer_sleep (ticks); 
    }
  else 
    {
      /* Otherwise, use a busy-wait loop for more accurate
         sub-tick timing. */
      real_time_delay (num, denom); 
    }
}

/* Busy-wait for approximately NUM/DENOM seconds. */
static void
real_time_delay (int64_t num, int32_t denom)
{
  /* Scale the numerator and denominator down by 1000 to avoid
     the possibility of overflow. */
  ASSERT (denom % 1000 == 0);
  busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000)); 
}
