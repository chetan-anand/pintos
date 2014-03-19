/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/*
	Added Code starts.
*/
bool priority_semaphore (const struct list_elem *a_, const struct list_elem *b_,void *aux UNUSED);
void func(struct lock *lock);
/*
	Added Code ends.
*/
/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  ASSERT (!intr_context ());
  /*printf("<1>\n");*/
  old_level = intr_disable ();
  while (sema->value == 0) 
    {
      /*
      	Added code starts.
      */
      /*printf("<2>\n");*/
      list_insert_ordered (&sema->waiters, &(thread_current ()->elem),priority_semaphore,NULL);
      /*printf("<3>\n");*/
      /*
      	update the waiting semaphore.
      */
      thread_current()->waiting_sema=sema;
      /*
      	Added code ends.
      */
      /*printf("<4>\n");*/
      thread_block ();
      /*printf("<5>\n");*/
    }
    /*printf("<6>\n");*/
  sema->value--;
  /*printf("<7>\n");*/
  intr_set_level (old_level);
  /*printf("<8>\n");*/
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) 
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) 
    {
      sema->value--;
      success = true; 
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  sema->value++;
  old_level = intr_disable ();
  if (!list_empty (&sema->waiters)) 
  {
    struct thread *t = list_entry (list_pop_front (&sema->waiters),
                                struct thread, elem);
    t->waiting_sema=NULL;
    thread_unblock (t);
  }
  intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) 
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) 
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) 
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));
  /*func(lock);*/
  sema_down (&lock->semaphore);
  /*thread_current()->waiting_lock=NULL;*/
  list_push_back(&thread_current()->lock_list,&lock->elem);
  lock->holder = thread_current ();
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
    lock->holder = thread_current ();
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) 
{
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  lock->holder = NULL;
  thread_current()->priority=thread_current()->actual_priority;
  sema_up (&lock->semaphore);
  struct list_elem *e;
  for (e = list_begin (&(thread_current()->lock_list)); e != list_end (&(thread_current()->lock_list)); e = list_next (e))
  {
  	struct lock *l = list_entry (e, struct lock, elem);
  	if(l==lock)
  	{
  		list_remove(e);
  		break;
  	}
  }
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) 
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem 
  {
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */
  };

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) 
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));
  
  sema_init (&waiter.semaphore, 0);
  //list_push_back (&cond->waiters, &waiter.elem);
  //list_insert_ordered(&cond->waiters,&waiter.elem,priority_semaphore,NULL);
  struct list_elem *e;
  for (e = list_begin (&cond->waiters); e != list_end (&cond->waiters);
           e = list_next (e))
        {
          struct semaphore_elem *f = list_entry (e, struct semaphore_elem, elem);
          struct thread *t=list_entry(list_front(&(f->semaphore.waiters)),struct thread,elem);
          if(t->priority < thread_current()->priority)
          	break;
        }
  list_insert(e,&waiter.elem);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (!list_empty (&cond->waiters)) 
    sema_up (&list_entry (list_pop_front (&cond->waiters),
                          struct semaphore_elem, elem)->semaphore);
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}
bool priority_semaphore (const struct list_elem *a_, const struct list_elem *b_,void *aux UNUSED)
{
  /*const struct value *a = list_entry (a_, struct value, elem);
  const struct value *b = list_entry (b_, struct value, elem);*/
  /*
  Compares and returns boolean on whether the a has more time_remaining_for_sleep
  or b has.
  */
  const struct thread *a=list_entry(a_,struct thread,elem);
  const struct thread *b=list_entry(b_,struct thread,elem);
  return a->priority > b->priority;
}
void func(struct lock *lock)
{
	/*
  	Added code starts.
  	Algorithm for priority donation.
  	1.First we try to see if the lock can be downed,if yes we proceed.
  	2.Else,we see who is the holder of the lock(by inquiring lock->holder)
  	and then donate our priority to that thread if it's priority is lower
  	than ours(current_thread).or else,we go to wait.
  	Don't forget to update the waiting_lock of the current thread.
  	3.To implement nested donation we have to find on what lock a thread is
  	waiting we find that using the waiting_lock member of the thread.
  */
  if(!sema_try_down(&lock->semaphore))
  {
  	/*
  	We can't proceed so point 2 in operation.
  	*/
  	//printf("Donation going to happen between Thread:%s and Thread:%s\n",lock->holder->name,thread_current()->name);
  	if(lock->holder->priority < thread_current()->priority)
  	{
  		/*
  			Current thread donates priority to the holder of the lock.
  			and we have to find where that thread is which we can easily
  			get by checking the status of the thread.
  			1.THREAD_READY->we need to find it in the list,remove it and add it once again.
  			2.THREAD_BLOCKED->we need to access the semaphore member.find it in the
  			list ,remove it and add it.
  		*/
  		lock->holder->priority= thread_current()->priority;
  		if(lock->holder->status==THREAD_READY)
  		{
  			struct list_elem *e;
      			for (e = list_begin (&ready_list); e != list_end (&ready_list);e = list_next (e))
        		{
          			if(list_entry (e, struct thread, elem)==lock->holder)
          			{
          				list_remove(e);
          				list_insert_ordered(&ready_list,e,priority_semaphore,NULL);
          				break;
          			}	
        		}
  		}
  		else    //if the thread is blocked.
  		{
  		/*
  			There are two possibilities here:
  			1.The thread is blocked because it waiting on a lock held by another thread.
  			2.The thread is blocked because it waiting on a semaphore held by another thread.
  		*/
  			struct list_elem *e;
  			bool waiting_on_a_lock;
  			if(lock->holder->waiting_lock!=NULL)
  				waiting_on_a_lock=true;
  			else
  				waiting_on_a_lock=false;
  			if(!waiting_on_a_lock)
  			{
  				/*The lock holder is waiting on a semaphore.*/
  				for(e=list_begin(&(lock->holder->waiting_sema->waiters));e!=list_end(&(lock->holder->waiting_sema->waiters));e=list_next(e))
  				{
  					if(list_entry(e,struct thread,elem)==lock->holder)
  					{
	  					list_remove(e);
		  				list_insert_ordered(&(lock->holder->waiting_sema->waiters),e,priority_semaphore,NULL);
		  				return;
  					}
  				}
  			}
      			for (e = list_begin (&(lock->holder->waiting_lock->semaphore.waiters)); e != list_end (&(lock->holder->waiting_lock->semaphore.waiters));e = list_next (e))
        		{
          			if(list_entry (e, struct thread, elem)==lock->holder)
          			{
          				list_remove(e);
          				list_insert_ordered(&(lock->holder->waiting_lock->semaphore.waiters),e,priority_semaphore,NULL);
          				break;
          			}	
        		}
        		
  		}
  		struct thread *cur=lock->holder;
  		bool waiting_on_a_lock;
  		while(cur->waiting_lock!=NULL)
  		{
  			if(cur->waiting_lock->holder->priority < cur->priority)
  			{
  				cur->waiting_lock->holder->priority=cur->priority;
  				if(cur->waiting_lock->holder->status==THREAD_READY)
  				{
  					struct list_elem *e;
      					for (e = list_begin (&ready_list); e != list_end (&ready_list);e = list_next (e))
        				{
          					if(list_entry (e, struct thread, elem)==cur->waiting_lock->holder)
          					{
          						list_remove(e);
          						list_insert_ordered(&ready_list,e,priority_semaphore,NULL);
          						break;
          					}	
        				}	
  				}
  				else   //that holder is blocked.(either on a semaphore or a lock.)
  				{
  					struct list_elem *e;
  					if(cur->waiting_lock->holder->waiting_lock!=NULL)
  						waiting_on_a_lock=true;
  					else
  						waiting_on_a_lock=false;
  				if(!waiting_on_a_lock)
  				{
  					/*The lock holder is waiting on a semaphore.*/
  					for(e=list_begin(&(cur->waiting_lock->holder->waiting_sema->waiters));e!=list_end(&(cur->waiting_lock->holder->waiting_sema->waiters));e=list_next(e))
  					{
  						if(list_entry(e,struct thread,elem)==lock->holder)
  						{
	  						list_remove(e);
		  					list_insert_ordered(&(cur->waiting_lock->holder->waiting_sema->waiters),e,priority_semaphore,NULL);
		  					return;
  						}
  					}
  				}
      					for (e = list_begin (&(cur->waiting_lock->holder->waiting_lock->semaphore.waiters)); e != list_end (&(cur->waiting_lock->holder->waiting_lock->semaphore.waiters));e = list_next (e))
		        		{
		          			if(list_entry (e, struct thread, elem)==cur->waiting_lock->holder)
		          			{
		          				list_remove(e);
		          				list_insert_ordered(&(cur->waiting_lock->holder->waiting_lock->semaphore.waiters),e,priority_semaphore,NULL);
		          				break;
		          			}	
		        		}
  				}
  			}
  			cur=cur->waiting_lock->holder;
  		}
  		cur->priority=thread_current()->priority;
  	}
  	thread_current()->waiting_lock=lock;
  }
  else
  {
  	lock->semaphore.value++;
  }
}
