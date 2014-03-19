#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

/*
	Added Code Starts.
*/
int find_free_frame();
int evict_page();
/*
	Added code ends.
*/
/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));
  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();
  /*
  	Added Code Starts.
  	The fault address is checked whether it is a NULL Pointer or
  	a invalid user virtual address.
  */
  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /*printf("Fault Address:%p f->esp:%p\n",fault_addr,f->esp);*/
  if(fault_addr==NULL)
  {
  	f->eax=-1;
  	thread_current()->parent->return_value=f->eax;
  	printf("%s: exit(%d)\n",thread_name(),f->eax);
	thread_exit();
  }
  if(!is_user_vaddr(fault_addr))
  {  
  	f->eax=-1;
  	thread_current()->parent->return_value=f->eax;
  	printf("%s: exit(%d)\n",thread_name(),f->eax);
	thread_exit();
  }
  /*
  	Now a page fault can also mean that a page be brought into main memory.
  	Algorithm:
  	1.Consult the supplementary_page_table and find out which type of page is to be loaded into the main memory.
  */
  bool handled = false;
  struct list_elem *e;
  uint8_t *kpage;
  int free_frame;
  int j;
  /*printf("Fault Address:%p\n",fault_addr);*/
  /*printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");*/
  struct disk *d;
  for (e = list_begin (&(thread_current()->supplementary_page_table)); e != list_end (&(thread_current()->supplementary_page_table)); e = list_next (e))
  {
  	struct supplementary_page_table_entry *s_p_t_e = list_entry (e, struct supplementary_page_table_entry, elem);
  	if(s_p_t_e->va == (int*)((int)fault_addr & 0xfffff000))
  	{
  		switch(s_p_t_e->type)
  		{
  			case 0:
  				/*printf("Error:This case should not occur.Page in memory still page faulted.(Error in page table might be.)\n");*/ 
  				break;
  			case 1:      
  				kpage = palloc_get_page (PAL_USER);
			       	if (kpage == NULL)
			       	{
			       		//printf("<1>\n");
					/* Swap eviction algorithm.*/
					free_frame = find_free_frame();
					//printf("Free Frame:%d\n",free_frame);
					/*
						A free frame is found.
						Algorithm:
						1.First from the type determine what type of page it is.
						2.Accordingly read from file,zero the page frame,or read from the swap area.
						3.Update the supplementary page table.
						4.Install the page(call install_page() with appropriate arguments.)
					*/
					if(free_frame != -1)
					{
						insert_in_free_frame(free_frame,s_p_t_e);
					}
					else
					{
						/*
							Here the free_frame refers to the frame which will be freed.
						*/
						free_frame = evict_page();
						insert_in_free_frame(free_frame,s_p_t_e);
					}
			       	}
			      	/*printf("upage : %p page_no:%d\n",upage,pg_no(upage));*/
			      	else
			      	{
			      		//printf("<2>\n");
			      		file_seek (s_p_t_e->file, s_p_t_e->offset);
			      		int frame_index = ((vtop(kpage) & 0xfffff000)>>12);
			      		/*printf("Frame Index:%d\n",frame_index);*/
			      		/* Load this page. */
			      		if (file_read (s_p_t_e->file, kpage, s_p_t_e->page_read_bytes) != (int) s_p_t_e->page_read_bytes)
					{
				  		palloc_free_page (kpage);
				  		return;
					}
					//printf("<1>\n");
			      		memset (kpage + s_p_t_e->page_read_bytes, 0, s_p_t_e->page_zero_bytes);
			      		//printf("<2>\n");

				      	/* Add the page to the process's address space.*/ 
				      	if (!install_page (s_p_t_e->va, kpage, s_p_t_e->writable)) 
					{
					  	palloc_free_page (kpage);
					  	return;
					}
					frames[frame_index].pid = thread_current()->tid;
			      		/*if(frame_index == 654)
			      			printf("PID in frame_index:%d is %d.\n",frame_index,frames[frame_index].pid);*/
			     		/*frames[frame_index].pte = lookup_page(thread_current()->pagedir,s_p_t_e->va,false);*/
			     		frames[frame_index].pte = s_p_t_e->va;
			      		frames[frame_index].free_bit = false;
			      		frames[frame_index].kpage = kpage;
				}
				s_p_t_e->type = 0;
				handled = true;
				break;
			case 2:
				kpage = palloc_get_page (PAL_USER);
				if(kpage == NULL)
				{
					/* Swap eviction algorithm.*/
					//printf("<12>\n");
					free_frame = find_free_frame();
					//printf("Free Frame_2:%d",free_frame);
					/*
						A free frame is found.
						Algorithm:
						1.First from the type determine what type of page it is.
						2.Accordingly read from file,zero the page frame,or read from the swap area.
						3.Update the supplementary page table.
						4.Install the page(call install_page() with appropriate arguments.)
					*/
					if(free_frame != -1)
					{
						insert_in_free_frame(free_frame,s_p_t_e);
					}
					else
					{
						/*
							Here the free_frame refers to the frame which will be freed.
						*/
						//printf("No Free Frame found...Will evict a victim.\n");
						free_frame = evict_page();
						//printf("Frame to be evicted:%d\n",free_frame);
						insert_in_free_frame(free_frame,s_p_t_e);
					}
				}
				else
				{
					//printf("<22>\n");
					int frame_index = ((vtop(kpage) & 0xfffff000)>>12);
			      		/*printf("Frame Index:%d\n",frame_index);*/
			      		//printf("<3>\n");
			      		//printf("thread_tid:%d kpage:%p and page_zero_bytes:%d\n",thread_current()->tid,kpage,s_p_t_e->page_zero_bytes);
			      		memset(kpage,0,s_p_t_e->page_zero_bytes);
			      		//printf("<4>\n");
			      		/* Add the page to the process's address space.*/ 
				      	if (!install_page (s_p_t_e->va, kpage, s_p_t_e->writable)) 
					{
					  	palloc_free_page (kpage);
					  	return;
					}
					frames[frame_index].pid = thread_current()->tid;
			      		/*if(frame_index == 654)
			      			printf("PID in frame_index:%d is %d.\n",frame_index,frames[frame_index].pid);*/
			     		/*frames[frame_index].pte = lookup_page(thread_current()->pagedir,s_p_t_e->va,false);*/
			     		frames[frame_index].pte = s_p_t_e->va;
			      		frames[frame_index].free_bit = false;
			      		frames[frame_index].kpage = kpage;
				}
				s_p_t_e->type = 0;
				handled = true;
				break;
			case 3:
			/* Swap eviction algorithm.*/
					//printf("Case 3\n");
					free_frame = find_free_frame();
					/*
						A free frame is found.
						Algorithm:
						1.First from the type determine what type of page it is.
						2.Accordingly read from file,zero the page frame,or read from the swap area.
						3.Update the supplementary page table.
						4.Install the page(call install_page() with appropriate arguments.)
					*/
					if(free_frame != -1)
					{
						insert_in_free_frame(free_frame,s_p_t_e);
					}
					else
					{
						/*
							Here the free_frame refers to the frame which will be freed.
						*/
						free_frame = evict_page();
						insert_in_free_frame(free_frame,s_p_t_e);
					}
					s_p_t_e->type = 0;
					handled = true;
					break;
			default:
				printf("This case should not be reached(Error in Supplementary Page Table.).\n");
				break;
  		}
  		if(handled)
  			break;
  	}
  }
  /*
  	Added Code Ends.
  */
  /*
  	Using the value of the handled we can find whether the page_fault is handled or not.
  	If till here,it is not handled,that means that we have to implement stack growth.
  */
  if(!handled)
  {
  	if(fault_addr >= ((f->esp)-32))
  	{
  		uint8_t *kpage;
  		bool success = false;
  		kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  		if (kpage != NULL) 
    		{
      			success = install_page ((void*)((int)fault_addr & 0xfffff000), kpage, true);
      			if(!success)
      			{
      				palloc_free_page (kpage);
      			}
      			else
      			{
      				/*
      					Update the frame table.
      				*/
      				int frame_index = ((vtop(kpage) & 0xfffff000)>>12);
		      		/*printf("Frame Index:%d\n",frame_index);*/
		      		frames[frame_index].pid = thread_current()->tid;
		     		/*frames[frame_index].pte = lookup_page(thread_current()->pagedir,(const void*)((int)fault_addr & 0xfffff000),false);*/
		     		frames[frame_index].pte = (uint32_t*)((int)fault_addr & 0xfffff000);
		      		frames[frame_index].free_bit = false;
		      		frames[frame_index].kpage = kpage;
		      		/*
		      			Update the supplementary page table.
		      		*/
		      		struct supplementary_page_table_entry *s_p_e = malloc(sizeof(struct supplementary_page_table_entry));
			 	s_p_e->va = (uint32_t*)((int)fault_addr & 0xfffff000);
			 	s_p_e->type = 0;
			 	s_p_e->file = NULL;
			 	s_p_e->offset = 0;
			 	s_p_e->page_read_bytes = 0;
			 	s_p_e->page_zero_bytes = PGSIZE;
			 	s_p_e->writable = true;
			 	list_push_back(&thread_current()->supplementary_page_table,&s_p_e->elem);
			 	
			 	handled = true;
      			}
  		}
  		else
  		{
  			free_frame = find_free_frame();
  			if(free_frame != -1)
  			{
  				install_page ((void*)((int)fault_addr & 0xfffff000), frames[free_frame].kpage, true);
  				/*
		      			Update the supplementary page table.
		      		*/
		      		struct supplementary_page_table_entry *s_p_e = malloc(sizeof(struct supplementary_page_table_entry));
			 	s_p_e->va = (uint32_t*)((int)fault_addr & 0xfffff000);
			 	s_p_e->type = 0;
			 	s_p_e->file = NULL;
			 	s_p_e->offset = 0;
			 	s_p_e->page_read_bytes = 0;
			 	s_p_e->page_zero_bytes = PGSIZE;
			 	s_p_e->writable = true;
			 	list_push_back(&thread_current()->supplementary_page_table,&s_p_e->elem);
			 	
			 	handled = true;
			 	frames[free_frame].free_bit = false;
			 	frames[free_frame].pte = (uint32_t*)((int)fault_addr & 0xfffff000);
			 	frames[free_frame].pid = thread_current()->tid;
  			}
  			else
  			{
  				free_frame = evict_page();
  				install_page ((void*)((int)fault_addr & 0xfffff000), frames[free_frame].kpage, true);
  				/*
		      			Update the supplementary page table.
		      		*/
		      		struct supplementary_page_table_entry *s_p_e = malloc(sizeof(struct supplementary_page_table_entry));
			 	s_p_e->va = (uint32_t*)((int)fault_addr & 0xfffff000);
			 	s_p_e->type = 0;
			 	s_p_e->file = NULL;
			 	s_p_e->offset = 0;
			 	s_p_e->page_read_bytes = 0;
			 	s_p_e->page_zero_bytes = PGSIZE;
			 	s_p_e->writable = true;
			 	list_push_back(&thread_current()->supplementary_page_table,&s_p_e->elem);
			 	
			 	handled = true;
			 	frames[free_frame].free_bit = false;
			 	frames[free_frame].pte = (uint32_t*)((int)fault_addr & 0xfffff000);
			 	frames[free_frame].pid = thread_current()->tid;
  			}
  		}
  	}
  	else
  	{
  		/*printf("Cause:Present Bit:%d\n",not_present);*/
  		//printf("Stack Page NULL \n");
  		/*printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");*/
  		f->eax=-1;
	  	thread_current()->parent->return_value=f->eax;
	  	printf("%s: exit(%d)\n",thread_name(),f->eax);
		thread_exit();
  	}
  }
  /* Count page faults. */
  page_fault_cnt++;

  
  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
  /*printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");*/
  /*kill (f);*/
}
/*
	Finds a free frame in the memory.
	Return Value:
	returns the frame number in case any frame is free,
	else returns -1.
*/
int find_free_frame()
{
	int i;
	for(i=655;i<1024;i++)
	{
		if(frames[i].free_bit)
			return i;
	}
	return -1;
}
int evict_page()
{
	/*
		Implementation of second chance algorithm.
	*/
	int i=clock_hand;
	//printf("clock_hand:%d\n",clock_hand);
	while(pagedir_is_accessed((thread_from_pid(frames[i].pid))->pagedir,frames[i].pte))
	{
		//printf("frames[%d].kpage:%p\n",i,frames[i].kpage);
		pagedir_set_accessed((thread_from_pid(frames[i].pid))->pagedir,frames[i].pte,0);
		if(i==1023)
		{
			i=655;
		}
		else
			i=(i+1)%1024;
	}
	clock_hand = i;
	/*
		The following will be done to the page which is evicted
		1.copied to swap.
		2.supp_page_entry changed to swap and swap_slot_no updated(see struct supplementary_page_table_entry)
		3.call pagedir_clear_page(to invalidate it's page table entry.)
		4.frame[i] is freed.
	*/
	/*
		for 1 find a free slot(j) and issue disk_write.
	*/
	int j,k;
	for(j=0;j<1024;j++)
	{
		if(swap_slot_free[j])
			break;
	}
	//printf("%dth swap slot is free.\n",j);
	for(k=0;k<8;k++)
	{
		disk_write(disk_get(1,1),k+j*8,frames[i].kpage+k*512);
	}
	swap_slot_free[j]=false;
	/*
	Finding the thread to which this thread belongs.
	*/
	struct thread *evict = thread_from_pid(frames[i].pid);
	struct supplementary_page_table_entry *s_p_e;
	struct list_elem *e;
	for (e = list_begin (&(evict->supplementary_page_table)); e != list_end (&(evict->supplementary_page_table)); e = list_next (e))
	{
		s_p_e = list_entry (e, struct supplementary_page_table_entry, elem);
		if(s_p_e->va == frames[i].pte)
		{
			s_p_e->type = 3;
			s_p_e->swap_slot_no = j;
			break;
		}
	}
	pagedir_clear_page(evict->pagedir,frames[i].pte);
	frames[i].free_bit = true;
	frames[i].pte = NULL;
	return i;
}
void insert_in_free_frame(int free_frame,struct supplementary_page_table_entry *s_p_t_e)
{
	int j;
	switch(s_p_t_e->type)
	{
		case 1:
			if(file_read(s_p_t_e->file,frames[free_frame].kpage,s_p_t_e->page_read_bytes) != (int) s_p_t_e->page_read_bytes)
			{
				palloc_free_page (frames[free_frame].kpage);
				return;
			}
			memset(frames[free_frame].kpage+s_p_t_e->page_read_bytes,0,s_p_t_e->page_zero_bytes);
			if(!install_page(s_p_t_e->va,frames[free_frame].kpage,s_p_t_e->writable))
			{
				palloc_free_page (frames[free_frame].kpage);
				return;
			}
			break;
		case 2:
			while(frames[free_frame].kpage == NULL)
				frames[free_frame].kpage = palloc_get_page(PAL_USER);
			//printf("Free Frame kpage:%d~%p\n",free_frame,frames[free_frame].kpage);
			memset(frames[free_frame].kpage,0,s_p_t_e->page_zero_bytes);
			if(!install_page(s_p_t_e->va,frames[free_frame].kpage,s_p_t_e->writable))
			{
				palloc_free_page(frames[free_frame].kpage);
				return;
			}
			break;
		case 3:
			for(j=0;j<8;j++)
			{
				disk_read(disk_get(1,1),j+s_p_t_e->swap_slot_no*8,frames[free_frame].kpage+512*j);
			}
			if(!install_page(s_p_t_e->va,frames[free_frame].kpage,s_p_t_e->writable))
			{
				palloc_free_page (frames[free_frame].kpage);
				return;
			}
			swap_slot_free[s_p_t_e->swap_slot_no] = true;
			break;
		default:
			printf("oops!!!!!Default....\n");
			break;
	}
	frames[free_frame].pid = thread_current()->tid;
	frames[free_frame].pte = s_p_t_e->va;
	frames[free_frame].free_bit = false;
}
