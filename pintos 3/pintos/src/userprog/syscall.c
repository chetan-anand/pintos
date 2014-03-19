#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"


static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /*
  	Added Code Starts.
  	Code for verifying user memory access.
  	First finding what is the syscall that needs to be implemented.
  	f->esp will be pointing to the type of system call.
  */
  /*printf("ESP:%d",*(int*)(f->esp));*/
  /*
	Check if the esp itself is inside the user virtual memory space.
  */
  if(f->esp==NULL || lookup_page(thread_current()->pagedir,f->esp,false)== NULL)
  {
	f->eax=-1;
	printf("%s: exit(%d)\n",thread_name(),f->eax);
	thread_exit();
	return;
  }
  if(!is_user_vaddr(((f->esp)+4)))
  {
	f->eax=-1;
	printf("%s: exit(%d)\n",thread_name(),f->eax);
	thread_exit();
	return;
  }
  void *vir_esp;
  int pid_exec;
  struct list_elem *e;
  switch(*(int *)(f->esp))
  {
  	case SYS_HALT:
  			power_off();
  			break;
  	case SYS_EXIT:
  			vir_esp=((f->esp)+4);
  			int status=*(int*)vir_esp;
  			f->eax=*(int*)vir_esp;
			/*
				This child is going to die ,so now either the parent is waiting on it,
				but since parent can wait on the child afterwards we store the exit
				status in dead_child_list of the parent.
				The implementation is wrong in the sense that it does not handle the 
				case when the parent exits without waiting on the child,before child exits.
			*/
  			if(thread_current()->waited_on)
				thread_current()->parent->return_value=f->eax;
			else
			{
				//dead_child_list insertion.
				thread_current()->present_in_dead_child_list = true;
				struct dead_child *dead=malloc(sizeof(struct dead_child));
				dead->tid=thread_current()->tid;
				dead->exit_status=f->eax;
				list_push_back(&thread_current()->parent->dead_child_list,&dead->elem);
			}
/*			/**/
/*				As given in pintos.pdf all the open files are closed and removed from the processes list.*/
/*			*/
/*			for (e = list_begin (&thread_current()->open_files_list); e != list_end (&thread_current()->open_files_list);e = list_next (e))*/
/*        		{*/
/*          			struct open_file *o = list_entry (e, struct open_file, elem);*/
/*  				list_remove(e);*/
/*  				file_close(o->file);*/
/*  				/*free(o);*/
/*          		}*/
  			printf("%s: exit(%d)\n",thread_name(),f->eax);
  			thread_exit();
  			break;
  	case SYS_EXEC:
  			//printf("Exec Called.\n");
  			vir_esp=(f->esp)+4;
  			if(lookup_page(thread_current()->pagedir,*(const char **)vir_esp,false)!=NULL)
  			{
	  			pid_exec=process_execute(*(char**)vir_esp);
	  			/*make a struct lock child_exec_lock variable in each thread,that keeps track of the 
	  			fact that parent will not execute until the child has loaded it's program.*/
	  			list_push_back(&(thread_current()->child_exec_lock.semaphore.waiters),&(thread_current()->elem));
	  			thread_block();
	  			//printf("Returned Value:%d\n",pid_exec);
	  			/*in start_process the new process spawned by the process_execute
	  			should acquire the lock and then after successfull loading should release the lock.*/
	  			if(thread_current()->return_value==-1)
	  			{
	  				f->eax=-1;
	  				return;
	  			}
	  			f->eax=pid_exec;
	  		}
  			else
  			{
  				f->eax=-1;
  				thread_current()->parent->return_value=f->eax;
				printf("%s: exit(%d)\n",thread_name(),f->eax);
				thread_exit();
  			}
  		break;
  	case SYS_WAIT:
/*  			printf("PID Waiting on:%d\n",*(int *)((f->esp)+4));*/
/*  			printf("Current Thread:%s\n",thread_name());*/
			thread_current()->wait_called=true;
  			f->eax=process_wait(*(int *)((f->esp)+4));
  			thread_current()->wait_called=false;
  			break;
  	case SYS_CREATE:
  			vir_esp=(f->esp)+4;
  			if(lookup_page(thread_current()->pagedir,*(const char **)vir_esp,false)!=NULL)
  			{
				/*
					name is pointing well below PHYS_BASE.
     				*/
  				const char *name=*(const char**)vir_esp;
				/*
					if name is NULL or the file name passed is empty.
				*/
				if(name==NULL || strcmp(name,"")==0)
				{
					f->eax=-1;
					thread_current()->parent->return_value=f->eax;
  					printf("%s: exit(%d)\n",thread_name(),f->eax);
					thread_exit();
				}
				if(strlen(name) > 14)
				{
					f->eax=0;
					thread_current()->parent->return_value=0;
					return;
				}
  				int size=*(int*)(vir_esp+4);
				/*
					if size is negative,then we can't create the file.
				*/
				if(size	< 0)
				{
					f->eax=-1;
					thread_current()->parent->return_value=f->eax;
					printf("%s: exit(%d)\n",thread_name(),f->eax);
					thread_exit();
				}
				/*printf("Size of struct thread:%d\n",sizeof(struct thread));
				for(;;);*/
  				f->eax=filesys_create(name,size);
  			}
			/*
				if the name is pointing to a invalid address.
			*/
			else
			{
				f->eax=-1;
				thread_current()->parent->return_value=f->eax;
  				printf("%s: exit(%d)\n",thread_name(),f->eax);
				thread_exit();
			}
  			break;
  	case SYS_REMOVE:
  			if(lookup_page(thread_current()->pagedir,*(const char **)((f->esp)+4),false)!=NULL)
  			{
  				if(strcmp(*(const char **)((f->esp)+4),"")==0)
  				{
  					f->eax=0;
  				}
  				else
  				{
  					f->eax=filesys_remove(*(const char **)((f->esp)+4));
  				}
  			}
  			else
  			{
  				f->eax=-1;
				thread_current()->parent->return_value=f->eax;
				printf("%s: exit(%d)\n",thread_name(),f->eax);
				return;
  			}
  			break;
  	case SYS_OPEN:
  			vir_esp=(f->esp)+4;
  			if(lookup_page(thread_current()->pagedir,*(const char **)vir_esp,false)!=NULL)
  			{
  				const char *name=*(const char**)vir_esp;
				/*
					if name is NULL or the file name passed is empty.
				*/
				if(name==NULL || strcmp(name,"")==0)
				{
					f->eax=-1;
					thread_current()->parent->return_value=f->eax;
					return;
				}
				struct file *file=filesys_open(name);
				if(file==NULL)
				{
					f->eax=-1;
					thread_current()->parent->return_value=f->eax;
					return;
				}
				/*
					Denying Writes to executables.
				*/
				if(strcmp(name,thread_name())==0 || strcmp(name,thread_current()->parent->name)==0)
				{
					file_deny_write(file);
				}
				struct open_file *o_f = malloc(sizeof(struct open_file));
				o_f->file=file;
				o_f->fd=thread_current()->last_fd+1;
				thread_current()->last_fd = o_f->fd;
				list_push_back(&thread_current()->open_files_list,&o_f->elem);
				f->eax=thread_current()->last_fd;
  			}
  			else
  			{
  				f->eax=-1;
  				thread_current()->parent->return_value=f->eax;
  				printf("%s: exit(%d)\n",thread_name(),f->eax);
  				thread_exit();
  			}
  			break;
  	case SYS_FILESIZE:
			for (e = list_begin (&thread_current()->open_files_list); e != list_end (&thread_current()->open_files_list);e = list_next (e))
        		{
          			struct open_file *o = list_entry (e, struct open_file, elem);
          			if(o->fd==*(int*)((f->esp)+4))
          			{
          				f->eax=file_length(o->file);
          				return;
          			}
		        }
  			break;
  	case SYS_READ:
  			if((*(int*)((f->esp)+4)) == 0)
  			{
  				input_getc();
  				return;
  			}
			for (e = list_begin (&thread_current()->open_files_list); e != list_end (&thread_current()->open_files_list);e = list_next (e))
        		{
          			struct open_file *o = list_entry (e, struct open_file, elem);
          			if((o->fd)==(*(int*)((f->esp)+4)))
          			{
          				if(lookup_page(thread_current()->pagedir,*(char**)((f->esp)+8),false)!=NULL)
					/*if(is_user_vaddr(*(char**)((f->esp)+8)))*/
          				{
          					/*printf("File Name:~%s~\n",*(char**)((f->esp)+8));*/
          					f->eax=file_read(o->file,*(char**)((f->esp)+8),*(uint32_t*)(((f->esp)+12)));
          					return;
          				}
          				else
          				{
          					f->eax=-1;
  						thread_current()->parent->return_value=f->eax;
          					printf("%s: exit(%d)\n",thread_name(),f->eax);
          					thread_exit();
          				}
          			}
		        }
		        /* File is not present in the list of open files.*/
		        f->eax=-1;
  			break;
  	case SYS_WRITE:
  			/*
  				Define a write_lock and whenever a process wants to write it will first have to
  				acquire a write lock except in the case of console in which locks are already implemented.
  				and when it finishes writing then it releases the lock.
  				Basically Implementation of readers and writers algorithm.
  			*/
  			vir_esp=(f->esp)+4;
  			int file_descriptor=*(int*)((f->esp)+4);
  			int size;
  			vir_esp=vir_esp+4;
  			if(lookup_page(thread_current()->pagedir,*(const char **)vir_esp,false)!=NULL)
  			{
  				const char *buffer=*(const char**)vir_esp;
  				size=*(int*)(vir_esp+4);
  				if(file_descriptor==1)
  				{
					putbuf(buffer,size);
				}
  				
  				else
  				{
  					/*lock_acquire(&write_lock);
  					//writing business..
  					lock_release(&write_lock);*/
  				for (e = list_begin (&thread_current()->open_files_list); e != list_end (&thread_current()->open_files_list);e = list_next (e))
        			{
          			struct open_file *o = list_entry (e, struct open_file, elem);
          			if((o->fd)==(*(int*)((f->esp)+4)))
          			{
          				if(lookup_page(thread_current()->pagedir,*(char**)((f->esp)+8),false)!=NULL)
          				{
  						f->eax=file_write(o->file,*(char**)((f->esp)+8),*(uint32_t*)(((f->esp)+12)));
						return;
          				}
          				else
          				{
          					f->eax=-1;
  						thread_current()->parent->return_value=f->eax;
          					printf("%s: exit(%d)\n",thread_name(),f->eax);
          					thread_exit();
          				}
          			}
		        }
  				}
  				
  			}
  			else
  			{
					f->eax=-1;
					thread_current()->parent->return_value=f->eax;
  					printf("%s: exit(%d)\n",thread_name(),f->eax);
  					thread_exit();
  			}
  			break;
  	case SYS_SEEK:
  			for (e = list_begin (&thread_current()->open_files_list); e != list_end (&thread_current()->open_files_list);e = list_next (e))
        		{
          			struct open_file *o = list_entry (e, struct open_file, elem);
          			if(o->fd==*(int*)((f->esp)+4))
          			{
          				if((*(int*)((f->esp)+8))>=0)
          				{
          					file_seek(o->file,*(int*)((f->esp)+8));
          					return;
          				}
          			}
		        }
  			break;
  	case SYS_TELL:
  			for (e = list_begin (&thread_current()->open_files_list); e != list_end (&thread_current()->open_files_list);e = list_next (e))
        		{
          			struct open_file *o = list_entry (e, struct open_file, elem);
          			if(o->fd==*(int*)((f->esp)+4))
          			{
          				f->eax=file_tell(o->file);
          				return;
          			}
          		}
  			break;
  	case SYS_CLOSE:
  			for (e = list_begin (&thread_current()->open_files_list); e != list_end (&thread_current()->open_files_list);e = list_next (e))
        		{
          			struct open_file *o = list_entry (e, struct open_file, elem);
          			if(o->fd==*(int*)((f->esp)+4))
          			{
          				list_remove(e);
          				file_close(o->file);
					free(o);
          				return;
          			}
          		}
  			break;
  }  
  /*
  	Added Code Ends.
  */
}
