#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
// #include "list.h"

static void syscall_handler (struct intr_frame *);
struct proc_file* scan_file(struct list* files, int fd);
struct proc_file {
	struct file* ptr;
	int fd;
	struct list_elem elem;
};

void* check_addr(const void*);

void
syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    int *p = f->esp;

    check_addr(p);

    int system_call = *p;
    switch (system_call)
    {
        case SYS_HALT:
            shutdown_power_off();
        break;

        case SYS_EXIT:
            check_addr(p + 1);
            exit_proc(*(p + 1));
        break;

        case SYS_EXEC:
            check_addr(p + 1);
            check_addr(*(p + 1));
            f->eax = exec_proc(*(p + 1));
        break;

        case SYS_WAIT:
            check_addr(p + 1);
		    f->eax = process_wait(*(p + 1));
        break;

        case SYS_CREATE:
            check_addr(p+2);
            check_addr(*(p+1));
            acquire_lock_filesys();
            f->eax = filesys_create(*(p+1),*(p+2));
            release_lock_filesys();
        break;

        case SYS_REMOVE:
            check_addr(p+1);
            check_addr(*(p+1));
            acquire_lock_filesys();
            f->eax = filesys_remove(*(p+1));
            release_lock_filesys();
        break;

        case SYS_OPEN:
            check_addr(p+1);
            check_addr(*(p+1));
            acquire_lock_filesys();
            struct file* fptr = filesys_open (*(p+1));
            release_lock_filesys();

            if(fptr==NULL)
                f->eax = -1;
            else
            {
                struct proc_file *pfile = malloc(sizeof(*pfile));
                pfile->ptr = fptr;
                pfile->fd = thread_current()->fd_index;
                thread_current()->fd_index++;
                list_push_back (&thread_current()->files, &pfile->elem);
                f->eax = pfile->fd;
            }
        break;

        case SYS_FILESIZE:
            check_addr (p+1);
            acquire_lock_filesys ();
            f->eax = file_length (scan_file(&thread_current()->files, *(p+1))->ptr);
            release_lock_filesys ();
        break;

        case SYS_READ:
            check_addr(p + 3);
            check_addr(*(p + 2));

            if(*(p + 1) == 0)
            {
                int i;
                uint8_t* buffer = *(p + 2);
                for(i = 0; i < *(p + 3); i++)
                    buffer[i] = input_getc();
                f->eax = *(p + 3);
            }
            else
            {
                struct proc_file* fptr = scan_file(&thread_current()->files, *(p + 1));
                if(fptr == NULL)
                {
                    f->eax = -1;
                }
                else
                {
                    acquire_lock_filesys();
                    f->eax = file_read (fptr->ptr, *(p+2), *(p + 3));
                    release_lock_filesys();
                }
            }
        break;

        case SYS_WRITE:
            check_addr (p + 3);
            check_addr (*(p + 2));

            if(*(p + 1) == 1)   /* Write to stdout */
            {
                if(*(p + 3) != 0)
                    putbuf(*(p + 2),*(p + 3));	/* put buffer and size to func putbuf */
                f->eax = *(p + 3);			    /* Return size of buffer */
            }
            else
            {
                struct proc_file* fptr = scan_file (&thread_current()->files, *(p + 1));
                if(fptr == NULL)
                {
                    f->eax = -1;
                }
                else
                {
                    acquire_lock_filesys ();
                    f->eax = file_write (fptr->ptr, *(p + 2), *(p + 3));
                    release_lock_filesys ();
                }
            }
        break;

        case SYS_SEEK:
            check_addr( p+ 2);

            acquire_lock_filesys ();
            file_seek (scan_file(&thread_current()->files, *(p + 1))->ptr, *(p + 2));
            release_lock_filesys ();
        break;

		case SYS_TELL:
            check_addr(p+1);

            acquire_lock_filesys();
            f->eax = file_tell(scan_file(&thread_current()->files, *(p + 1))->ptr);
            release_lock_filesys();
		break;

		case SYS_CLOSE:
            check_addr (p+1);
            acquire_lock_filesys ();
            close_file (&thread_current()->files,*(p+1));
            release_lock_filesys ();
		break;

        default:
            printf("Default %d\n", *p);
    }
}

void exit_proc (int status)
{
    struct list_elem *e;

    for (e = list_begin (&thread_current()->parent->child_proc); e != list_end (&thread_current()->parent->child_proc); e = list_next (e))
    {
        struct child *ch = list_entry (e, struct child, elem);
        if(ch->tid == thread_current()->tid)
        {
            ch->action = false;
            ch->exit_error = status;
        }
    }
    thread_current()->exit_error = status;

    if(thread_current()->parent->wait_tid == thread_current()->tid)
        sema_up(&thread_current()->parent->child_lock);

    thread_exit();
}

void* check_addr (const void *vaddr)
{
    if (!is_user_vaddr(vaddr))
    {
        exit_proc(-1);
    }

    /* Verify that the user-addr is mapped to kernel-addr */ 
    void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
    if (!ptr)
    {
        exit_proc(-1);
    }
}

int exec_proc (char *file_name)
{
    acquire_lock_filesys();
    char * fn_cp = malloc (strlen(file_name)+1);
    strlcpy(fn_cp, file_name, strlen(file_name)+1);

    char * save_ptr;
    fn_cp = strtok_r(fn_cp," ",&save_ptr);

    struct file* f = filesys_open (fn_cp);

    file_close(f);
    release_lock_filesys();
    if(f == NULL)
    {
        return -1;
    }
    return process_execute(file_name);
}

void close_file(struct list* files, int fd)
{
    struct list_elem *e;
    struct proc_file *f;

    for (e = list_begin (files); e != list_end (files); e = list_next (e))
    {
        f = list_entry (e, struct proc_file, elem);
        if(f->fd == fd)
        {
            file_close (f->ptr);
            list_remove (e);
        }
    }
    free(f);
    if(fd == 1 || fd == 0)
    {
        exit_proc(-1);
    }
}

void close_all_files(struct list* files)
{
    struct list_elem *e;
    while(!list_empty(files))
    {
        e = list_pop_front(files);
        struct proc_file *f = list_entry (e, struct proc_file, elem); 
        file_close(f->ptr);
        list_remove(e);
        free(f);
    }  
}

struct proc_file* scan_file(struct list* files, int fd)
{
	struct list_elem *e;

      for (e = list_begin (files); e != list_end (files); e = list_next (e))
        {
          struct proc_file *f = list_entry (e, struct proc_file, elem);
          if(f->fd == fd)
          	return f;
        }

    return NULL;
}