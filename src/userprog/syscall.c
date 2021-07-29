#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
// #include "list.h"

static void syscall_handler (struct intr_frame *);
struct file_descriptor* scan_file(struct list* files, int fd);
struct file_descriptor {
	struct file* ptr;
	int fd;
	struct list_elem elem;
};

void check_vali_add(const void*);

void
syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    int *esp = f->esp;

    check_vali_add(esp);

    int system_call = *esp;
    switch (system_call)
    {
        case SYS_HALT:
            shutdown_power_off();
            break;

        case SYS_EXIT:
            check_vali_add(esp + 1);
            exit_proc(*(esp + 1));
            break;

        case SYS_EXEC:
            check_vali_add(esp + 1);
            check_vali_add(*(esp + 1));
            f->eax = exec_proc(*(esp + 1));
            break;

        case SYS_WAIT:
            check_vali_add(esp + 1);
		    f->eax = process_wait(*(esp + 1));
            break;

        case SYS_CREATE:
            check_vali_add(esp+2);
            check_vali_add(*(esp+1));
            acquire_lock_filesys();
            f->eax = filesys_create(*(esp+1),*(esp+2));
            release_lock_filesys();
            break;

        case SYS_REMOVE:
            check_vali_add(esp+1);
            check_vali_add(*(esp+1));
            acquire_lock_filesys();
            f->eax = filesys_remove(*(esp+1));
            release_lock_filesys();
            break;

        case SYS_OPEN:
            check_vali_add(esp+1);
            check_vali_add(*(esp+1));
            acquire_lock_filesys();
            struct file* fptr = filesys_open (*(esp+1));
            release_lock_filesys();

            if(fptr==NULL)
                f->eax = -1;
            else
            {
                struct file_descriptor *pfile = malloc(sizeof(*pfile));
                pfile->ptr = fptr;
                pfile->fd = thread_current()->fd_index;
                thread_current()->fd_index++;
                list_push_back (&thread_current()->files, &pfile->elem);
                f->eax = pfile->fd;
            }
            break;

        case SYS_FILESIZE:
            check_vali_add (esp+1);
            acquire_lock_filesys ();
            f->eax = file_length (scan_file(&thread_current()->files, *(esp+1))->ptr);
            release_lock_filesys ();
            break;

        case SYS_READ:
            check_vali_add(esp + 3);
            check_vali_add(*(esp + 2));

            if(*(esp + 1) == 0)
            {
                int i;
                uint8_t* buffer = *(esp + 2);
                for(i = 0; i < *(esp + 3); i++)
                    buffer[i] = input_getc();
                f->eax = *(esp + 3);
            }
            else
            {
                struct file_descriptor* fptr = scan_file(&thread_current()->files, *(esp + 1));
                if(fptr == NULL)
                {
                    f->eax = -1;
                }
                else
                {
                    acquire_lock_filesys();
                    f->eax = file_read (fptr->ptr, *(esp+2), *(esp + 3));
                    release_lock_filesys();
                }
            }
            break;

        case SYS_WRITE:
            check_vali_add (esp + 3);
            check_vali_add (*(esp + 2));

            if(*(esp + 1) == 1)   /* Write to stdout */
            {
                if(*(esp + 3) != 0)
                    putbuf(*(esp + 2),*(esp + 3));	/* put buffer and size to func putbuf */
                f->eax = *(esp + 3);			    /* Return size of buffer */
            }
            else
            {
                struct file_descriptor* fptr = scan_file (&thread_current()->files, *(esp + 1));
                if(fptr == NULL)
                {
                    f->eax = -1;
                }
                else
                {
                    acquire_lock_filesys ();
                    f->eax = file_write (fptr->ptr, *(esp + 2), *(esp + 3));
                    release_lock_filesys ();
                }
            }
            break;

        case SYS_SEEK:
            check_vali_add(esp+ 2);

            acquire_lock_filesys ();
            file_seek (scan_file(&thread_current()->files, *(esp + 1))->ptr, *(esp + 2));
            release_lock_filesys ();
            break;

		case SYS_TELL:
            check_vali_add(esp+1);

            acquire_lock_filesys();
            f->eax = file_tell(scan_file(&thread_current()->files, *(esp + 1))->ptr);
            release_lock_filesys();
		    break;

		case SYS_CLOSE:
            check_vali_add (esp+1);
            acquire_lock_filesys ();
            close_file (&thread_current()->files,*(esp+1));
            release_lock_filesys ();
		    break;

        default:
            exit_proc(-1);
            break;
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

void check_vali_add (const void *vaddr)
{
    int i;
    char *esp = (char *)vaddr;
    for(i=0; i< 4; i++)
    {
        if (!is_user_vaddr(esp + i))
        {
            exit_proc(-1);
        }

        /* Verify that the user-addr is mapped to kernel-addr */ 
        void *check  = pagedir_get_page(thread_current()->pagedir, esp + i);
        if (check == NULL)
        {
            exit_proc(-1);
        }
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

    for (e = list_begin (files); e != list_end (files); e = list_next (e))
    {
        struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
        if(f->fd == fd)
        {
            file_close (f->ptr);
            list_remove (e);
            free(f);
            break;
        }
    }
}

void close_all_files(struct list* files)
{
    struct list_elem *e;
    while(!list_empty(files))
    {
        e = list_pop_front(files);
        struct file_descriptor *f = list_entry (e, struct file_descriptor, elem); 
        file_close(f->ptr);
        list_remove(e);
        free(f);
    }  
}

struct file_descriptor* scan_file(struct list* files, int fd)
{
	struct list_elem *e;

      for (e = list_begin (files); e != list_end (files); e = list_next (e))
        {
          struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
          if(f->fd == fd)
          	return f;
        }

    return NULL;
}

