#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include <hash.h>

/* Constants that define where the page is located. */
typedef enum {
	ALL_ZERO,
	IN_RAM,
	IN_SWAP,
	IN_FILESYS
} page_location_Type;

struct sup_pg_table
{
	struct hash supplemental;
};

struct sup_pg_table_entry
{
	struct hash_elem hash_elem;
	page_location_Type location;
	void *upage;
	int index;
	int zero;
	int read;
	bool from_file;
	struct file *file;
	int offset;
	bool writeable; 
};

struct sup_pg_table *vm_sup_pg_table_init (void);
void vm_sup_pg_table_set_page (void *upage, bool writeable);
void vm_sup_pg_table_push_to_RAM (void *upage, struct thread *t);
void vm_sup_pg_table_push_to_SWAP (void *upage, int index, struct thread *t);
void vm_sup_pg_table_push_to_FILE (void *upage, struct file *f, int offset, int read, int zero, struct thread *cur);
struct sup_pg_table_entry *vm_sup_pg_table_lookup (void *upage, struct thread *t);
void vm_sup_pg_table_destroy (struct sup_pg_table *st);
void vm_sup_pg_table_delete_entry (void *upage);

#endif /* VM_PAGE_H */
