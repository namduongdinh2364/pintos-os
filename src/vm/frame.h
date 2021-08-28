#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/hash.h"
#include <hash.h>

struct frame_table *ft;
struct lock frame_table_lock;

struct frame_table
{
	struct hash frames;
};

struct frame_table_entry
{
	struct hash_elem hash_elem;
	struct list_elem list_elem;
	void *upage;
	int tid;
	bool pinned;
	struct thread *owner_thread;
};

void vm_frame_table_init(void);
void vm_frame_table_set_frame(void *upage, int tid);
void vm_frame_table_evict_frame(void);
struct frame_table_entry *vm_frame_table_lookup(void *upage, int tid);
void vm_frame_table_delete_entry(void *upage, int tid);
void vm_frame_table_destroy(void);

#endif /* VM_FRAME_H */
