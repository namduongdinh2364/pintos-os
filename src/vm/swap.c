#include "threads/malloc.h"
#include "swap.h"
#include <stdio.h>

struct swap_table * swap_table_ptr;

/**
 * bitmap is initally all set to false.
 * false = block available. true=in use
 */
void vm_swap_init(void){
	int num_pages;

	swap_table_ptr = malloc(sizeof(struct swap_table));
	swap_table_ptr->swap_block = block_get_role(BLOCK_SWAP);
	if (swap_table_ptr->swap_block == NULL)
		PANIC ("Not found block device, can't initialize swap");

	num_pages = block_size(swap_table_ptr->swap_block) / SECTORS_PER_PAGE;
	swap_table_ptr->swap_bitmap = bitmap_create(num_pages);
	if (swap_table_ptr->swap_bitmap == NULL)
		PANIC ("Failed swap bitmap creation");

  	bitmap_set_all (swap_table_ptr->swap_bitmap, false);
}

/**
 * Find an available swap slot and write page in RAM to page in Block.
 * If failed, return SWAP_ERROR
 * Otherwise, return the swap slot index
 */
int vm_swap_out(void * kpage)
{
	int sw_index = bitmap_scan_and_flip(swap_table_ptr->swap_bitmap, 0, 1, false);

  	if (sw_index == BITMAP_ERROR)
    	return SWAP_ERROR;

	/* write data to the swap slot */
	size_t sector_index = 0;
	while (sector_index < SECTORS_PER_PAGE)
	{
		block_write(swap_table_ptr->swap_block, sw_index * SECTORS_PER_PAGE + sector_index , kpage);
		kpage += BLOCK_SECTOR_SIZE;
		sector_index++;
	}

	return sw_index;
}

/* Write data in swap block to kpage. */
bool vm_swap_in(void * kpage, int bitmap_index)
{
	int i = 0;
	int sector_index = bitmap_index * SECTORS_PER_PAGE;

	while (i < SECTORS_PER_PAGE)
	{
		block_read(swap_table_ptr->swap_block, sector_index + i, kpage);
		kpage += BLOCK_SECTOR_SIZE;
		i++;
	}
	bitmap_set(swap_table_ptr->swap_bitmap, bitmap_index ,false);

	return true;
}	

void vm_swap_free(int index){
	bitmap_set(swap_table_ptr->swap_bitmap, index, false);
}

void vm_swap_destroy(void){
	bitmap_destroy(swap_table_ptr->swap_bitmap);
}
