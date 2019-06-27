#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MIN_SIZE 0
#define MAX_SIZE 10^8
#define LARGE_ENOUGH_MEM 128
#define MEM_LINE_LEN 4
#define BLOCK_SIZE sizeof(struct block) + MEM_LINE_LEN - sizeof(struct block)%MEM_LINE_LEN


using namespace std;

struct block {
    size_t size;
    struct block* next;
    struct block* prev;
    int is_free;
};
typedef struct block* Block;

Block global_last_allocated = NULL;
Block global_first_allocated = NULL;

Block DivideLargeBlock(Block old_block, size_t size) {
    Block new_block = (Block)((char*)old_block + BLOCK_SIZE + size);

    new_block->size = old_block->size - size - BLOCK_SIZE;
    old_block->size = size;
    new_block->next = old_block->next;
    old_block->next = new_block;
    new_block->prev = old_block;
    new_block->is_free = 0;
    return new_block;
}

Block FindFreeBlock(size_t size) {
    Block curr = global_first_allocated;
    while (curr != NULL &&
            !(curr->size >= size && curr->is_free)) { //TODO: check cond
        curr = curr->next;
    }
    size_t aligmnentSize = size + MEM_LINE_LEN - size%MEM_LINE_LEN;
    if (curr != NULL &&
            curr->size - aligmnentSize - BLOCK_SIZE >= LARGE_ENOUGH_MEM) {
        DivideLargeBlock(curr, aligmnentSize);
    }
    // if all blocks do not fit and the last block is freed but not big enough
    // - make it bigger.
    if (curr == NULL && global_last_allocated->is_free == 1) {
        unsigned long diff = size - global_last_allocated->size;
        diff = diff + MEM_LINE_LEN - diff%MEM_LINE_LEN;
        void* added = sbrk(diff);

        if (added == (void*) -1) {
            return NULL;
        }
        global_last_allocated->size = size;
        return global_last_allocated;
    } else {
        return curr;
    }
}

Block AddNewBlock(size_t size) {
    Block block = (Block)sbrk(0);
    
    void* new_block = sbrk(BLOCK_SIZE);

    if (new_block == (void*) -1) {
        return NULL;
    }

    size_t data_alignment = MEM_LINE_LEN - size%MEM_LINE_LEN;
    void* new_data = sbrk(size + data_alignment);
    
    if (new_data == (void*) -1) {
        sbrk(-BLOCK_SIZE);
        return NULL;
    }

    if(global_last_allocated != NULL) {
        global_last_allocated->next = block;
    }

    block->size = size + data_alignment;
    block->next = NULL;
    block->prev = global_last_allocated;
    global_last_allocated = block;
    block->is_free = 0;

    return block;
}

Block MergeAdjacentBlocks(Block first, Block second) {
    // TODO: be aware, this function changes it's input parameters
    first->size += second->size + BLOCK_SIZE;
    first->next = second->next;

    if (second->next != NULL) {
        second->next->prev = first;
    }

    second->size = 0;
    second->prev = NULL;
    second->next = NULL;

    return first;
}

/////////////////////////////////////////////////////////////////////////////////

void* malloc(size_t size) {
    //check input
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return NULL;
    }

    Block block;
    //if its the first call to malloc
    if(!global_last_allocated) {
        block = AddNewBlock(size);
        if (block == NULL) {
            return NULL;
        }
        global_first_allocated = block;
    } else {
        block = FindFreeBlock(size);
        // if there is a freed block, unfree him, update the block info and return it
        if (block != NULL) {
            block->is_free = 0;
            // if there isn't any freed block, allocate a new one
        } else {
            block = AddNewBlock(size);
            if (block == NULL) {
                return NULL;
            }
        }
    }
    // jump a size of a block and jump over the metadata
    return (char *)block + BLOCK_SIZE;
}

void free(void* p) {
    if (p == NULL) {
        return;
    }

    Block block = (Block)((char *)p - BLOCK_SIZE);
    block->is_free = 1;

    if (block->next != NULL && block->next->is_free == 1) {
        MergeAdjacentBlocks(block, block->next);
    }
    if (block->prev != NULL && block->prev->is_free == 1) {
        MergeAdjacentBlocks(block->prev,block);
    }
}

void* calloc(size_t num, size_t size){
    void* p = malloc(num*size);
    if (p == NULL) {
        return NULL;
    }

    memset(p, 0, num*size);
    return p;
}

void* realloc(void* oldp, size_t size) {
    // check input
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return NULL;
    }
    if (oldp == NULL) {
        return malloc(size);
    }

    Block old_block = (Block)((char *)oldp - BLOCK_SIZE);
    // if the new size is smaller - no need to realloc (wasteful but works)
    if (old_block->size >= size) {
        return oldp;
    }
    // if the new size is bigger
    void* newp = malloc(size);
    if (newp == NULL) {
        return NULL;
    }

    memcpy(newp, oldp, old_block->size);
    free(oldp);
    return newp;
}

size_t _num_free_blocks() {
    unsigned int num_free = 0;
    Block block = global_first_allocated;
    while (block != NULL) {
        if(block->is_free == 1) {
            num_free++;
        }
        block = block->next;
    }
    return num_free;
}

size_t _num_free_bytes() {
    unsigned int num_free = 0;
    Block block = global_first_allocated;
    while (block != NULL) {
        if(block->is_free == 1) {
            num_free += block->size;
        }
        block = block->next;
    }
    return num_free;
}

size_t _num_allocated_blocks() {
    unsigned int num_allocated = 0;
    Block block = global_first_allocated;
    while (block != NULL) {
        num_allocated++;
        block = block->next;
    }
    return num_allocated;
}

size_t _num_allocated_bytes() {
    unsigned int num_allocated = 0;
    Block block = global_first_allocated;
    while (block != NULL) {
        num_allocated += block->size;
        block = block->next;
    }
    return num_allocated;
}

size_t _num_meta_data_bytes() {
    return BLOCK_SIZE * _num_allocated_blocks();
}

size_t _size_meta_data() {
    return BLOCK_SIZE;
}
