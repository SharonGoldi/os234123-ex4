#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MIN_SIZE 0
#define MAX_SIZE 10^8

using namespace std;

struct block {
    size_t size;
    struct block* next;
    int is_free;
};
typedef struct block* Block;

Block global_last_allocated = NULL;
Block global_first_allocated = NULL;

Block FindFreeBlock(size_t size) {
    Block curr = global_first_allocated;
    while (curr != NULL &&
            !(curr->size >= size && curr->is_free)) {
        curr = curr->next;
    }
    return curr;
}

Block AddNewBlock(size_t size) {
    Block block = (Block)sbrk(0);
    void* new_block = sbrk(size + sizeof(struct block));

    if (new_block == (void*) -1) {
        return NULL;
    }

    if(global_last_allocated != NULL) {
        global_last_allocated->next = block;
    }

    block->size = size;
    block->next = NULL;
    block->is_free = 0;
    global_last_allocated = block;

    return block;
}

/////////////////////////////////////////////////////////////////////////////////

void* malloc(size_t size) {
    //check input
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return nullptr;
    }

    Block block;
    //if its the first call to malloc
    if(!global_last_allocated) {
        block = AddNewBlock(size);
        if (block == nullptr) {
            return nullptr;
        }
        global_first_allocated = block;
    } else {
        block = FindFreeBlock(size);
        // if there is a freed block, unfree him, update the block info and return it
        if (block != nullptr) {
            block->is_free = 0;
        // if there isn't any freed block, allocate a new one
        } else {
            block = AddNewBlock(size);
            if (block == nullptr) {
                return nullptr;
            }
        }
    }
    // added 1 to jump a size of a block and jump over the metadata
    return (block + 1);
}

void free(void* p) {
    if (p == NULL) {
        return;
    }

    Block block = (Block)p - 1;
    block->is_free = 1;
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

    Block old_block = (Block)oldp - 1;
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
    return sizeof(struct block) * _num_allocated_blocks();
}

size_t _size_meta_data() {
    return sizeof(struct block);
}
