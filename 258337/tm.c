/**
 * @file   tm.c
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// Internal headers
#include <tm.h>
#include <assert.h>

// -------------------------------------------------------------------------- //

/** Define a proposition as likely true.
 * @param prop Proposition
**/
#undef likely
#ifdef __GNUC__
    #define likely(prop) \
        __builtin_expect((prop) ? 1 : 0, 1)
#else
    #define likely(prop) \
        (prop)
#endif

/** Define a proposition as likely false.
 * @param prop Proposition
**/
#undef unlikely
#ifdef __GNUC__
    #define unlikely(prop) \
        __builtin_expect((prop) ? 1 : 0, 0)
#else
    #define unlikely(prop) \
        (prop)
#endif

/** Define one or several attributes.
 * @param type... Attribute names
**/
#undef as
#ifdef __GNUC__
    #define as(type...) \
        __attribute__((type))
#else
    #define as(type...)
    #warning This compiler has no support for GCC attributes
#endif

// -------------------------------------------------------------------------- //
//my function:
void free_transaction(tx_t tx, shared_t shared);
bool validate_transaction(shared_t shared as(unused), tx_t tx as(unused));
size_t get_index_start(shared_t shared as(unused), void const* memory_state_ptr as(unused));
unsigned int extract_version(unsigned int versioned_lock);
bool validate_the_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_items, unsigned int* locks_before_reading);
bool is_lock(unsigned int versioned_lock);

//only one region for our program, its the main contenant.
struct region {
    void* start;                //the global region memory
    atomic_size_t size;         //size of the segment (assume only one segment here)
    atomic_size_t align;       // Claimed alignment of the shared memory region (in bytes)
    atomic_size_t align_alloc; // Actual alignment of the memory allocations (in bytes)
    atomic_uint global_version_clock; //The global clock
    atomic_uint* versioned_locks;
};

struct shared_memory_state{
    bool read; //if the value has been read last ()
    void*  new_value;  //the value to write by the transaction at this location
};

struct transaction{
    bool is_read_only;
    unsigned int rv;  //read version number
    unsigned int wv;  //write version number
    struct shared_memory_state* memory_state; //a pointer to an array of object shared_memory_state storing the new value to write
};

struct segment{
    atomic_size_t size;
};

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused)) {
    // TODO: tm_create(size_t, size_t)
    //alloc the space for the struct region:
    struct region* region = (struct region*) malloc(sizeof(struct region));
    //copy from references
    if (unlikely(!region)) {
        return invalid_shared;
    }
    // Check that the given alignment is correct
    // Also satisfy alignment requirement of 'struct link'
    //size of void is the size of a pointer depending on the 32-bit or 64-bit system.
    size_t align_alloc = align < sizeof(void*) ? sizeof(void*) : align;
    //allocate the segment:
    //The posix_memalign() function shall allocate size bytes aligned on a boundary specified by alignment, and shall
    // return a pointer to the allocated memory in memptr. The value of alignment shall be a power of two multiple of sizeof(void *).
    //Upon successful completion, posix_memalign() shall return zero
    if (unlikely(posix_memalign(&(region->start), align_alloc, size) != 0)) {
        free(region->start);
        free(region);
        return invalid_shared;
    }
    //we fill the segment with zero:
    memset(region->start, 0, size);
    //then we can init the region:
    atomic_init(&(region->size), size);
    atomic_init(&(region->align), align);
    atomic_init(&(region->align_alloc), align_alloc);
    //init global_clock to zero
    atomic_init(&(region->global_version_clock), 0u); //0u = unsigned int

    //we create the array for versioned-locks
    //The difference in malloc and calloc is that malloc does not set the memory to zero where as calloc sets allocated memory to zero.
    //in our region we gonna have size/align number of "case", each one need a lock.
    atomic_uint* versioned_locks = (atomic_uint*) calloc(size / align, sizeof(atomic_uint));
    if (unlikely(!versioned_locks)) {
        free(region->start);
        free(region);
        return invalid_shared;
    }
    //assign versioned locks to region
    region->versioned_locks = versioned_locks;
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
    //cast:
    struct region* region_to_destroy = (struct region*) shared;
    free(region_to_destroy->start);
    free(region_to_destroy->versioned_locks);
    free(shared);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused)) {
    //cast:
    struct region* region = (struct region*) shared;
    return region->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared as(unused)) {
    //cast:
    struct region* region = (struct region*) shared;
    size_t size = atomic_load(&(region->size));        //pointeur??
    return size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared as(unused)) {
    //cast:
    struct region* region = (struct region*) shared;
    size_t align = atomic_load(&(region->align));
    return align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
//create an empty new transaction:
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused)) {
    struct region* region = (struct region*) shared;
    //get global clock:
    unsigned int global_clock = atomic_load(&(region->global_version_clock));
    //init a transaction:
    struct transaction* transaction = (struct transaction*) malloc(sizeof(struct transaction));
    if (unlikely(!transaction)) {
        return invalid_tx;
    }
    transaction->is_read_only = is_ro;
    transaction->rv = global_clock;
    size_t alignment = tm_align(shared); //size_t is unsigned integer version of sizeof()
    size_t size_transaction = tm_size(shared);
    size_t number_of_case = size_transaction / alignment;

    //if is not read only : alloc new space for shared_memory_state with value null
    if(!is_ro) {
        //create a local memory_state
        struct shared_memory_state *memory_state = (struct shared_memory_state *) calloc(number_of_case,
                                                                                         sizeof(struct shared_memory_state));
        if (unlikely(!memory_state)) {
            free(transaction);
            return invalid_tx;
        }
        for (size_t i = 0; i < number_of_case; i++) {
            memory_state[i].new_value = NULL;
            memory_state[i].read = false;
        }
        transaction->memory_state = memory_state;
    }
    return (tx_t)transaction;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
    struct transaction* transaction = (struct transaction*) tx;
    if (transaction->is_read_only) {
        free_transaction(tx, shared);
        return true;
    }
    bool is_validated = validate_transaction(shared, tx);
    if (!is_validated) {
        free_transaction(tx, shared);
        return false;
    }
    // Propage writes to shared memory and release write locks
    //TO DO
   // propagate_writes(shared, tx);
    free_transaction(tx, shared);
    return is_validated;
}
//tx : transaction
//shared : region
void free_transaction(tx_t tx, shared_t shared) {
    struct transaction* transaction = (struct transaction*) tx;
    if(!transaction->is_read_only){
        //free each shared_memory_state new value pointer:
        for (size_t i = 0; i < tm_size(shared)/tm_align(shared); i++) {
           struct shared_memory_state* memory_state = &(transaction->memory_state[i]);
            if (memory_state->new_value != NULL) {
                free(memory_state->new_value);
            }
        }
        //free memory state
        free(transaction->memory_state);
    }
    //free the transaction
    free(transaction);
}
//To DO (is tm_validate)
bool validate_transaction(shared_t shared as(unused), tx_t tx as(unused)) {
    return false;
}


/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    size_t alignment = tm_align(shared);
    struct transaction* transaction = (struct transaction*) tx;
    struct region* region = (struct region*) shared;
    bool trans_is_read_only = transaction->is_read_only;
    //check if the size correspond to a multiple to alignment:
    if (size % alignment != 0) {
        free_transaction(tx, shared);
        return false;
    }
    size_t number_of_cases = size/alignment;
    //get the index were the transaction slot start in the main memory
    size_t start_index = get_index_start(shared, source);


    //copy local of the array of locks: (unsigned int) (store the lock and a version number)
    unsigned int* locks_array_local_copy = (unsigned int*) calloc(number_of_cases , sizeof(unsigned int));
    if (unlikely(!locks_array_local_copy)) {
        free_transaction(tx, shared);
        return false;
    }
    for (size_t i = 0; i < number_of_cases; i++) {
        size_t lock_index =  i + start_index;
        atomic_uint* versioned_lock_i = &(region->versioned_locks[lock_index]);
        unsigned int lock_i = atomic_load(versioned_lock_i);
        locks_array_local_copy[i] = lock_i;
        if (is_lock(lock_i) || extract_version(lock_i) > (transaction->rv)) {
            free(locks_array_local_copy);
            free_transaction(tx, shared);
            return false;
        }
    }

    //the pointer to the first case we want to read
    const void* what_we_want_to_read = source;
    //pointer to the location where we want to write the result of the read
    void* where_we_want_to_save_the_read = target;

    //now we iterate over the cases:
    for (size_t i = start_index; i < start_index + number_of_cases; i++) {
        //we create a local variable memory_state
        struct shared_memory_state* memory_state = NULL;
        if (!trans_is_read_only) {
            //we get the local memory_state of the transaction if it has one (not read only)
            memory_state = &(transaction->memory_state[i]);
        }
        if (!trans_is_read_only && memory_state->new_value != NULL) {
            //If the transaction has already written something one time: we copy the local value (and not the global, as we
            //would write this in the global memory:
            // Copies "numBytes" bytes from address "from" to address "to" :  memcpy(void *to, const void *from, size_t numBytes);
            memcpy(where_we_want_to_save_the_read, memory_state->new_value, alignment);
        } else {
           //copy the value from the global memory in the target (so its the read operation)
           //since we have not write anything else.
            memcpy(where_we_want_to_save_the_read, what_we_want_to_read, alignment);
        }
        if (!trans_is_read_only) {
            // specify that we have read the current value
            memory_state->read = true;
        }
        //we increment the pointeur (next case)
        what_we_want_to_read = alignment + what_we_want_to_read;
        where_we_want_to_save_the_read = alignment + where_we_want_to_save_the_read;
    }
    bool validated = validate_the_read(shared, tx, source, start_index, number_of_cases, locks_array_local_copy);
    free((void*)locks_array_local_copy);
    if (!validated) {
        free_transaction(tx, shared);
        return false;
    }
    return true;
}

unsigned int extract_version(unsigned int versioned_lock) {
    //we gonna apply a trick here to get the version number (so remove the first bit)
    //create a number 00000---
    unsigned int a = 0u;
    //negative 111111----
    unsigned int neg_a = ~(a);
    //shift it of 1 to the left : 011111---
    unsigned int shift_neg_a  = neg_a >> 1;
    //return AND between the 011111 and versionlock (exemple 101011 -> 001011)
    return shift_neg_a & versioned_lock;
}


bool is_lock(unsigned int versioned_lock){
    //a = 00000--001
    unsigned int a = 1u; //sign bit??
    //shift a to the left for (unsigned int size -1) -> 1000---000
    unsigned int a_shift = a << (sizeof(a)*8-1);
    //AND operation between 1000--00 and versioned_lock
    return a_shift & versioned_lock;
}

//TO DO emmeler les arguments
bool validate_the_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t start_index, size_t nb_of_cases, unsigned int* locks_array_previous) {
    if (shared == NULL || (void*)tx == NULL || source == NULL || locks_array_previous == NULL) {
        return false;
    }
    assert(sizeof(locks_array_previous)/sizeof(unsigned int*) == nb_of_cases);
    struct region* region = (struct region*) shared;
    struct transaction* transaction = (struct transaction*) tx;

    for (size_t i = 0; i < nb_of_cases; i++) {
        unsigned int lock_previous = locks_array_previous[i];
        if(is_lock(lock_previous)){
            return false;
        }
        //assert(!is_lock(lock_previous));
        size_t lock_idx = start_index + i;
        unsigned int version_lock_current = atomic_load(&(region->versioned_locks[lock_idx]));
        if (is_lock(version_lock_current)) {
            return false;
        }
        unsigned int previous_version = extract_version(lock_previous);
        unsigned int version_current = extract_version(version_lock_current);
        if (previous_version != version_current || version_current > (transaction->rv)) {
            return false;
        }
    }
    return true;
}

// look at the index of memory_state we want to write at.
size_t get_index_start(shared_t shared as(unused), void const* memory_state_ptr as(unused)) {
    size_t alignment = tm_align(shared);
    void* start = tm_start(shared);
    size_t start_index = (memory_state_ptr - start) / alignment;
    return start_index;
}


/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    struct transaction* transaction = (struct transaction*) tx;
    struct region* region = (struct region*) shared;
    //security checks:
    assert(!transaction->is_read_only);
    if (size % tm_align(shared) != 0) {
        free_transaction(tx, shared);
        return false;
    }
    //get the number of slots:
    size_t number_of_cases = size/tm_align(shared);
    //get the index were the transaction slot start in the main memory
    size_t start_index = get_index_start(shared, source);
    //the pointer to the source (what we want to write)
    const void* what_we_want_to_write = source;
    //the pointer to the source in the global memory (where we want to write)
    //not used for one segment
    void* where_we_want_to_write = target;
    //now we iterate over the cases:
    for (size_t i = start_index; i < start_index + number_of_cases; i++) {
        //we get the local memory_state of the transaction (has one because if not read only)
        struct shared_memory_state* memory_state = &(transaction->memory_state[i]);
        if (memory_state->new_value != NULL) {
            //If the transaction has already written something one time: we copy the local value (and not the global, as we
            //would write this in the global memory:
            // memcpy(void *to, const void *from, size_t numBytes);
            memcpy(memory_state->new_value, what_we_want_to_write, tm_align(shared));
        } else {
            //otherwise we alloc a place for the value we want to write
            memory_state->new_value = malloc(tm_align(shared));
            if (unlikely(!(memory_state->new_value))) {
                free_transaction(tx, shared);
                return false;
            }
            // Copies "numBytes" bytes from address "from" to address "to" :  memcpy(void *to, const void *from, size_t numBytes);
            memcpy(memory_state->new_value, what_we_want_to_write, tm_align(shared));
        }
        // increment the source pointer of what we want to write
        what_we_want_to_write = tm_align(shared) + what_we_want_to_write;
    }
    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t shared as(unused), tx_t tx as(unused), size_t size as(unused), void** target as(unused)) {
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target as(unused)) {
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
