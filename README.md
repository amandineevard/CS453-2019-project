# CS-453 - Course project

Your goal is to implement a Software Transactional Memory (STM).

The *real* goal is of course to get you a hands-on experience with actual concurrent programming.


## Layout of this repository

* `grading/` Directory containing the evaluation binary, for faster local testing.

   Section **How to write my own STM?** further details testing (and later submitting your code).

* `include/` C and C++ headers files that define the public interface of your STM.

* `template/` Template (in C) of _your_ implementation, but you're free to replace everything and write C++.

* `reference/` Reference, single lock-based implementation, that you have to "beat" to maximize your grade.

   Note that you are not allowed to write an implementation that is _equivalent_ to the reference.
   When in doubt, ask the TA right away for clarifications.

* `playground/` As its name suggests, _playground_ is to play with the C(++)11 atomics. We'll be using it (only) during at the end of the second present, when we will be implementing a simple mutex.


## What prior knowledge do I need?

Only basic C or C++ knowledge.

How to use the atomic libraries and the memory models of C11 and C++11 will be taught in the weekly project sessions.

### Useful resources

* [C/C++ reference](https://en.cppreference.com/w/)

  * [C11 atomic](https://en.cppreference.com/w/c/atomic)

  * [C++11 atomic](https://en.cppreference.com/w/cpp/atomic)

* [Preshing on Programming](http://preshing.com/archives/) - Stellar resources and facts about concurrent programming


## What is a STM?

* [This course](http://lpd.epfl.ch/site/education/ca_2019).

* The Art of Multiprocessor Programming - Chapter 18.

### Some implementations out there

* [TinySTM](https://github.com/patrickmarlier/tinystm) 

* [LibLTX](https://sourceforge.net/projects/libltx)

* [stmmap](https://github.com/skaphan/stmmap)

You may read and inspire from existing STM libraries, but it must be **your own code** that carries out transactions.


## Grading

* *Correctness* is a must.

   The executed transactions must satisfy three properties (see below). No correctness = no passing grade for the project.

* *Throughput* is to go from a passing grade to the maximum grade.

   Comparison of your implementation to the reference one. Metric: #transaction *commits* per second.

### Evaluation machine

* 2 (dual-socket) Intel(R) Xeon(R) 10-core CPU E5-2680 v2 at 2.80GHz (×2 hyperthreading => 40 virtual cores)

* 256 GB of RAM, so you can consider RAM "unlimited" in your implementation

* Operating system: GNU/Linux (distribution: Ubuntu 18.04 LTS)


## How to write my own STM?

1. Clone/download this repository.

2. Make a local copy of/rename the `template` directory with your SCIPER number (e.g. `$ cp -r template 123456`). Be aware `make` is sensitive to spaces in the path/names.

3. Complete or completely rewrite (your copy of) the template with **your own code**.

   1. Complete/rewrite your code; only the interface should be kept identical.

   2. Compile and test locally with: `path/to/directory/grading$ make build-libs run`.

   3. Send your code to the *measurement server* for testing on the *evaluation machine*.

   4. Repeat any of the previous steps until you are satisfied with correctness and performance.

### Sending your code for measurement

1. Zip your modified (copy of the) `template` directory.

2. Send your code for evaluation with the `submit.py` script.
```
usage: submit.py [-h] --uuid UUID [--host HOST] [--port PORT] [--force-update] [--download] zippath

positional arguments:
  zippath         Path to a zip file containing your library code,
                                  or that will be overwritten with '--download'

optional arguments:
  -h, --help      show this help message and exit
  --uuid UUID     Secret user unique identifier
  --host HOST     Server hostname
  --port PORT     Server TCP port
  --force-update  Update your submission to the server; no validation of the correctness of your submission will be performed
  --download      Download your submission currently kept for grading under 'zippath' (instead of submitting a new one);
                  if '--force-update' is used, a "swap" is performed
```

You can submit code as often as you want until the deadline.

Only the (correct) submission with the highest speedup will be stored persistently and considered for grading, so no need to resubmit your best implementation just before the deadline.
The TAs may still ask you to provide a copy of your best implementation though (possibly after the deadline), so do not delete anything before the end of the semester.

As an option from the `submit.py` script, you can force-replace your submission with another one.
Note that no compilation nor performance check is performed.
The submission script also allows you to download the submission considered for your grade, so you can make sure the system has the version you want it to keep.

### List of structures and functions to implement

The student may write her/his library either in C11 (and above) or C++11 (and above).

* The structure of your _shared memory region_ (i.e. `struct region` in `reference/tm.c`)

* `shared_t tm_create(size_t, size_t)`

* `void tm_destroy(shared_t)`

* `void* tm_start(shared_t)`

* `size_t tm_size(shared_t)`

* `size_t tm_align(shared_t)`

* `tx_t tm_begin(shared_t, bool)`

* `bool tm_end(shared_t, tx_t)`

* `bool tm_read(shared_t, tx_t, void const*, size_t, void*)`

* `bool tm_write(shared_t, tx_t, void const*, size_t, void*)`

* `alloc_t tm_alloc(shared_t, tx_t, size_t, void**)`

* `bool tm_free(shared_t, tx_t, void*)`

See the interface specification below for more information.


## Interface specification

### Overview and properties

To use this *Software Transactional Memory* (STM) library, the *user* (e.g. the `grading` tool) first creates a new shared memory region.
A **shared memory region** is a non-empty set of shared memory segments.
Shared memory region creation and destruction are respectively managed by `tm_create` and `tm_destroy`.
The content of the shared memory region is *only* accessed from inside a transaction, and *solely* by the use of the functions mentioned below.

A **transaction** consists of a sequence of `tm_read`, `tm_write`, `tm_alloc`, `tm_free` operations in a shared memory region, enclosed between a call to `tm_begin` and a call to `tm_end` (as well as any number of non-transactional operations in private memory).
A transaction is executed on one and only one shared memory region.
A transaction either *commits* its speculative updates to the shared memory region when `tm_end` is reached, or *aborts* its execution (discarding its speculative updates) at any time (see the reference).
When a transaction is aborted, the *user* (i.e. the `grading` tool for this project) is responsible for retrying the *same* transaction (i.e. *going back* to the same `tm_begin` call site).

Transactions executed on the same shared region must satisfy three properties:

* **Atomicity**

   All speculative memory updates of a transaction are either committed or discarded as a unit.

* **Consistency**

   A (pending) transaction observes its own modifications, e.g. a read following one or more writes observes the last value written in program order.
   Transactions appear to have been committed one at a time.

* **Isolation**

   No speculative memory update is visible outside of their transaction, until their transaction commits.

### Reference

Create (i.e. allocate + init) a new shared memory region, with one first, non-free-able allocated segment of the requested size and alignment.

* `shared_t tm_create(size_t size, size_t align);`

| Parameter | Description |
| :-------- | :---------- |
| `size` | Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment |
| `align` | Alignment (in bytes, must be a power of 2) that the shared memory region must support |

**Return:** Opaque shared memory region handle, `invalid_shared` on failure.

> **NB:** the requested alignment in that function will be the alignment assumed in every subsequent memory operation.

> **NB:** the first allocated segment must be initialized with 0.

&nbsp;

Destroy (i.e. clean-up + free) a given shared memory region.

* `void tm_destroy(shared_t shared);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region handle to destroy |

> **NB:** no concurrent call for the same shared memory region.

> **NB:** it is guaranteed that when this function is called the associated shared memory region has not been destroyed yet.

> **NB:** it is guaranteed that no transaction is running on the shared memory region when this function is called.

> **NB:** the first allocated segment, along with all the segments that were allocated with `tm_alloc` but not freed with `tm_free` at the time of the call, must be freed by this function.

&nbsp;

Return the start address of the first allocated segment in the shared memory region.

* `void* tm_start(shared_t shared);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region to query |

**Return:** Start address of the first allocated segment

> **NB:** this function can be called concurrently.

> **NB:** the returned address must be aligned on the shared region alignment.

> **NB:** this function never fails: it must always return the address of the first allocated segment, which is not free-able.

> **NB:** the start address returned must not be `NULL`.

&nbsp;

Return the size (in bytes) of the first allocated segment in the shared memory region.

* `size_t tm_size(shared_t shared);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region to query |

**Return:** First allocated segment size (in bytes)

> **NB:** this function can be called concurrently.

> **NB:** the returned size must be aligned on the shared region alignment.

> **NB:** this function never fails: it must always return the size of the first allocated segment, which is not free-able.

&nbsp;

Return the alignment (in bytes) of the memory accesses on given shared memory region.

* `size_t tm_align(shared_t shared);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region to query |

**Return:** Alignment used globally (in bytes)

> **NB:** this function can be called concurrently.

&nbsp;

Begin a new transaction on the given shared memory region.

* `tx_t tm_begin(shared_t shared, bool is_ro);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region to start a transaction on |
| `is_ro` | Whether the transaction will be read-only |

**Return:** Opaque transaction identifier, `invalid_tx` on failure

> **NB:** this function can be called concurrently.

> **NB:** there is no concept of nested transactions, i.e. one transaction started in another transaction.

> **NB:** if `is_ro` is set to true, only `tm_read` can be called in the begun transaction.

&nbsp;

End the given transaction.

* `bool tm_end(shared_t shared, tx_t tx);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region associated with the transaction |
| `tx` | Transaction to end |

**Return:** Whether the whole transaction committed

> **NB:** this function can be called concurrently, concurrent calls must be made with at least a different `shared` parameter or a different `tx` parameter.

> **NB:** this function will not be called by the *user* (e.g. the `grading` tool) when any of `tm_read`, `tm_write`, `tm_alloc`, `tm_free` notifies that the transaction was aborted.

&nbsp;

Read operation in the given transaction, source in the shared region and target in a private region.

* `bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region associated with the transaction |
| `tx` | Transaction to use |
| `source` | Source (aligned) start address (in shared memory) |
| `size` | Length to copy (in bytes) |
| `target` | Target (aligned) start address (in private memory) |

**Return:** Whether the whole transaction can continue

> **NB:** this function can be called concurrently, concurrent calls must be made with at least a different `shared` parameter or a different `tx` parameter.

> **NB:** the private buffer `target` can only be dereferenced for the duration of the call.

> **NB:** the length `size` must be a positive multiple of the shared memory region's alignment, otherwise the behavior is undefined.

> **NB:** the length of the buffers `source` and `target` must be at least `size`, otherwise the behavior is undefined.

> **NB:** the `source` and `target` addresses must be a positive multiple of the shared memory region's alignment, otherwise the behavior is undefined.

&nbsp;

Write operation in the given transaction, source in a private region and target in the shared region.

* `bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region associated with the transaction |
| `tx` | Transaction to use |
| `source` | Source (aligned) start address (in private memory) |
| `size` | Length to copy (in bytes) |
| `target` | Target (aligned) start address (in shared memory) |

**Return:** Whether the whole transaction can continue

> **NB:** this function can be called concurrently, concurrent calls must be made with at least a different `shared` parameter or a different `tx` parameter.

> **NB:** the private buffer `source` can only be dereferenced for the duration of the call.

> **NB:** the length `size` must be a positive multiple of the shared memory region's alignment, otherwise the behavior is undefined.

> **NB:** the length of the buffers `source` and `target` must be at least `size`, otherwise the behavior is undefined.

> **NB:** the `source` and `target` addresses must be a positive multiple of the shared memory region's alignment, otherwise the behavior is undefined.

&nbsp;

Memory allocation in the given transaction.

* `alloc_t tm_alloc(shared_t shared, tx_t tx, size_t size, void** target);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region associated with the transaction |
| `tx` | Transaction to use |
| `size` | Allocation requested size (in bytes) |
| `target` | Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment |

**Return:** One of: `success_alloc` (allocation was successful and transaction can continue), `abort_alloc` (transaction was aborted) and `nomem_alloc` (memory allocation failed)

> **NB:** this function can be called concurrently, concurrent calls must be made with at least a different `shared` parameter or a different `tx` parameter.

> **NB:** the pointer `target` can only be dereferenced for the duration of the call.

> **NB:** the value of `*target` is defined only if `success_alloc` was returned, and undefined otherwise.

> **NB:** the value of `*target` after the call if `success_alloc` was returned must not be `NULL`.

> **NB:** when `nomem_alloc` is returned, the transaction is not aborted.

> **NB:** the allocated segment must be initialized with 0.

> **NB:** only `tm_free` must be used to free the allocated segment.

> **NB:** the length `size` must be a positive multiple of the shared memory region's alignment, otherwise the behavior is undefined.

&nbsp;

Memory freeing in the given transaction.

* `bool tm_free(shared_t shared, tx_t tx, void* target);`

| Parameter | Description |
| :-------- | :---------- |
| `shared` | Shared memory region associated with the transaction |
| `tx` | Transaction to use |
| `target` | Address of the first byte of the previously allocated segment (with `tm_alloc` only) to deallocate |

**Return:** Whether the whole transaction can continue

> **NB:** this function can be called concurrently, concurrent calls must be made with at least a different `shared` parameter or a different `tx` parameter.

> **NB:** this function must not be called with `target` as the first allocated segment (the address returned by `tm_start`).
