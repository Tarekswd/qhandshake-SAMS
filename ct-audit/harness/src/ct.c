/* Memcheck client requests (ctgrind technique, Langley 2010): secret bytes are marked "undefined", so memcheck
 * reports every conditional jump and memory address that depends on them. Outside Valgrind these are no-ops. */
#include <stddef.h>
#include <valgrind/memcheck.h>

void ct_poison(const void *p, size_t n) { VALGRIND_MAKE_MEM_UNDEFINED(p, n); }
void ct_unpoison(const void *p, size_t n) { VALGRIND_MAKE_MEM_DEFINED(p, n); }
/* Taint check: memcheck emits one "client check request" report if any byte is still undefined. Used on outputs
 * before declassifying them, to prove the secret really flowed through the code under test. */
void ct_check(const void *p, size_t n) { (void)VALGRIND_CHECK_MEM_IS_DEFINED(p, n); }
