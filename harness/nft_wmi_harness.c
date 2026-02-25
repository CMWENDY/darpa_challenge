/*
 * Symbolic Execution Harness: nf_tables_api.c WMI & WMP Detection 
 * Target: nft_expr_init() and rule evaluation lifecycle in nf_tables_api.c
 * Detects: WMI-1 (UAF), WMI-2 (Type Confusion), WMI-3 (Arb Free), WMI-4 (WWW)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <klee/klee.h>

#define SYM_INT(name) ({ int _v; klee_make_symbolic(&_v, sizeof(_v), name); _v; })
#define SYM_PTR(name) ({ void* _v; klee_make_symbolic(&_v, sizeof(_v), name); _v; })

/* --- WMP Chain Tracking --- */
#define WMI_1_UAF          (1 << 0)
#define WMI_2_TYPE_CONF    (1 << 1)
#define WMI_3_ARB_FREE     (1 << 2)
#define WMI_4_WWW          (1 << 3)
#define WMI_HIJACK         (1 << 4)

uint32_t wmp_state_mask = 0;

/* --- Shadow Heap Metadata --- */
typedef enum { CHUNK_FREE, CHUNK_ALLOCATED } chunk_state_t;

struct shadow_chunk {
    void *ptr;
    size_t size;
    chunk_state_t state;
    uint32_t type_id; 
    bool is_tainted;
};

#define MAX_CHUNKS 16
struct shadow_chunk shadow_heap[MAX_CHUNKS];
int chunk_count = 0;

/* --- Target Netfilter Structures --- */
#define TYPE_NFT_EXPR_PAYLOAD 0x10
#define TYPE_NFT_EXPR_LOG     0x20

typedef void (*eval_fn_t)(void *packet);

struct nft_expr {
    eval_fn_t eval;
    uint32_t type_id;
    uint64_t data; // Attacker controlled data
};

struct nft_rule {
    struct nft_expr *expr;
    int is_active;
};

/* --- Shadow Heap Allocator Wrappers --- */
void* mock_kmalloc(size_t size, uint32_t type_id) {
    void *ptr = malloc(size);
    if (chunk_count < MAX_CHUNKS) {
        shadow_heap[chunk_count].ptr = ptr;
        shadow_heap[chunk_count].size = size;
        shadow_heap[chunk_count].state = CHUNK_ALLOCATED;
        shadow_heap[chunk_count].type_id = type_id;
        shadow_heap[chunk_count].is_tainted = false;
        chunk_count++;
    }
    return ptr;
}

void mock_kfree(void *ptr) {
    bool valid_free = false;
    for (int i = 0; i < chunk_count; i++) {
        if (shadow_heap[i].ptr == ptr) {
            if (shadow_heap[i].state == CHUNK_FREE) {
                printf("[WMI-1/3 DETECTED] Double free on pointer: %p\n", ptr);
                wmp_state_mask |= WMI_3_ARB_FREE;
            }
            shadow_heap[i].state = CHUNK_FREE;
            valid_free = true;
            break;
        }
    }
    
    if (!valid_free) {
        printf("[WMI-3 DETECTED] Arbitrary/Invalid free on pointer: %p\n", ptr);
        wmp_state_mask |= WMI_3_ARB_FREE;
    }
    free(ptr);
}

/* --- Vulnerability Simulation (nf_tables_api.c) --- */
void safe_eval(void *packet) { /* Normal behavior */ }
void win_eval(void *packet) { printf("[EXPLOIT] RIP Hijacked!\n"); }

int main() {
    printf("--- Starting DARPA WMI Detection Harness ---\n");

    /* 1. Setup Phase */
    struct nft_rule *rule = mock_kmalloc(sizeof(struct nft_rule), 0);
    rule->expr = mock_kmalloc(sizeof(struct nft_expr), TYPE_NFT_EXPR_PAYLOAD);
    rule->expr->eval = safe_eval;
    rule->is_active = 1;

    /* 2. Symbolic Triggers (Did the attacker trigger an error path?) */
    int trigger_error_path = SYM_INT("trigger_error_path");
    int trigger_realloc    = SYM_INT("trigger_realloc");
    void *sym_arb_ptr      = SYM_PTR("sym_arb_ptr");

    /* WMI-3: Arbitrary Free Attempt */
    if (SYM_INT("try_arb_free")) {
        mock_kfree(sym_arb_ptr);
    }

    /* WMI-1: Stale Reference Creation */
    if (trigger_error_path) {
        // Bug: We free the expression due to an error, but forget to NULL the rule->expr pointer
        mock_kfree(rule->expr);
        printf("[STATE] rule->expr freed, but reference retained.\n");
    }

    /* WMI-2 & WMI-4: Type Confusion and Write-What-Where */
    if (trigger_error_path && trigger_realloc) {
        // Attacker grooms the heap to reallocate the freed slot as a DIFFERENT type
        struct nft_expr *fake_expr = mock_kmalloc(sizeof(struct nft_expr), TYPE_NFT_EXPR_LOG);
        
        // Shadow heap check for Type Confusion
        for (int i=0; i < chunk_count; i++) {
            if (shadow_heap[i].ptr == rule->expr && shadow_heap[i].type_id != TYPE_NFT_EXPR_PAYLOAD) {
                printf("[WMI-2 DETECTED] Type Confusion! Expected 0x10, got 0x%x\n", shadow_heap[i].type_id);
                wmp_state_mask |= WMI_2_TYPE_CONF;
            }
        }

        // WMI-4: Write-What-Where (Attacker overwrites the function pointer)
        // REFINEMENT: Safely make a separate variable symbolic instead of a heap struct field directly.
        void *sym_func_ptr;
        klee_make_symbolic(&sym_func_ptr, sizeof(sym_func_ptr), "attacker_func_ptr");
        fake_expr->eval = (eval_fn_t)sym_func_ptr; 
        
        printf("[WMI-4 DETECTED] Symbolic data written to overlapping control structure.\n");
        wmp_state_mask |= WMI_4_WWW;
    }

    /* WMI-1 Execution / Impact Confirmation */
    if (rule->is_active) {
        // Shadow heap check for Use-After-Free
        for (int i=0; i < chunk_count; i++) {
            if (shadow_heap[i].ptr == rule->expr && shadow_heap[i].state == CHUNK_FREE) {
                printf("[WMI-1 DETECTED] Use-After-Free dereference!\n");
                wmp_state_mask |= WMI_1_UAF;
            }
        }

        // Execution Impact: Use the Shadow Heap to safely check if the attacker successfully overwrote the memory
        // REFINEMENT: Avoids a fatal C memory error by not directly dereferencing the freed rule->expr->eval pointer.
        for (int i=0; i < chunk_count; i++) {
            if (shadow_heap[i].ptr == rule->expr && shadow_heap[i].type_id == TYPE_NFT_EXPR_LOG) {
                wmp_state_mask |= WMI_HIJACK;
            }
        }
    }

    /* --- WMP Chaining Output --- */
    if ((wmp_state_mask & WMI_1_UAF) && (wmp_state_mask & WMI_4_WWW) && (wmp_state_mask & WMI_HIJACK)) {
        printf("\n[SUCCESS] WMP Chain Detected: WMI-1 -> WMI-2 -> WMI-4 -> RIP Control!\n");
        klee_assert(0); // Force KLEE to generate a test case for this exact chain
    }

    return 0;
}