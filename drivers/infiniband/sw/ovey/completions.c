#include <linux/completion.h>
#include <linux/list.h>
#include <linux/slab.h> // kmalloc

#include "completions.h"
#include "ovey.h"

atomic_t ovey_completion_counter = {
        .counter = 0
};

// global object
struct ovey_completion_chain ovey_completion_list;

struct ovey_completion_chain *ovey_completion_add_entry(void) {
    struct ovey_completion_chain * chain_node = kmalloc(sizeof (struct ovey_completion_chain), GFP_KERNEL);
    chain_node->req_id = ovey_get_next_completion_id();
    chain_node->completion_resolved = false;
    init_completion(&chain_node->completion);
    list_add_tail(&chain_node->list_item, &ovey_completion_list.list_item);
    // after list_add_tail!
    opr_info("added entry with completion id %lld to chain; new list size is %u, was %u; ptr=%px\n",
             chain_node->req_id,
             ovey_completion_size(),
             ovey_completion_size() - 1,
             chain_node
    );
    return chain_node;
}

struct ovey_completion_chain * ovey_completion_find_by_id(u64 id) {
    opr_info("ovey_completion_find_by_id(%lld)", id);
    struct ovey_completion_chain * curr;
    struct ovey_completion_chain * n;
    list_for_each_entry_safe(curr, n, &ovey_completion_list.list_item, list_item) {
        if (curr->req_id == id) {
            opr_info("found!");
            return curr;
        }
    }
    opr_info("NULL!");
    return NULL;
}

int ovey_completion_resolve_by_id(u64 completion_id) {
    opr_info("ovey_completion_resolve_by_id(%lld)!", completion_id);
    struct ovey_completion_chain * chain_node = ovey_completion_find_by_id(completion_id);
    if (chain_node == NULL) {
        opr_err("The completion chain doesn't know the element %lld\n", completion_id);
        return -EINVAL;
    }
    if (chain_node->completion_resolved) {
        opr_err("The completion chain item with id %lld is already resolved\n", completion_id);
        return -1;
    }
    opr_info("chain_node=%px\n", chain_node);
    complete(&chain_node->completion);
    chain_node->completion_resolved = true;
    return 0;
}

void ovey_completion_delete_entry(struct ovey_completion_chain * entry) {
    struct list_head * head = &ovey_completion_list.list_item;

    // Will update the pointers next and prev
    list_del(&entry->list_item);

    // after list_del
    opr_info("removed entry with completion id %lld from chain; new list size is %u, was %u\n",
             entry->req_id,
             ovey_completion_size(),
             ovey_completion_size() + 1
    );

    if (head == &entry->list_item) {
        opr_info("Prevented to delete/free main list item (statically allocated)");
        return;
    }

    // free the used memory of this item
    kfree(&entry->list_item);
}

void ovey_completion_clear(void) {
    struct list_head * head;
    struct ovey_completion_chain * curr;
    struct ovey_completion_chain * n;

    opr_info("ovey_completion_clear()");

    head = &ovey_completion_list.list_item;

    redo:
    list_for_each_entry_safe(curr, n, head, list_item) {
        opr_info("deleting entry with id=%lld, resolved=%s\n", curr->req_id, curr->completion_resolved ? "true" : "false");
        if (!curr->completion_resolved) {
            opr_err("completion of this entry is not resolved yet! Resolving it now!\n");
            ovey_completion_resolve_by_id(curr->req_id);
        }
        ovey_completion_delete_entry(curr);
        // I don't know another convenient solution
        // delete until no items are left
        goto redo;
    }

    // I think this should also be done at this point but I'm not 100% sure
    // better be safe
    head->prev = NULL;
    head->next = NULL;
}

unsigned ovey_completion_size(void) {
    unsigned counter = 0;
    struct ovey_completion_chain * curr;
    struct ovey_completion_chain * n;
    list_for_each_entry_safe(curr, n, &ovey_completion_list.list_item, list_item) {
        counter++;
    }
    return counter;
}

