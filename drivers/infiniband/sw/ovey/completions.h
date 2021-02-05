#ifndef _COMPLETIONS_H
#define _COMPLETIONS_H

extern atomic_t ovey_completion_counter;

static inline u64 ovey_get_next_completion_id(void) {
    return (u64) atomic_fetch_add(1, &ovey_completion_counter);
}

struct ovey_completion_chain {
    // linux double-linked list api
    // see https://www.oreilly.com/library/view/linux-device-drivers/0596000081/ch10s05.html
    struct list_head list_item;
    u64 req_id;
    // true or false; default false; true if daemon replied to it
    // not important; completion has already a "done" field
    //u8 resolved;
    struct completion completion;
    // False (0) or True(1) once en entry got marked as finished.
    // This must be an dedicated property. completion->done doesn't work
    // since it isn't a true/false boolean
    u8 completion_resolved: 1;
    // TODO add data that gets filled by daemon request
    //  like a union
};

// Each item of the list
extern struct ovey_completion_chain ovey_completion_list;

/**
 * Adds an entry to the chain and automatically assigns an id (completion id or request id) to it.
 * @return
 */
struct ovey_completion_chain * ovey_completion_add_entry(void);

/**
 * Returns 0 if a completion was resolved successfully are <0 if not.
 * @param completion_id completion id
 * @return 0 if a completion was resolved successfully are <0 if not
 */
int ovey_completion_resolve_by_id(u64 completion_id);

/**
 * Deletes an entry from the list.
 * @param entry
 */
void ovey_completion_delete_entry(struct ovey_completion_chain * entry);

/**
 * Clears the list with all items. It also checks if all items
 * are set to done.
 * @param entry
 */
void ovey_completion_clear(void);

/**
 * Returns the element count of items.
 * @return element count of items in the completion chain
 */
unsigned ovey_completion_size(void);

#endif  /* _COMPLETIONS_H */
