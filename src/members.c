#include "members.h"

#include <stdlib.h>
#include <string.h>

int rank_cmp(double since_a, const uint8_t *id_a, double since_b, const uint8_t *id_b)
{
    if (since_a < since_b)
        return -1;
    if (since_a > since_b)
        return 1;
    return memcmp(id_a, id_b, MC_ID_LEN);
}

member *mt_find(member_table *t, const uint8_t id[MC_ID_LEN])
{
    for (int i = 0; i < MAX_MEMBERS; i++)
        if (t->m[i].used && memcmp(t->m[i].id, id, MC_ID_LEN) == 0)
            return &t->m[i];
    return NULL;
}

member *mt_add(member_table *t, const uint8_t id[MC_ID_LEN])
{
    for (int i = 0; i < MAX_MEMBERS; i++) {
        if (!t->m[i].used) {
            memset(&t->m[i], 0, sizeof(member));
            t->m[i].used = 1;
            memcpy(t->m[i].id, id, MC_ID_LEN);
            return &t->m[i];
        }
    }
    return NULL;
}

void mt_remove(member *m)
{
    EVP_PKEY_free(m->pub);
    memset(m, 0, sizeof(*m));
}

int mt_count(const member_table *t)
{
    int n = 0;
    for (int i = 0; i < MAX_MEMBERS; i++)
        n += t->m[i].used;
    return n;
}

int mt_is_banned(const member_table *t, const uint8_t id[MC_ID_LEN])
{
    for (int i = 0; i < t->nbanned; i++)
        if (memcmp(t->banned[i], id, MC_ID_LEN) == 0)
            return 1;
    return 0;
}

void mt_ban(member_table *t, const uint8_t id[MC_ID_LEN])
{
    if (mt_is_banned(t, id))
        return;
    if (t->nbanned == MAX_BANNED) { /* 满了覆盖最早的 */
        memmove(t->banned[0], t->banned[1], (MAX_BANNED - 1) * MC_ID_LEN);
        t->nbanned--;
    }
    memcpy(t->banned[t->nbanned++], id, MC_ID_LEN);
}

member *mt_first_admin(member_table *t)
{
    member *best = NULL;
    for (int i = 0; i < MAX_MEMBERS; i++) {
        member *m = &t->m[i];
        if (m->used && m->is_admin &&
            (!best || rank_cmp(m->since, m->id, best->since, best->id) < 0))
            best = m;
    }
    return best;
}

static int cmp_member_ptr(const void *a, const void *b)
{
    const member *x = *(const member *const *)a, *y = *(const member *const *)b;
    return rank_cmp(x->since, x->id, y->since, y->id);
}

int mt_sorted(member_table *t, member **out, int max)
{
    int n = 0;
    for (int i = 0; i < MAX_MEMBERS && n < max; i++)
        if (t->m[i].used)
            out[n++] = &t->m[i];
    qsort(out, (size_t)n, sizeof(member *), cmp_member_ptr);
    return n;
}
