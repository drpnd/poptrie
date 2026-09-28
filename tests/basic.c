/*_
 * Copyright (c) 2014-2016 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 */

#include "../poptrie.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


/* Macro for testing */
#define TEST_FUNC(str, func, ret)                \
    do {                                         \
        printf("%s: ", str);                     \
        if ( 0 == func() ) {                     \
            printf("passed");                    \
        } else {                                 \
            printf("failed");                    \
            ret = -1;                            \
        }                                        \
        printf("\n");                            \
    } while ( 0 )

#define TEST_PROGRESS()                              \
    do {                                             \
        printf(".");                                 \
        fflush(stdout);                              \
    } while ( 0 )


/*
 * Initialization test
 */
static int
test_init(void)
{
    struct poptrie *poptrie;

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    TEST_PROGRESS();

    /* Release */
    poptrie_release(poptrie);

    return 0;
}

static int
test_lookup(void)
{
    struct poptrie *poptrie;
    int ret;
    void *nexthop;

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* No route must be found */
    if ( NULL != poptrie_lookup(poptrie, 0x1c001203) ) {
        return -1;
    }

    /* Route add */
    nexthop = (void *)1234;
    ret = poptrie_route_add(poptrie, 0x1c001200, 24, nexthop);
    if ( ret < 0 ) {
        /* Failed to add */
        return -1;
    }
    if ( nexthop != poptrie_lookup(poptrie, 0x1c001203) ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Route update */
    nexthop = (void *)5678;
    ret = poptrie_route_update(poptrie, 0x1c001200, 24, nexthop);
    if ( ret < 0 ) {
        /* Failed to update */
        return -1;
    }
    if ( nexthop != poptrie_lookup(poptrie, 0x1c001203) ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Route delete */
    ret = poptrie_route_del(poptrie, 0x1c001200, 24);
    if ( ret < 0 ) {
        /* Failed to update */
        return -1;
    }
    if ( NULL != poptrie_lookup(poptrie, 0x1c001203) ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Release */
    poptrie_release(poptrie);

    return 0;
}

static int
test_lookup2(void)
{
    struct poptrie *poptrie;
    int ret;
    void *nexthop;

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* No route must be found */
    if ( NULL != poptrie_lookup(poptrie, 0x1c001203) ) {
        return -1;
    }

    /* Route add */
    nexthop = (void *)1234;
    ret = poptrie_route_add(poptrie, 0x1c001203, 32, nexthop);
    if ( ret < 0 ) {
        /* Failed to add */
        return -1;
    }
    if ( nexthop != poptrie_lookup(poptrie, 0x1c001203) ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Route update */
    nexthop = (void *)5678;
    ret = poptrie_route_update(poptrie, 0x1c001203, 32, nexthop);
    if ( ret < 0 ) {
        /* Failed to update */
        return -1;
    }
    if ( nexthop != poptrie_lookup(poptrie, 0x1c001203) ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Route delete */
    ret = poptrie_route_del(poptrie, 0x1c001203, 32);
    if ( ret < 0 ) {
        /* Failed to update */
        return -1;
    }
    if ( NULL != poptrie_lookup(poptrie, 0x1c001203) ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Release */
    poptrie_release(poptrie);

    return 0;
}

static int
test_lookup_linx(void)
{
    struct poptrie *poptrie;
    FILE *fp;
    char buf[4096];
    int prefix[4];
    int prefixlen;
    int nexthop[4];
    int ret;
    u32 addr1;
    u32 addr2;
    u64 i;

    /* Load from the linx file */
    fp = fopen("tests/linx-rib.20141217.0000-p46.txt", "r");
    if ( NULL == fp ) {
        return -1;
    }

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* Load the full route */
    i = 0;
    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%d.%d.%d.%d/%d %d.%d.%d.%d", &prefix[0], &prefix[1],
                     &prefix[2], &prefix[3], &prefixlen, &nexthop[0],
                     &nexthop[1], &nexthop[2], &nexthop[3]);
        if ( ret < 0 ) {
            return -1;
        }

        /* Convert to u32 */
        addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
            + ((u32)prefix[2] << 8) + (u32)prefix[3];
        addr2 = ((u32)nexthop[0] << 24) + ((u32)nexthop[1] << 16)
            + ((u32)nexthop[2] << 8) + (u32)nexthop[3];

        /* Add an entry */
        ret = poptrie_route_add(poptrie, addr1, prefixlen, (void *)(u64)addr2);
        if ( ret < 0 ) {
            return -1;
        }
        if ( 0 == i % 10000 ) {
            TEST_PROGRESS();
        }
        i++;
    }

    for ( i = 0; i < 0x100000000ULL; i++ ) {
        if ( 0 == i % 0x10000000ULL ) {
            TEST_PROGRESS();
        }
        if ( poptrie_lookup(poptrie, i) != poptrie_rib_lookup(poptrie, i) ) {
            return -1;
        }
    }

    /* Release */
    poptrie_release(poptrie);

    /* Close */
    fclose(fp);

    return 0;
}

static int
test_lookup_linx_update(void)
{
    struct poptrie *poptrie;
    FILE *fp;
    char buf[4096];
    int prefix[4];
    int prefixlen;
    int nexthop[4];
    int ret;
    u32 addr1;
    u32 addr2;
    u64 i;
    int tm;
    char type;

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* Load from the linx file */
    fp = fopen("tests/linx-rib.20141217.0000-p52.txt", "r");
    if ( NULL == fp ) {
        return -1;
    }

    /* Load the full route */
    i = 0;
    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%d.%d.%d.%d/%d %d.%d.%d.%d", &prefix[0], &prefix[1],
                     &prefix[2], &prefix[3], &prefixlen, &nexthop[0],
                     &nexthop[1], &nexthop[2], &nexthop[3]);
        if ( ret < 0 ) {
            return -1;
        }

        /* Convert to u32 */
        addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
            + ((u32)prefix[2] << 8) + (u32)prefix[3];
        addr2 = ((u32)nexthop[0] << 24) + ((u32)nexthop[1] << 16)
            + ((u32)nexthop[2] << 8) + (u32)nexthop[3];

        /* Add an entry */
        ret = poptrie_route_add(poptrie, addr1, prefixlen, (void *)(u64)addr2);
        if ( ret < 0 ) {
            return -1;
        }
        if ( 0 == i % 10000 ) {
            TEST_PROGRESS();
        }
        i++;
    }

    /* Close */
    fclose(fp);

    /* Load from the update file */
    fp = fopen("tests/linx-update.20141217.0000-p52.txt", "r");
    if ( NULL == fp ) {
        return -1;
    }

    /* Load the full route */
    i = 0;
    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%d %c %d.%d.%d.%d/%d %d.%d.%d.%d", &tm, &type,
                     &prefix[0], &prefix[1], &prefix[2], &prefix[3], &prefixlen,
                     &nexthop[0], &nexthop[1], &nexthop[2], &nexthop[3]);
        if ( ret < 0 ) {
            return -1;
        }

        /* Convert to u32 */
        addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
            + ((u32)prefix[2] << 8) + (u32)prefix[3];
        addr2 = ((u32)nexthop[0] << 24) + ((u32)nexthop[1] << 16)
            + ((u32)nexthop[2] << 8) + (u32)nexthop[3];

        if ( 'a' == type ) {
            /* Add an entry (use update) */
            ret = poptrie_route_update(poptrie, addr1, prefixlen,
                                       (void *)(u64)addr2);
            if ( ret < 0 ) {
                return -1;
            }
        } else if ( 'w' == type ) {
            /* Delete an entry */
            ret = poptrie_route_del(poptrie, addr1, prefixlen);
            if ( ret < 0 ) {
                /* Ignore any errors */
            }
        }
        if ( 0 == i % 1000 ) {
            TEST_PROGRESS();
        }
        i++;
    }

    /* Close */
    fclose(fp);

    for ( i = 0; i < 0x100000000ULL; i++ ) {
        if ( 0 == i % 0x10000000ULL ) {
            TEST_PROGRESS();
        }
        if ( poptrie_lookup(poptrie, i) != poptrie_rib_lookup(poptrie, i) ) {
            return -1;
        }
    }

    /* Release */
    poptrie_release(poptrie);

    return 0;
}


/*
 * Test FIB reference counting for route_add, route_change, route_update, and
 * route_del error paths (regression test for FIB reference leak).
 */
static int
test_fib_refcount(void)
{
    struct poptrie *poptrie;
    int ret;
    int i;
    int used;

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* Add a route */
    ret = poptrie_route_add(poptrie, 0x0a000000, 8, (void *)1);
    if ( ret < 0 ) {
        return -1;
    }

    /* route_change on a non-existent route must fail and not leak FIB */
    ret = poptrie_route_change(poptrie, 0x0b000000, 8, (void *)2);
    if ( 0 == ret ) {
        return -1;
    }

    /* route_add duplicate must fail and not leak FIB */
    ret = poptrie_route_add(poptrie, 0x0a000000, 8, (void *)3);
    if ( 0 == ret ) {
        return -1;
    }

    /* Count FIB entries in use */
    used = 0;
    for ( i = 0; i < poptrie->fib.sz; i++ ) {
        if ( poptrie->fib.entries[i].refs > 0 ) {
            used++;
        }
    }
    /* Expect: 1 (default NULL) + 1 (nexthop=1) = 2 */
    if ( 2 != used ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Release */
    poptrie_release(poptrie);

    return 0;
}

/*
 * Test longest prefix match with nested prefixes of varying depths.
 */
static int
test_lpm(void)
{
    struct poptrie *poptrie;
    int ret;

    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* Build a tree with routes at various prefix lengths */
    ret = poptrie_route_add(poptrie, 0x0a000000, 8, (void *)1);    /* 10.0.0.0/8 */
    if ( ret < 0 ) return -1;
    ret = poptrie_route_add(poptrie, 0x0a010000, 16, (void *)2);   /* 10.1.0.0/16 */
    if ( ret < 0 ) return -1;
    ret = poptrie_route_add(poptrie, 0x0a010100, 24, (void *)3);   /* 10.1.1.0/24 */
    if ( ret < 0 ) return -1;
    ret = poptrie_route_add(poptrie, 0x0a010200, 24, (void *)4);   /* 10.1.2.0/24 */
    if ( ret < 0 ) return -1;
    ret = poptrie_route_add(poptrie, 0x0a010101, 32, (void *)5);   /* 10.1.1.1/32 */
    if ( ret < 0 ) return -1;
    TEST_PROGRESS();

    /* Check longest prefix match */
    if ( (void *)5 != poptrie_lookup(poptrie, 0x0a010101) ) return -1; /* 10.1.1.1 -> /32 */
    if ( (void *)3 != poptrie_lookup(poptrie, 0x0a010102) ) return -1; /* 10.1.1.2 -> /24 */
    if ( (void *)4 != poptrie_lookup(poptrie, 0x0a010200) ) return -1; /* 10.1.2.0 -> /24 */
    if ( (void *)2 != poptrie_lookup(poptrie, 0x0a010300) ) return -1; /* 10.1.3.0 -> /16 */
    if ( (void *)1 != poptrie_lookup(poptrie, 0x0a020000) ) return -1; /* 10.2.0.0 -> /8 */
    if ( NULL != poptrie_lookup(poptrie, 0x0b000000) ) return -1;      /* 11.0.0.0 -> NULL */
    TEST_PROGRESS();

    /* Delete a more specific route and check fallback */
    ret = poptrie_route_del(poptrie, 0x0a010101, 32);
    if ( ret < 0 ) return -1;
    if ( (void *)3 != poptrie_lookup(poptrie, 0x0a010101) ) return -1; /* now /24 */

    /* Delete /24 and check fallback to /16 */
    ret = poptrie_route_del(poptrie, 0x0a010100, 24);
    if ( ret < 0 ) return -1;
    if ( (void *)2 != poptrie_lookup(poptrie, 0x0a010100) ) return -1; /* now /16 */
    TEST_PROGRESS();

    /* Change nexthop on existing route */
    ret = poptrie_route_change(poptrie, 0x0a000000, 8, (void *)100);
    if ( ret < 0 ) return -1;
    if ( (void *)100 != poptrie_lookup(poptrie, 0x0a020000) ) return -1;
    TEST_PROGRESS();

    /* route_update on non-existent should add */
    ret = poptrie_route_update(poptrie, 0x0c000000, 8, (void *)200);
    if ( ret < 0 ) return -1;
    if ( (void *)200 != poptrie_lookup(poptrie, 0x0c000000) ) return -1;
    TEST_PROGRESS();

    poptrie_release(poptrie);
    return 0;
}

/*
 * Load the LINX RIB and verify correctness using sampled lookups (prefix
 * addresses, boundary addresses, and random addresses).  This is much faster
 * than the full 2^32 scan in test_lookup_linx but still exercises the core
 * lookup path against real data.
 */
static int
test_lookup_linx_sampled(void)
{
    struct poptrie *poptrie;
    FILE *fp;
    char buf[4096];
    int prefix[4];
    int prefixlen;
    int nexthop[4];
    int ret;
    u32 addr1;
    u32 addr2;
    u64 i;
    u64 fails;
    u64 tested;

    typedef struct { u32 addr; int len; u32 nh; } route_t;
    route_t *routes = NULL;
    int nroutes = 0;
    int cap = 0;

    /* Load from the linx file */
    fp = fopen("tests/linx-rib.20141217.0000-p46.txt", "r");
    if ( NULL == fp ) {
        return -1;
    }

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        fclose(fp);
        return -1;
    }

    /* Load the full route */
    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%d.%d.%d.%d/%d %d.%d.%d.%d", &prefix[0], &prefix[1],
                     &prefix[2], &prefix[3], &prefixlen, &nexthop[0],
                     &nexthop[1], &nexthop[2], &nexthop[3]);
        if ( ret < 0 || ret < 10 ) {
            continue;
        }

        addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
            + ((u32)prefix[2] << 8) + (u32)prefix[3];
        addr2 = ((u32)nexthop[0] << 24) + ((u32)nexthop[1] << 16)
            + ((u32)nexthop[2] << 8) + (u32)nexthop[3];

        ret = poptrie_route_add(poptrie, addr1, prefixlen, (void *)(u64)addr2);
        if ( ret < 0 ) {
            poptrie_route_update(poptrie, addr1, prefixlen, (void *)(u64)addr2);
        }

        if ( nroutes >= cap ) {
            cap = cap ? cap * 2 : 65536;
            routes = (route_t *)realloc(routes, cap * sizeof(route_t));
        }
        routes[nroutes].addr = addr1;
        routes[nroutes].len = prefixlen;
        routes[nroutes].nh = addr2;
        nroutes++;
    }
    fclose(fp);
    TEST_PROGRESS();

    /* Test 1: Look up each prefix address */
    fails = 0;
    for ( i = 0; i < (u64)nroutes; i++ ) {
        if ( poptrie_lookup(poptrie, routes[i].addr)
             != poptrie_rib_lookup(poptrie, routes[i].addr) ) {
            fails++;
        }
    }
    if ( fails > 0 ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Test 2: Look up boundary addresses (just before and after each prefix) */
    fails = 0;
    tested = 0;
    for ( i = 0; i < (u64)nroutes && tested < 100000; i++ ) {
        u32 mask;
        u32 base;
        u32 end;
        if ( routes[i].len == 0 || routes[i].len >= 32 ) {
            continue;
        }
        mask = 0xFFFFFFFF << (32 - routes[i].len);
        base = routes[i].addr & mask;
        end = base | ~mask;
        if ( base > 0 ) {
            if ( poptrie_lookup(poptrie, base - 1)
                 != poptrie_rib_lookup(poptrie, base - 1) ) {
                fails++;
            }
            tested++;
        }
        if ( end < 0xFFFFFFFF ) {
            if ( poptrie_lookup(poptrie, end + 1)
                 != poptrie_rib_lookup(poptrie, end + 1) ) {
                fails++;
            }
            tested++;
        }
    }
    if ( fails > 0 ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Test 3: Random addresses */
    fails = 0;
    srand(42);
    for ( i = 0; i < 1000000; i++ ) {
        u32 addr = ((u32)rand() << 16) | rand();
        if ( poptrie_lookup(poptrie, addr)
             != poptrie_rib_lookup(poptrie, addr) ) {
            fails++;
        }
    }
    if ( fails > 0 ) {
        return -1;
    }
    TEST_PROGRESS();

    free(routes);
    poptrie_release(poptrie);

    return 0;
}

/*
 * Load the LINX RIB (p52), apply updates, and verify correctness using
 * sampled lookups.  Faster than the full 2^32 scan in
 * test_lookup_linx_update.
 */
static int
test_lookup_linx_update_sampled(void)
{
    struct poptrie *poptrie;
    FILE *fp;
    char buf[4096];
    int prefix[4];
    int prefixlen;
    int nexthop[4];
    int ret;
    u32 addr1;
    u32 addr2;
    u64 i;
    u64 fails;
    int tm;
    char type;

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* Load from the linx file */
    fp = fopen("tests/linx-rib.20141217.0000-p52.txt", "r");
    if ( NULL == fp ) {
        return -1;
    }

    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%d.%d.%d.%d/%d %d.%d.%d.%d", &prefix[0], &prefix[1],
                     &prefix[2], &prefix[3], &prefixlen, &nexthop[0],
                     &nexthop[1], &nexthop[2], &nexthop[3]);
        if ( ret < 0 || ret < 10 ) {
            continue;
        }

        addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
            + ((u32)prefix[2] << 8) + (u32)prefix[3];
        addr2 = ((u32)nexthop[0] << 24) + ((u32)nexthop[1] << 16)
            + ((u32)nexthop[2] << 8) + (u32)nexthop[3];

        ret = poptrie_route_add(poptrie, addr1, prefixlen, (void *)(u64)addr2);
        if ( ret < 0 ) {
            poptrie_route_update(poptrie, addr1, prefixlen, (void *)(u64)addr2);
        }
    }
    fclose(fp);
    TEST_PROGRESS();

    /* Load from the update file */
    fp = fopen("tests/linx-update.20141217.0000-p52.txt", "r");
    if ( NULL == fp ) {
        return -1;
    }

    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%d %c %d.%d.%d.%d/%d %d.%d.%d.%d", &tm, &type,
                     &prefix[0], &prefix[1], &prefix[2], &prefix[3], &prefixlen,
                     &nexthop[0], &nexthop[1], &nexthop[2], &nexthop[3]);
        if ( ret < 0 || ret < 11 ) {
            continue;
        }

        addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
            + ((u32)prefix[2] << 8) + (u32)prefix[3];
        addr2 = ((u32)nexthop[0] << 24) + ((u32)nexthop[1] << 16)
            + ((u32)nexthop[2] << 8) + (u32)nexthop[3];

        if ( 'a' == type ) {
            poptrie_route_update(poptrie, addr1, prefixlen, (void *)(u64)addr2);
        } else if ( 'w' == type ) {
            poptrie_route_del(poptrie, addr1, prefixlen);
        }
    }
    fclose(fp);
    TEST_PROGRESS();

    /* Verify with random lookups */
    fails = 0;
    srand(42);
    for ( i = 0; i < 2000000; i++ ) {
        u32 addr = ((u32)rand() << 16) | rand();
        if ( poptrie_lookup(poptrie, addr)
             != poptrie_rib_lookup(poptrie, addr) ) {
            fails++;
        }
    }
    if ( fails > 0 ) {
        return -1;
    }
    TEST_PROGRESS();

    poptrie_release(poptrie);

    return 0;
}

/*
 * Main routine for the basic test
 */
int
main(int argc, const char *const argv[])
{
    int ret;

    ret = 0;

    /* Run tests */
    TEST_FUNC("init", test_init, ret);
    TEST_FUNC("lookup", test_lookup, ret);
    TEST_FUNC("lookup2", test_lookup2, ret);
    TEST_FUNC("fib_refcount", test_fib_refcount, ret);
    TEST_FUNC("lpm", test_lpm, ret);
    TEST_FUNC("lookup_linx_sampled", test_lookup_linx_sampled, ret);
    TEST_FUNC("lookup_linx_update_sampled", test_lookup_linx_update_sampled, ret);
    TEST_FUNC("lookup_fullroute", test_lookup_linx, ret);
    TEST_FUNC("lookup_fullroute_update", test_lookup_linx_update, ret);

    return ret;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
