/*_
 * Copyright (c) 2016 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 */

#include "../poptrie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
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

#define IPV6ADDR(w0, w1, w2, w3, w4, w5, w6, w7)                        \
    (((((__uint128_t)w0 << 48) | ((__uint128_t)w1 << 32)                \
       | ((__uint128_t)w2 << 16) | ((__uint128_t)w3)) << 64)            \
     | (((__uint128_t)w4 << 48) | ((__uint128_t)w5 << 32)               \
        | ((__uint128_t)w6 << 16) | ((__uint128_t)w7)))

static __inline__ __uint128_t
in6_addr_to_uint128(struct in6_addr *in6)
{
    __uint128_t a;
    int i;

    a = 0;
    for ( i = 0; i < 16; i++ ) {
        a <<= 8;
        a |= in6->s6_addr[i];
    }

    return a;
}


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
    __uint128_t addr;
    void *nexthop;

    /* Initialize */
    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* No route must be found */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x3, 1, 2, 3, 4);
    if ( NULL != poptrie6_lookup(poptrie, addr) ) {
        return -1;
    }

    /* Route add */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x0, 0, 0, 0, 0);
    nexthop = (void *)1234;
    ret = poptrie6_route_add(poptrie, addr, 48, nexthop);
    if ( ret < 0 ) {
        /* Failed to add */
        return -1;
    }
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x3, 1, 2, 3, 4);
    if ( nexthop != poptrie6_lookup(poptrie, addr) ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Route update */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x0, 0, 0, 0, 0);
    nexthop = (void *)5678;
    ret = poptrie6_route_update(poptrie, addr, 48, nexthop);
    if ( ret < 0 ) {
        /* Failed to update */
        return -1;
    }
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x3, 1, 2, 3, 4);
    if ( nexthop != poptrie6_lookup(poptrie, addr) ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Route delete */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x0, 0, 0, 0, 0);
    ret = poptrie6_route_del(poptrie, addr, 48);
    if ( ret < 0 ) {
        /* Failed to update */
        return -1;
    }
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x3, 1, 2, 3, 4);
    if ( NULL != poptrie6_lookup(poptrie, addr) ) {
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
    char v6str1[256];
    char v6str2[256];
    int prefix[8];
    int prefixlen;
    int nexthop[8];
    struct in6_addr v6addr;
    int ret;
    __uint128_t addr1;
    __uint128_t addr2;
    u64 i;

    /* Load from the linx file */
    fp = fopen("tests/linx-rib-ipv6.20141225.0000.p69.txt", "r");
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
        memset(prefix, 0, sizeof(int) * 8);
        memset(nexthop, 0, sizeof(int) * 8);

        ret = sscanf(buf, "%255[^'/']/%d %255s", v6str1, &prefixlen, v6str2);
        if ( ret < 0 ) {
            return -1;
        }
        ret = inet_pton(AF_INET6, v6str1, &v6addr);
        if ( 1 != ret ) {
            return -1;
        }
        addr1 = in6_addr_to_uint128(&v6addr);
        ret = inet_pton(AF_INET6, v6str2, &v6addr);
        if ( 1 != ret ) {
            return -1;
        }
        addr2 = in6_addr_to_uint128(&v6addr);

        /* Add an entry (use the least significant 64 bits for testing) */
        ret = poptrie6_route_add(poptrie, addr1, prefixlen, (void *)(u64)addr2);
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
        addr1 = (((__uint128_t)0x2000) << 112) | (((__uint128_t)i) << 92);
        if ( poptrie6_lookup(poptrie, addr1)
             != poptrie6_rib_lookup(poptrie, addr1) ) {
            return -1;
        }
    }

    /* Release */
    poptrie_release(poptrie);

    /* Close */
    fclose(fp);

    return 0;
}


/*
 * Test FIB reference counting for IPv6 route operations (regression test for
 * FIB reference leak in route_change on non-existent route).
 */
static int
test_fib_refcount6(void)
{
    struct poptrie *poptrie;
    int ret;
    int i;
    int used;
    __uint128_t addr;

    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x0, 0, 0, 0, 0);
    ret = poptrie6_route_add(poptrie, addr, 48, (void *)1);
    if ( ret < 0 ) {
        return -1;
    }

    /* route_change on non-existent route must fail and not leak FIB */
    addr = IPV6ADDR(0x2001, 0xdb9, 0x0, 0x0, 0, 0, 0, 0);
    ret = poptrie6_route_change(poptrie, addr, 48, (void *)2);
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

    poptrie_release(poptrie);
    return 0;
}

/*
 * Test longest prefix match with nested IPv6 prefixes.
 */
static int
test_lpm6(void)
{
    struct poptrie *poptrie;
    int ret;
    __uint128_t addr;

    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        return -1;
    }

    /* 2001:db8::/32 */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x0, 0x0, 0, 0, 0, 0);
    ret = poptrie6_route_add(poptrie, addr, 32, (void *)1);
    if ( ret < 0 ) return -1;

    /* 2001:db8:1::/48 */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x0, 0, 0, 0, 0);
    ret = poptrie6_route_add(poptrie, addr, 48, (void *)2);
    if ( ret < 0 ) return -1;

    /* 2001:db8:1:1::/64 */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x1, 0, 0, 0, 0);
    ret = poptrie6_route_add(poptrie, addr, 64, (void *)3);
    if ( ret < 0 ) return -1;
    TEST_PROGRESS();

    /* Check longest prefix match */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x1, 0, 0, 0, 1);
    if ( (void *)3 != poptrie6_lookup(poptrie, addr) ) return -1;

    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x2, 0, 0, 0, 1);
    if ( (void *)2 != poptrie6_lookup(poptrie, addr) ) return -1;

    addr = IPV6ADDR(0x2001, 0xdb8, 0x2, 0x0, 0, 0, 0, 1);
    if ( (void *)1 != poptrie6_lookup(poptrie, addr) ) return -1;

    addr = IPV6ADDR(0x2002, 0x0, 0x0, 0x0, 0, 0, 0, 1);
    if ( NULL != poptrie6_lookup(poptrie, addr) ) return -1;
    TEST_PROGRESS();

    /* Delete /64 and check fallback */
    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x1, 0, 0, 0, 0);
    ret = poptrie6_route_del(poptrie, addr, 64);
    if ( ret < 0 ) return -1;

    addr = IPV6ADDR(0x2001, 0xdb8, 0x1, 0x1, 0, 0, 0, 1);
    if ( (void *)2 != poptrie6_lookup(poptrie, addr) ) return -1;
    TEST_PROGRESS();

    /* route_update on non-existent should add */
    addr = IPV6ADDR(0x2001, 0xdb9, 0x0, 0x0, 0, 0, 0, 0);
    ret = poptrie6_route_update(poptrie, addr, 32, (void *)100);
    if ( ret < 0 ) return -1;

    addr = IPV6ADDR(0x2001, 0xdb9, 0x0, 0x0, 0, 0, 0, 1);
    if ( (void *)100 != poptrie6_lookup(poptrie, addr) ) return -1;
    TEST_PROGRESS();

    poptrie_release(poptrie);
    return 0;
}

/*
 * Load the IPv6 LINX RIB and verify correctness using sampled lookups (prefix
 * addresses and random addresses).  Much faster than the full 2^32 scan in
 * test_lookup_linx.
 */
static int
test_lookup_linx6_sampled(void)
{
    struct poptrie *poptrie;
    FILE *fp;
    char buf[4096];
    char v6str1[256];
    char v6str2[256];
    int prefixlen;
    struct in6_addr v6addr;
    int ret;
    __uint128_t addr1;
    __uint128_t addr2;
    u64 i;
    u64 fails;

    typedef struct { __uint128_t addr; int len; __uint128_t nh; } route6_t;
    route6_t *routes = NULL;
    int nroutes = 0;
    int cap = 0;

    fp = fopen("tests/linx-rib-ipv6.20141225.0000.p69.txt", "r");
    if ( NULL == fp ) {
        return -1;
    }

    poptrie = poptrie_init(NULL, 19, 22);
    if ( NULL == poptrie ) {
        fclose(fp);
        return -1;
    }

    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%255[^'/']/%d %255s", v6str1, &prefixlen, v6str2);
        if ( ret < 0 || ret < 3 ) {
            continue;
        }
        if ( 1 != inet_pton(AF_INET6, v6str1, &v6addr) ) {
            continue;
        }
        addr1 = in6_addr_to_uint128(&v6addr);
        if ( 1 != inet_pton(AF_INET6, v6str2, &v6addr) ) {
            continue;
        }
        addr2 = in6_addr_to_uint128(&v6addr);

        ret = poptrie6_route_add(poptrie, addr1, prefixlen,
                                 (void *)(u64)addr2);
        if ( ret < 0 ) {
            poptrie6_route_update(poptrie, addr1, prefixlen,
                                  (void *)(u64)addr2);
        }

        if ( nroutes >= cap ) {
            cap = cap ? cap * 2 : 32768;
            routes = (route6_t *)realloc(routes, cap * sizeof(route6_t));
        }
        routes[nroutes].addr = addr1;
        routes[nroutes].len = prefixlen;
        routes[nroutes].nh = addr2;
        nroutes++;
    }
    fclose(fp);
    TEST_PROGRESS();

    /* Test prefix addresses */
    fails = 0;
    for ( i = 0; i < (u64)nroutes; i++ ) {
        if ( poptrie6_lookup(poptrie, routes[i].addr)
             != poptrie6_rib_lookup(poptrie, routes[i].addr) ) {
            fails++;
        }
    }
    if ( fails > 0 ) {
        return -1;
    }
    TEST_PROGRESS();

    /* Test random addresses in 2000::/3 */
    fails = 0;
    srand(42);
    for ( i = 0; i < 500000; i++ ) {
        __uint128_t addr;
        addr = (((__uint128_t)0x2000) << 112);
        addr |= ((__uint128_t)(rand() & 0xFFFF)) << 96;
        addr |= ((__uint128_t)rand()) << 64;
        addr |= ((__uint128_t)rand());
        if ( poptrie6_lookup(poptrie, addr)
             != poptrie6_rib_lookup(poptrie, addr) ) {
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
 * Main routine for the basic test
 */
int
main(int argc, const char *const argv[])
{
    int ret;

    ret = 0;

    /* Run tests */
    TEST_FUNC("init6", test_init, ret);
    TEST_FUNC("lookup6", test_lookup, ret);
    TEST_FUNC("fib_refcount6", test_fib_refcount6, ret);
    TEST_FUNC("lpm6", test_lpm6, ret);
    TEST_FUNC("lookup6_linx_sampled", test_lookup_linx6_sampled, ret);
    TEST_FUNC("lookup6_fullroute", test_lookup_linx, ret);

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
