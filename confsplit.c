#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

//#define TOK_1 "mode_cfg"
//#define TOK_2 "wins4"
#define TOK_1 "\twins4 255.255.255.255;"

#ifdef DEBUG
static int
creat_chunk(void)
{
    static int n = 0;
    int fd;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "chunk-%04d", n++);
    fd = creat(tmp, 0644);
    assert(fd != -1);
    return fd;
}
#endif

static int
is_tok_2(const char *map, const char *end)
{
#ifdef TOK_2
    while (map < end && (isblank(*map) || *map == '\n' || *map == '{')) { //}
        map++;
    }
    assert(map < end);
    return !memcmp(map, TOK_2, sizeof(TOK_2) - 1);
#else
    (void)(map && end);
    return 1;
#endif
}

static int
testconf(const char *infile)
{
    int rv;
    int fd;
    struct stat st;
    char *map, *base, *end;
    size_t sz;

    fd = open(infile, O_RDONLY);
    assert(fd != -1);
    rv = fstat(fd, &st);
    assert(rv == 0);
    map = mmap(NULL, st.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    assert(map != MAP_FAILED);
    close(fd);

    base = map;
    end = map + st.st_size;
    sz = st.st_size;
    rv = -1;
    while (1) {
        char *p, *q;
        assert(base + sz == end);
        p = memchr(base, '\"', sz);
        if (!p) {
            rv = 0;
            break;
        }
        // open quote: p - map
        if (p < map + 8 || memcmp(p - 8, "\tbanner ", 8)) {
            fprintf(stderr, "error: bad open quote at %zu\n", p - map);
            break;
        }
        sz -= ++p - base;
        assert(p + sz == end);
        q = memchr(p, '\"', sz);
        if (!q) {
            fprintf(stderr, "error: unbalanced quote at %zu\n", p - map);
            break;
        }
        // close quote: q - map
        if (q + 2 >= end || q[1] != ';' || q[2] != '\n') {
            fprintf(stderr, "error: bad close quote at %zu\n", q - map);
            break;
        }
        sz -= ++q - p;
        base = q;
    }

    munmap(map, st.st_size);

    return rv;
}

int
main(int argc, char **argv)
{
    int rv;
    int fd;
    struct stat st;
    char *map, *fill, a;
    size_t inptr, outptr, chunk;
    const char *infile, *outfile;

#ifdef DEBUG
    infile = "conf";
    outfile = "conf.out";
    chunk = 4500;
#else
    if (argc < 4) {
        fprintf(stderr, "usage: %s infile outfile split\n", argv[0]);
        return -1;
    }

    infile = argv[1];
    outfile = argv[2];
    chunk = strtoull(argv[3], NULL, 0);
#endif
    rv = testconf(infile);
    if (rv) {
        return -1;
    }

    a = '\n';
    fill = malloc(chunk);
    assert(fill);
    memset(fill, '#', chunk);

    fd = open(infile, O_RDONLY);
    assert(fd != -1);
    rv = fstat(fd, &st);
    assert(rv == 0);
    map = mmap(NULL, st.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    assert(map != MAP_FAILED);
    close(fd);

    fd = creat(outfile, 0644);
    assert(fd);

    inptr = 0;
    outptr = 0;
    while (1) {
        size_t base = inptr;
        size_t end = inptr + chunk;
        if (end > (size_t)st.st_size) {
#ifdef DEBUG
            int fdo = creat_chunk();
            write(fdo, map + base, st.st_size - base);
            close(fdo);
#endif
            write(fd, map + base, st.st_size - base);
            break;
        }
        inptr = end;
        while (1) {
            while (inptr > base && memcmp(map + inptr, TOK_1, sizeof(TOK_1) - 1)) {
                inptr--;
            }
            assert(inptr > base);
            if (is_tok_2(map + inptr + sizeof(TOK_1) - 1, map + st.st_size)) {
#ifdef DEBUG
                int fdo = creat_chunk();
                write(fdo, map + base, inptr - base);
                printf("split @%zu (fill %zu)\n", inptr, end - inptr);
#endif
                write(fd, map + base, inptr - base);
                if (end > inptr) {
#ifdef DEBUG
                    write(fdo, fill, end - inptr - 1);
                    write(fdo, &a, 1);
                    close(fdo);
#endif
                    write(fd, fill, end - inptr - 1);
                    write(fd, &a, 1);
                }
                outptr += chunk;
                break;
            }
            inptr--;
#ifdef DEBUG
            printf("retry @%zu\n", inptr);
#endif
        }
    }

    close(fd);
    munmap(map, st.st_size);
    free(fill);
    return 0;
}
