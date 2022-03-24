#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/queue.h>
#include <linux/limits.h>

#include <stdio.h>

char *get_file_ext(const char *filepath)
{
    int last = -1;
    for (int i = strlen(filepath); i >= 0; --i)
    {
        if (filepath[i] == '/')
            break;
        if (filepath[i] == '.')
        {
            last = i;
            break;
        }
    }

    char *ret;
    if (last == -1)
    {
        // no ext
        ret = (char *)malloc(1);
        memset(ret, 0, 1);
    }
    else
    {
        const int sz = strlen(filepath) - 1 - last;
        ret = (char *)malloc(sz);
        memset(ret, 0, sz);
        strcpy(ret, filepath + last + 1);
    }
    return ret; // must free by caller
}

int get_file_stat(const char *filepath)
{
    struct stat sb;
    if (stat(filepath, &sb) != 0)
    {
        switch (errno)
        {
        case ENOENT:
            return 4; // not found
        case EACCES:
            return 3;
        default:
            return 5; // forbidden
        }
    }
    else
    {
        if (S_ISREG(sb.st_mode))
        {
            return 0; // regular file
        }
        else if (S_ISDIR(sb.st_mode))
        {
            return 1; // directory
        }
        else
        {
            return 3; // forbidden
        }
    }
}

const char *get_method_str(enum evhttp_cmd_type t)
{
    char *methods[] = {
        "GET",
        "POST",
        "HEAD",
        "PUT",
        "DELETE",
        "OPTIONS",
        "TRACE",
        "CONNECT",
        "PATCH"};
    int i;
    for (i = 0; i < sizeof(methods) && !((t >> i) & 0x1); i++)
        ;
    return methods[i];
}

struct path_node
{
    TAILQ_ENTRY(path_node)
    field;
    char *p;
};
TAILQ_HEAD(qhead, path_node);
static struct qhead *resolve_path(char *path, int raw, int leadslash)
{
    int ls = (leadslash && path[0] == '/') ? 1 : 0;

    char *delim = "/";
    char *p = strtok(path, delim);
    struct qhead *h = (struct qhead *)malloc(sizeof(struct qhead));
    TAILQ_INIT(h);
    do
    {
        if (raw) // keep the raw path
        {
            struct path_node *nd = (struct path_node *)malloc(sizeof(struct path_node));
            nd->p = p;
            TAILQ_INSERT_TAIL(h, nd, field);
        }
        else // resolve the path to remove . and ..
        {
            if (!strcmp(p, "..")) // p == ..
            {
                if (!TAILQ_EMPTY(h)) // pop out a node and drop
                {
                    struct path_node *v = TAILQ_LAST(h, qhead);
                    TAILQ_REMOVE(h, v, field);
                    free(v);
                }
            }
            else if (!strcmp(p, ".")) // p == .
            {
                // drop
            }
            else // other
            {
                struct path_node *nd = (struct path_node *)malloc(sizeof(struct path_node));
                nd->p = p;
                TAILQ_INSERT_TAIL(h, nd, field);
            }
        }

        p = strtok(NULL, delim);
    } while (p);

    if (ls) // add a leading slash
    {
        struct path_node *nd = (struct path_node *)malloc(sizeof(struct path_node));
        nd->p = ""; // the slash will be added when join
        TAILQ_INSERT_HEAD(h, nd, field);
    }

    return h;
}

char *join_path(const char *base, const char *path)
{
    char *tmp_path = (char *)malloc(strlen(path));
    strcpy(tmp_path, path);
    char *tmp_base = (char *)malloc(strlen(base));
    strcpy(tmp_base, base);
    struct qhead *hbase = resolve_path(tmp_base, 1, 1);
    struct qhead *hpath = resolve_path(tmp_path, 0, 0);

    TAILQ_CONCAT(hbase, hpath, field);
    char *ret = (char *)calloc(PATH_MAX, 1);
    char *cp_dst = ret;

    struct path_node *v, *w;
    TAILQ_FOREACH(v, hbase, field)
    {
        if (cp_dst - ret + strlen(v->p) > PATH_MAX - 1)
        {
            // file path too long
            memset(ret, 0, PATH_MAX); // return a empty string
            break;
        }

        memcpy(cp_dst, v->p, strlen(v->p));
        cp_dst += strlen(v->p);
        *cp_dst++ = '/';
    }
    if (cp_dst > ret && *--cp_dst == '/')
        *cp_dst = 0; // set the last slash to \0

    // free the nodes in TAILQ
    for (v = TAILQ_FIRST(hbase); v; v = w)
    {
        w = TAILQ_NEXT(v, field);
        TAILQ_REMOVE(hbase, v, field);
        free(v);
    }

    free(hbase);
    free(hpath);
    free(tmp_path);
    free(tmp_base);
    return ret;
}