#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>
#include <signal.h>

#include <zlog.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/keyvalq_struct.h>
#include <event2/http.h>

#include "config.h"
#include "utils.h"

#define SERVER_SIGNATURE "Mginy /0.1"

zlog_category_t *rl; // run log
zlog_category_t *al; // access log

static SSL_CTX *evssl_init(const char *cert_chain, const char *privkey)
{
    SSL_CTX *server_ctx;
    SSL_load_error_strings();
    SSL_library_init();
    if (!RAND_poll())
        return NULL;

    server_ctx = SSL_CTX_new(SSLv23_server_method());

    if (!SSL_CTX_use_certificate_chain_file(server_ctx, cert_chain))
    {
        zlog_fatal(rl, "Failed load cert chain file: %s", cert_chain);
        return NULL;
    }
    if (!SSL_CTX_use_PrivateKey_file(server_ctx, privkey, SSL_FILETYPE_PEM))
    {
        zlog_fatal(rl, "Failed load private key file: %s", privkey);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(server_ctx))
    {
        zlog_fatal(rl, "Checking key files fail");
        return NULL;
    }
    return server_ctx;
}

static struct bufferevent *bev_cb(struct event_base *base, void *arg)
{
    SSL_CTX *ctx = (SSL_CTX *)arg;
    struct bufferevent *r = bufferevent_openssl_socket_new(base, -1, SSL_new(ctx), BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
    return r;
}

void gen_err_page_content(struct evbuffer *buf, int respcode, char *brief, char *msg)
{
    char *fmt = "<!DOCTYPE html>\n"
                "<head>\n"
                "    <title>%d %s</title>\n"
                "</head>\n"
                "<body>\n"
                "    <center><h1>%d %s</h1></center>\n<p>%s</p>\n<hr>\n"
                "    <center>%s</center>\n"
                "</body>\n"
                "</html>\n";
    evbuffer_add_printf(buf, fmt, respcode, brief, respcode, brief, msg, SERVER_SIGNATURE);
    return;
}

int handle_get(struct evhttp_request *req)
{
    int sc;
    const char *website_base = "/home/wentian/http-server/www/";
    const struct evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    const char *uri_str = evhttp_uri_get_path(uri);
    const char *uripath = evhttp_decode_uri(uri_str);
    if (strlen(uripath) > 8190)
    {
        evhttp_send_reply(req, 414, "Request-URI Too Large", NULL);
        sc = 414;
        return sc;
    }

    char *filepath = join_path(website_base, uripath);
    if (filepath[0] == 0) // empty str indicates error
    {
        zlog_error(rl, "The length of file path exceeds the limit.");
    }

    struct evbuffer *outbuf = evbuffer_new();
    struct evkeyvalq *out_headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(out_headers, "Server", SERVER_SIGNATURE);
    switch (get_file_stat(filepath))
    {
    case 0: // regular file
    {
        char *ext = get_file_ext(filepath);
        char *content_type = get_mime_type(ext);
        free(ext);

        const int chunksize = 1048576;
        evhttp_add_header(out_headers, "Content-Type", content_type);
        free(content_type);
        FILE *fp = fopen(filepath, "rb");
        if (!fp)
        {
            zlog_error(rl, "Error open %s\n", filepath);
            evhttp_send_reply(req, 403, "Forbidden", outbuf);
            sc = 403;
            break;
        }

        ev_off_t offset = 0;
        int rs = evbuffer_add_file(outbuf, fileno(fp), offset, -1);
        if (rs == -1)
        {
            zlog_error(rl, "Load file failed.\n");
            gen_err_page_content(outbuf, 500, "Internal Server Error", "");
            evhttp_send_reply(req, HTTP_INTERNAL, "Internal Server Error", outbuf);
            sc = 500;
            break;
        }
        evhttp_send_reply(req, HTTP_OK, "OK", outbuf);
        sc = 200;
        /*
            printf("%d", rs);

            int readbytes = evbuffer_get_length(outbuf);
            offset += readbytes;

            // do
            // {
            //     curbytes += readbytes;
            // } while (readbytes < max_buffer_op_size && curbytes < chunksize);
            printf("readbytes: %d\n", readbytes);
            if (readbytes < chunksize)
            {
                evhttp_send_reply(req, HTTP_OK, "OK", outbuf);
            }
            else
            {
                //evhttp_add_header(out_headers, "Transfer-Encoding", "chunked");
                evhttp_send_reply_start(req, HTTP_OK, "OK");
                evhttp_send_reply_chunk(req, outbuf);
                while (readbytes)
                {
                    evhttp_send_reply_chunk(req, outbuf);
                    //readbytes = evbuffer_read(outbuf, fileno(fp), chunksize);
                    rs = evbuffer_add_file(outbuf, fileno(fp), offset, chunksize);
                    printf("%d", rs);
                    readbytes = evbuffer_get_length(outbuf);
                    offset += readbytes;
                }
                evhttp_send_reply_chunk(req, outbuf);
                evhttp_send_reply_end(req);
            }*/
        fclose(fp);

        break;
    }
    case 1: // dirs
        gen_err_page_content(outbuf, 403, "Forbidden", "");
        evhttp_send_reply(req, 403, "Forbidden", outbuf);
        sc = 403;
        break;
    case 3: //forbidden
        gen_err_page_content(outbuf, 403, "Forbidden", "");
        evhttp_send_reply(req, 403, "Forbidden", outbuf);
        sc = 403;
        break;
    case 4: //not found
        gen_err_page_content(outbuf, 404, "Not Found", "The requested URL was not found on this server.");
        evhttp_send_reply(req, 404, "Not Found", outbuf);
        sc = 404;
        break;
    case 5:
        gen_err_page_content(outbuf, 500, "Internal Server Error", "");
        evhttp_send_reply(req, 500, "Internal Server Error", outbuf);
        sc = 500;
        break;
    }

    evbuffer_free(outbuf);
    free(filepath);
    free((void *)uripath);
    return sc;
}

int handle_post(struct evhttp_request *req)
{
    int sc;
    const char *website_base = "../www/";

    const struct evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    const char *uri_str = evhttp_uri_get_path(uri);
    const char *uripath = evhttp_decode_uri(uri_str);
    if (strlen(uripath) > 8190)
    {
        evhttp_send_reply(req, 414, "Request-URI Too Large", NULL);
        sc = 414;
        return sc;
    }
    char *filepath = join_path(website_base, uripath);
    if (filepath[0] == 0) // empty str indicates error
    {
        zlog_error(rl, "The length of file path exceeds the limit.");
    }

    struct evbuffer *inbuf = evhttp_request_get_input_buffer(req);
    struct evbuffer *outbuf = evbuffer_new();
    struct evkeyvalq *out_headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(out_headers, "Server", SERVER_SIGNATURE);

    FILE *fp = fopen(filepath, "wb");
    if (!fp)
    {
        zlog_error(rl, "Error open %s\n", filepath);
        evhttp_send_reply(req, 403, "Forbidden", outbuf);
        sc = 403;
        return sc;
    }
    else
    {
        evbuffer_write(inbuf, fileno(fp));
        evhttp_send_reply(req, 200, "OK", outbuf);
        sc = 200;
    }

    fclose(fp);
    evbuffer_free(outbuf);
    free(filepath);
    free((void *)uripath);
    return sc;
}

static void http_gen_cb(struct evhttp_request *req, void *arg)
{
    enum evhttp_cmd_type req_cmd = evhttp_request_get_command(req);
    const struct evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    const char *method_str = get_method_str(req_cmd);
    const char *uri_str = evhttp_uri_get_path(uri);

    int sc;
    switch (evhttp_request_get_command(req))
    {
    case EVHTTP_REQ_GET:
        sc = handle_get(req);
        break;
    case EVHTTP_REQ_POST:
        sc = handle_post(req);
        break;

    default:
    {
        struct evbuffer *outbuf = evbuffer_new();
        gen_err_page_content(outbuf, 405, "Method Not Allowed", "");
        evhttp_send_reply(req, 405, "Method Not Allowed", outbuf);
        sc = 405;
        evbuffer_free(outbuf);
        break;
    }
    }

    if (sc < 400)
        zlog_info(al, "%s %s - %d", method_str, uri_str, sc);
    else
        zlog_error(al, "%s %s - %d", method_str, uri_str, sc);
}

void sig_handler(int signo, short events, void *arg)
{
    event_base_loopbreak((struct event_base *)arg);
}

int main(int argc, char **argv)
{
    int rc = zlog_init("../config/zlog.conf");
    if (rc)
    {
        printf("Zlog init failed!\n");
        return -1;
    }
    al = zlog_get_category("access_log");
    rl = zlog_get_category("run_log");

    const char *cert_chain_file = "../../certs/cert.crt";
    const char *cert_privkey_file = "../../certs/rsa_private.key";

    load_mime_types("../config/mime.types");

    SSL_CTX *ctx;
    struct event_base *evbase;

    ctx = evssl_init(cert_chain_file, cert_privkey_file);

    evbase = event_base_new();
    if (!evbase)
    {
        zlog_fatal(rl, "Error create event base!");
        return -1;
    }

    struct evhttp *httpsd = evhttp_new(evbase);
    if (!httpsd)
    {
        zlog_fatal(rl, "Error create http server!");
        return -1;
    }

    evhttp_set_bevcb(httpsd, bev_cb, (void *)ctx);
    evhttp_set_gencb(httpsd, http_gen_cb, NULL);
    if (evhttp_bind_socket(httpsd, "0.0.0.0", 443))
    {
        zlog_fatal(rl, "Cannot listen on port 443");
        return -1;
    }

    struct evhttp *httpd = evhttp_new(evbase);
    if (!httpsd)
    {
        zlog_fatal(rl, "Error create http server!");
        return -1;
    }
    evhttp_set_gencb(httpd, http_gen_cb, NULL);
    if (evhttp_bind_socket(httpd, "0.0.0.0", 80))
    {
        zlog_fatal(rl, "Cannot listen on port 80");
        return -1;
    }

    struct event *sig_event = evsignal_new(evbase, SIGINT & SIGTERM, sig_handler, (void *)evbase);
    evsignal_add(sig_event, NULL);
    zlog_info(rl, "(PID %u) Server start...", getpid());

    event_base_dispatch(evbase);

    zlog_info(rl, "SIGINT accepted. Stopping ...");
    evhttp_free(httpsd);
    evhttp_free(httpd);
    event_free(sig_event);
    event_base_free(evbase);
    SSL_CTX_free(ctx);

    zlog_info(rl, "Server stopped.");
    zlog_fini();
    return 0;
}