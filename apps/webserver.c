#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <uv.h>

#define DEFAULT_BACKLOG 0
static uv_tcp_t server;
static uv_loop_t *loop;


void on_close(uv_handle_t* handle)
{
    printf("close client handle\n");
    free(handle);
    return;
}

void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    *buf = uv_buf_init( (char*)malloc(suggested_size), suggested_size);
    return;
}

void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    if (nread > 0)
    {
        write(1, buf->base, nread);
    }
    else
    {
        if (nread == UV_EOF )
        {
            /* close */            
            uv_close((uv_handle_t*) stream, on_close);
        }
        else
        {
            fprintf(stderr, "read: %s\n", uv_strerror(nread));
        }
    }
    free(buf->base);
}
    

void on_connection ( uv_stream_t *server_handle , int status)
{
    int returnCode = 0;
    uv_tcp_t* client_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    assert((uv_tcp_t *) server_handle == &server);

    uv_tcp_init(loop, client_handle);
    printf("on_connection\n");

    returnCode = uv_accept(server_handle, (uv_stream_t*)client_handle);
    if (returnCode)
    {
        fprintf(stderr, "accept: %s \n", uv_strerror(returnCode));
        return;
    }
    else 
    {
        uv_read_start((uv_stream_t*)client_handle, on_alloc, on_read);
//UV_EXTERN int uv_read_stop(uv_stream_t*);
//        uv_close((uv_handle_t*) client_handle, on_close);
        return;
    }

    //uv_close((uv_handle_t*)client_handle, on_close);
}
int main()
{
    struct sockaddr_in addr;
    int returnCode = 0;

    loop = uv_default_loop();

    uv_tcp_init(loop , &server);
    uv_ip4_addr("0.0.0.0",8000, &addr);
    returnCode = uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
    if(returnCode)
    {
        fprintf(stderr, "bind: %s \n", uv_strerror(returnCode));
        return -1;
    }
//UV_EXTERN int uv_listen(uv_stream_t* stream, int backlog, uv_connection_cb cb);
    returnCode = uv_listen((uv_stream_t*) &server, DEFAULT_BACKLOG, on_connection);
    if (returnCode)
    {
        fprintf(stderr, "listen: %s \n", uv_strerror(returnCode));
        return -1;
    }

    printf("Hello world \n");
    
    uv_run(loop, UV_RUN_DEFAULT); 
    uv_loop_close(loop);
    free(loop);

}
