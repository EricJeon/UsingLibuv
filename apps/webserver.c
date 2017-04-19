#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../libuv/include/uv.h"
#include "../libhttp_parser/http_parser.h"


/* customizing value */
#define SERVER_IP "0.0.0.0"
#define SERVER_PORT 8000

#define DEFAULT_BACKLOG 10   /* indicates the number of connections the kernel might queue */

#define BLOCK_HTTP_PARSE_MESSAGE

typedef struct {
    uv_tcp_t tcpHandle;
    uv_loop_t *pEventLoop;
}server_t;

static server_t listenServer;



typedef struct {
    uv_tcp_t tcpHandle;         /* client socket */
    server_t *pServerHandle;    /* listening socket + event loop */
    http_parser stHttpParser; 
    uv_write_t  *write_req;

    /* REST related */
    char * pRESTcmd;
    enum http_method eHttpMethod;   /* 0 : delete 1: get 3: post 4: put */
}client_t;

 
static struct http_parser_settings s_httpParserSettings;

/* callback function */
void onConnection_cb( uv_stream_t *pServer_handle , int status);
void onAlloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void onRead_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void onClose_cb(uv_handle_t* handle);

/* http parser callback functions */

/* URL == cmd, so get the command from URL of http header*/
int onUrl_http_cb(http_parser* pHttpParser, const char *at, size_t length);
int onBody_http_cb(http_parser* pHttpParser, const char *at, size_t length);
int onHeaderStatus_http_cb(http_parser* pHttpParser, const char *at, size_t length);
int onHeaderField_http_cb(http_parser* pHttpParser, const char *at, size_t length);
int onHeaderValue_http_cb(http_parser* pHttpParser, const char *at, size_t length);

int onHeaders_http_cb(http_parser* pHttpParser);
int onMessage_http_cb(http_parser* pHttpParser);

#define RESPONSE \
    "http/1.1 200 OK \r\n" \
    "Content-Type: text/plain \r\n" \
    "Content-Length: 12 \r\n" \
    "\r\n" \
    "hello world \n"


#if 0
void after_write(uv_write_t*req, int status)
{

   uv_close((uv_handle_t*) req->handle, on_close);
   free(req);
   return; 
}

int  on_headers_complete(http_parser * parser)
{
    client_t*client = parser->data;
    // send data 
    printf("httpmesaage!\n");
    client->write_req = (uv_write_t* )malloc(sizeof(uv_write_t));
    uv_write((uv_write_t*)client->write_req, (uv_stream_t *)&client->handle, &resbuf, 1, after_write);
    return 1;
}
#endif



int onUrl_http_cb(http_parser* pHttpParser, const char *at, size_t length)
{
    client_t *pClient = NULL;

    pClient = (client_t *)pHttpParser->data;
    
    pClient->pRESTcmd = malloc(length +1);
    bzero(pClient->pRESTcmd, length + 1);
    memcpy(pClient->pRESTcmd, at , length);

//  fprintf(stderr, " URL-RESTcmd : %s , URL length: %zd \n", pClient->pRESTcmd , length);
    return 0;
}

int onHeaders_http_cb(http_parser* pHttpParser)
{
    client_t *pClient = NULL;

    pClient = (client_t *)pHttpParser->data;
    pClient->eHttpMethod = pHttpParser->method; 

//  fprintf(stderr, " httpMethod : %s\n", http_method_str(pClient->eHttpMethod));
    return 0;
}

int onBody_http_cb(http_parser* pHttpParser, const char *at, size_t length)
{
    client_t *pClient = NULL;

    pClient = (client_t *) pHttpParser->data;

    //printf(" httpMethod : %d\n", (pClient->eHttpMethod));
    /* PARSE JASON */
    if ( pClient->eHttpMethod == 3) /* POST */
    {
        printf("Receive POST so Start to parse  JASON \n");
        printf(" for example, just dump boyd \n");
        printf("%s\n", at);
    }
    return 0;
}


#ifndef BLOCK_HTTP_PARSE_MESSAGE
char arString[256];

int onMessage_http_cb(http_parser* pHttpParser)
{
#if 1
    printf(" %s is called\n", __func__ );
#else
    bzero(arString, 256);
    memcpy(arString, at, length);
    printf("onBody : %s ", arString);
#endif
    return 0;
}


int onHeaderStatus_http_cb(http_parser* pHttpParser, const char *at, size_t length)
{
    bzero(arString, 256);
    memcpy(arString, at, length);
    printf("Status : %s ", arString);
    return 0;
}


int onHeaderField_http_cb(http_parser* pHttpParser, const char *at, size_t length)
{
    bzero(arString, 256);
    memcpy(arString, at, length);
    printf("%s : ", arString);
    return 0;
}

int onHeaderValue_http_cb(http_parser* pHttpParser, const char *at, size_t length)
{
    bzero(arString, 256);
    memcpy(arString, at, length);
    printf(" %s\n", arString);
    return 0;
}
#endif


void onClose_cb(uv_handle_t* handle)
{
    printf("close client handle\n"); /* free client_t which is allocated on connection*/
    if ( handle != NULL)
    {
        // this routine is called
        //fprintf(stderr, "client hand is not null, so free it\n");
        free(handle);
    }
    return;
}



/* routine - do not need to change this alloc_cb in normal cases */
void onAlloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    // normally suggested_size = 65536
    //printf("Read - suggest size : %zu \n", suggested_size);
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
    return;
}

void onRead_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    size_t parsed;
    client_t *pClient = (client_t*)stream;

    if (nread > 0)
    {
#if 1
        /* parse  http ..*/
        parsed = http_parser_execute(&pClient->stHttpParser, &s_httpParserSettings, buf->base, nread);
        if (parsed < nread)
        {
            fprintf(stderr, "http parser error\n");
        }
#else
        write(1, buf->base, nread);
#endif
        fprintf(stderr ,"URL : %s , Method : %s \n", pClient->pRESTcmd,http_method_str(pClient->eHttpMethod));
    }
    else
    {
        if (nread == UV_EOF )
        {
            uv_close((uv_handle_t*)&pClient->tcpHandle, onClose_cb);
        }
        else
        {
            fprintf(stderr, "read: %s\n", uv_strerror(nread));
        }
    }
    free(buf->base); /* DATA from Client */

    /* temporary Response */
//    pClient->write_req = (uv_write_t* )malloc(sizeof(uv_write_t));
 //   uv_write((uv_write_t*)client->write_req, (uv_stream_t *)&client->handle, &resbuf, 1, after_write);



    /* in case of POST */



    /* in case of GET */



    return;
}
    
void onConnection_cb( uv_stream_t *pServer_handle , int status)
{
    int returnCode = 0;
    client_t *pClient = NULL; 

    assert((uv_tcp_t *)pServer_handle == &listenServer.tcpHandle);

    pClient = malloc(sizeof(client_t));
    pClient->pServerHandle = (server_t *)pServer_handle;
    returnCode = uv_tcp_init((uv_loop_t * )pClient->pServerHandle->pEventLoop, (uv_tcp_t*)&pClient->tcpHandle );
    if (returnCode != 0)
    {
        fprintf(stderr,"fail to init client tcp socket \n");
        return;
    }
    /* todo initialize HTTP parser */
    http_parser_init(&pClient->stHttpParser, HTTP_REQUEST);
    pClient->stHttpParser.data = pClient;
    /* todo initialize JSON request */
    /* todo initialize write request */


#if 0 /* When the uv_connection_cb callback is called it is guaranteed that this function will complete successfully the first time.  */
    returnCode = uv_accept(server_handle, (uv_stream_t*)&client->handle);
    if (returnCode)
    {
        fprintf(stderr, "accept: %s \n", uv_strerror(returnCode));
        return;
    }
#else
    uv_accept((uv_stream_t*)&pClient->pServerHandle->tcpHandle,(uv_stream_t*)&pClient->tcpHandle);
#endif
    fprintf(stderr, "Socket engine is connected \n");

    /* The uv_read_cb callback will be made several times 
     * until there is no more data to read or uv_read_stop() is called */
    returnCode = uv_read_start((uv_stream_t*)&pClient->tcpHandle, onAlloc_cb, onRead_cb);
    if (returnCode != 0)
    {
        fprintf(stderr, "read: %s \n", uv_strerror(returnCode));
        return;
    }
    return;
}

int main()
{
    struct sockaddr_in serverAddr;
    int returnCode = 0;

    listenServer.pEventLoop = uv_default_loop();
    if (listenServer.pEventLoop == NULL)
    {
        fprintf(stderr,"fail to init default loop\n");
        return -1;
    }
    /* todo : modulize http parser */
    s_httpParserSettings.on_url = onUrl_http_cb; /* get url -> command */
    s_httpParserSettings.on_headers_complete = onHeaders_http_cb; /* get HTTP method */
    s_httpParserSettings.on_body = onBody_http_cb;

#ifndef BLOCK_HTTP_PARSE_MESSAGE
    s_httpParserSettings.on_status = onHeaderStatus_http_cb;
    s_httpParserSettings.on_header_field = onHeaderField_http_cb;
    s_httpParserSettings.on_header_value = onHeaderValue_http_cb;
    s_httpParserSettings.on_message_complete = onMessage_http_cb;
#endif
    returnCode = uv_tcp_init(listenServer.pEventLoop , (uv_tcp_t*)&listenServer.tcpHandle);
    if (returnCode != 0)
    {
        fprintf(stderr,"fail to init tcp socket \n");
        return -1;
    }

    /* todo : set ip address and port from env file */
    returnCode = uv_ip4_addr( SERVER_IP , SERVER_PORT, &serverAddr);
    if (returnCode != 0)
    {
        fprintf(stderr,"fail to set ip and port \n");
        return -1;
    }
   
    returnCode = uv_tcp_bind((uv_tcp_t*)&listenServer.tcpHandle, (const struct sockaddr *)&serverAddr, 0);
    if(returnCode)
    {
        fprintf(stderr, "bind: %s \n", uv_strerror(returnCode));
        return -1;
    }
    /* todo : simulate connection */
    returnCode = uv_listen((uv_stream_t*)&listenServer.tcpHandle, DEFAULT_BACKLOG, onConnection_cb); 
    if (returnCode)
    {
        fprintf(stderr, "listen: %s \n", uv_strerror(returnCode));
        return -1;
    }
    
    fprintf(stdout, "Socket engine runs successfully and waiting for connection \n");
    fprintf(stdout, "ip : %s  port : %d \n", SERVER_IP, SERVER_PORT);
    
    returnCode = uv_run( listenServer.pEventLoop, UV_RUN_DEFAULT); 
    if ( returnCode != 0)
    {
        fprintf(stderr, "uv_stop was called while there are still active handles or requests.\n");
    }
    else
    {
        fprintf(stderr,"event loop is stopped. there is no requeset \n");
    }

    returnCode = uv_loop_close(listenServer.pEventLoop);
    if (returnCode != 0)
    {
        fprintf(stderr, " some resources are not freeed \n");
    }
    /* todo check need to free */
    if (listenServer.pEventLoop != NULL)
       free(listenServer.pEventLoop); 

    return 0;
}
