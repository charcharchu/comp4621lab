#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <strings.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>

#define SERVER_NAME "micro_proxy"
#define SERVER_URL "http://www.acme.com/software/micro_proxy/"
#define PROTOCOL "HTTP/1.0"
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"
#define TIMEOUT 300


static int open_client_socket( int client, char* hostname, unsigned short port );
static void proxy_http( int client, char* method, char* path, char* protocol, char* headers, FILE* sockrfp, FILE* sockwfp );
static void proxy_ssl( int client, char* method, char* host, char* protocol, char* headers, FILE* sockrfp, FILE* sockwfp );
static void sigcatch( int sig );
static void trim( char* line );




#define ISspace(x) isspace((int)(x))

void *accept_request(void *);
void bad_request(int);
void print_error(const char *);
int get_line(int, char *, int);
int startup(u_short *);

#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif

#undef USE_IPV6

static int
open_client_socket( int client, char* hostname, unsigned short port )
{
#ifdef USE_IPV6
    struct addrinfo hints;
    char portstr[10];
    int gaierr;
    struct addrinfo* ai;
    struct addrinfo* ai2;
    struct addrinfo* aiv4;
    struct addrinfo* aiv6;
    struct sockaddr_in6 sa_in;
#else /* USE_IPV6 */
    struct hostent *he;
    struct sockaddr_in sa_in;
#endif /* USE_IPV6 */
    int sa_len, sock_family, sock_type, sock_protocol;
    int sockfd;

    (void) memset( (void*) &sa_in, 0, sizeof(sa_in) );

#ifdef USE_IPV6

    (void) memset( &hints, 0, sizeof(hints) );
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    (void) snprintf( portstr, sizeof(portstr), "%d", (int) port );
    if ( (gaierr = getaddrinfo( hostname, portstr, &hints, &ai )) != 0 ) {

        return -1;
    }


    aiv4 = (struct addrinfo*) 0;
    aiv6 = (struct addrinfo*) 0;
    for ( ai2 = ai; ai2 != (struct addrinfo*) 0; ai2 = ai2->ai_next )
    {
        switch ( ai2->ai_family )
        {
        case AF_INET:
            if ( aiv4 == (struct addrinfo*) 0 )
                aiv4 = ai2;
            break;
        case AF_INET6:
            if ( aiv6 == (struct addrinfo*) 0 )
                aiv6 = ai2;
            break;
        }
    }


    if ( aiv4 != (struct addrinfo*) 0 )
    {
        if ( sizeof(sa_in) < aiv4->ai_addrlen )
        {
            (void) fprintf(
                stderr, "%s - sockaddr too small (%lu < %lu)\n",
                hostname, (unsigned long) sizeof(sa_in),
                (unsigned long) aiv4->ai_addrlen );
            return -1;
        }
        sock_family = aiv4->ai_family;
        sock_type = aiv4->ai_socktype;
        sock_protocol = aiv4->ai_protocol;
        sa_len = aiv4->ai_addrlen;
        (void) memmove( &sa_in, aiv4->ai_addr, sa_len );
        goto ok;
    }
    if ( aiv6 != (struct addrinfo*) 0 )
    {
        if ( sizeof(sa_in) < aiv6->ai_addrlen )
        {
            (void) fprintf(
                stderr, "%s - sockaddr too small (%lu < %lu)\n",
                hostname, (unsigned long) sizeof(sa_in),
                (unsigned long) aiv6->ai_addrlen );
            return -1;
        }
        sock_family = aiv6->ai_family;
        sock_type = aiv6->ai_socktype;
        sock_protocol = aiv6->ai_protocol;
        sa_len = aiv6->ai_addrlen;
        (void) memmove( &sa_in, aiv6->ai_addr, sa_len );
        goto ok;
    }


    return -1;

ok:
    freeaddrinfo( ai );

#else /* USE_IPV6 */

    he = gethostbyname( hostname );
    if ( he == (struct hostent*) 0 ) {

        return -1;
    }
    sock_family = sa_in.sin_family = he->h_addrtype;
    sock_type = SOCK_STREAM;
    sock_protocol = 0;
    sa_len = sizeof(sa_in);
    (void) memmove( &sa_in.sin_addr, he->h_addr, he->h_length );
    sa_in.sin_port = htons( port );

#endif /* USE_IPV6 */

    sockfd = socket( sock_family, sock_type, sock_protocol );
    if ( sockfd < 0 ) {

        return -1;
    }

    if ( connect( sockfd, (struct sockaddr*) &sa_in, sa_len ) < 0 ) {

        return -1;
    }

    return sockfd;
}


static void
proxy_http( int client, char* method, char* path, char* protocol, char* headers, FILE* sockrfp, FILE* sockwfp )
{
    char line[10000], protocol2[10000], comment[10000];
    const char *connection_close = "Connection: close\r\n";
    int first_line, status, ich;
    long content_length, i;
    char* headerLine = headers;

    (void) alarm( TIMEOUT );
    (void) fprintf( sockwfp, "%s %s %s\r\n", method, path, protocol );

    fputs( headers, sockwfp );
    (void) fflush( sockwfp );

    content_length = -1;
    while ( headerLine )
    {
        char* nextLine = strchr(headerLine, '\n');
        if (nextLine) *nextLine = '\0';
        if ( strncasecmp( headerLine, "Content-Length:", 15 ) == 0 )
        {
            trim( headerLine );
            content_length = atol( &(headerLine[15]) );
        }
        headerLine = nextLine ? (nextLine + 1) : NULL;
    }

    if ( content_length != -1 )
        for ( i = 0; i < content_length && ( recv(client, &ich, 1, 0) ) > 0; ++i )
            fputc( ich, sockwfp );
    (void) fflush( sockwfp );

    (void) alarm( TIMEOUT );
    content_length = -1;
    first_line = 1;
    status = -1;
    while ( fgets( line, sizeof(line), sockrfp ) != (char*) 0 )
    {
        if ( strcmp( line, "\n" ) == 0 || strcmp( line, "\r\n" ) == 0 )
            break;
        (void) send(client, line, strlen(line), 0);
        (void) alarm( TIMEOUT );
        trim( line );
        if ( first_line )
        {
            (void) sscanf( line, "%[^ ] %d %s", protocol2, &status, comment );
            first_line = 0;
        }
        if ( strncasecmp( line, "Content-Length:", 15 ) == 0 )
            content_length = atol( &(line[15]) );
    }

    send(client, connection_close, strlen(connection_close), 0);
    (void) send(client, line, strlen(line), 0);

    if ( strcasecmp( method, "HEAD" ) != 0 && status != 304 )
    {

        for ( i = 0;
                ( content_length == -1 || i < content_length ) && ( ich = getc( sockrfp ) ) != EOF;
                ++i )
        {
            send(client, &ich, 1, 0);
            if ( i % 10000 == 0 )
                (void) alarm( TIMEOUT );
        }
    }
}


static void
proxy_ssl( int client, char* method, char* host, char* protocol, char* headers, FILE* sockrfp, FILE* sockwfp )
{
    int client_read_fd, server_read_fd, client_write_fd, server_write_fd;
    struct timeval timeout;
    fd_set fdset;
    int maxp1, r;
    char buf[10000];
    const char *connection_established = "HTTP/1.0 200 Connection established\r\n\r\n";

    send(client, connection_established, strlen(connection_established), 0);
    client_read_fd = client;
    server_read_fd = fileno( sockrfp );
    client_write_fd = client;
    server_write_fd = fileno( sockwfp );
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    if ( client_read_fd >= server_read_fd )
        maxp1 = client_read_fd + 1;
    else
        maxp1 = server_read_fd + 1;
    (void) alarm( 0 );
    for (;;)
    {
        FD_ZERO( &fdset );
        FD_SET( client_read_fd, &fdset );
        FD_SET( server_read_fd, &fdset );
        r = select( maxp1, &fdset, (fd_set*) 0, (fd_set*) 0, &timeout );
        if ( r == 0 ) {
            return;
        }
        else if ( FD_ISSET( client_read_fd, &fdset ) )
        {
            r = read( client_read_fd, buf, sizeof( buf ) );
            if ( r <= 0 )
                break;
            r = write( server_write_fd, buf, r );
            if ( r <= 0 )
                break;
        }
        else if ( FD_ISSET( server_read_fd, &fdset ) )
        {
            r = read( server_read_fd, buf, sizeof( buf ) );
            if ( r <= 0 )
                break;
            r = write( client_write_fd, buf, r );
            if ( r <= 0 )
                break;
        }
    }
}


static void
sigcatch( int sig )
{

}


static void
trim( char* line )
{
    int l;

    l = strlen( line );
    while ( line[l-1] == '\n' || line[l-1] == '\r' )
        line[--l] = '\0';
}




void *accept_request(void *_client)
{
    int client = (int) (long) _client;
    int numchars;

    char line[10000], method[10000], url[10000], protocol[10000], host[10000], path[10000], headers[20000];
    unsigned short port;
    int iport;
    int sockfd;
    int ssl;
    int headers_len = 0;
    FILE* sockrfp;
    FILE* sockwfp;

    numchars = get_line(client, line, sizeof(line));

    if ( numchars == 0 ) {
 
        return NULL;
    }


    trim( line );
    if ( sscanf( line, "%[^ ] %[^ ] %[^ ]", method, url, protocol ) != 3 ) {

        return NULL;
    }

    if ( url[0] == '\0' ) {

        return NULL;
    }

    if ( strncasecmp( url, "http://", 7 ) == 0 )
    {
        (void) strncpy( url, "http", 4 );       
        if ( sscanf( url, "http://%[^:/]:%d%s", host, &iport, path ) == 3 )
            port = (unsigned short) iport;
        else if ( sscanf( url, "http://%[^/]%s", host, path ) == 2 )
            port = 80;
        else if ( sscanf( url, "http://%[^:/]:%d", host, &iport ) == 2 )
        {
            port = (unsigned short) iport;
            *path = '\0';
        }
        else if ( sscanf( url, "http://%[^/]", host ) == 1 )
        {
            port = 80;
            *path = '\0';
        }
        else {

            return NULL;
        }
        ssl = 0;
    }
    else if ( strcmp( method, "CONNECT" ) == 0 )
    {
        if ( sscanf( url, "%[^:]:%d", host, &iport ) == 2 )
            port = (unsigned short) iport;
        else if ( sscanf( url, "%s", host ) == 1 )
            port = 443;
        else {

            return NULL;
        }
        ssl = 1;
    }
    else {

        return NULL;
    }


    (void) signal( SIGALRM, sigcatch );


    (void) alarm( TIMEOUT );
    while ( get_line(client, line, sizeof(line)) > 0 )
    {
        int line_len = strlen(line);
        (void) alarm( TIMEOUT );
        memcpy(&headers[headers_len], line, line_len);
        headers_len += line_len;
        if ( strcmp( line, "\n" ) == 0 || strcmp( line, "\r\n" ) == 0 )
            break;
    }
    headers[headers_len] = '\0';


    (void) alarm( TIMEOUT );
    sockfd = open_client_socket( client, host, port );

    if (sockfd >= 0) {

        sockrfp = fdopen( sockfd, "r" );
        sockwfp = fdopen( sockfd, "w" );

        if ( ssl )
            proxy_ssl( client, method, host, protocol, headers, sockrfp, sockwfp );
        else
            proxy_http( client, method, path, protocol, headers, sockrfp, sockwfp );


        (void) close( sockfd );
    }

    close(client);
    return NULL;
}


void bad_request(int client)
{
    char buf[1024];

    snprintf(buf, 1024, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, strlen(buf), 0);
    snprintf(buf, 1024, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    snprintf(buf, 1024, "\r\n");
    send(client, buf, strlen(buf), 0);
    snprintf(buf, 1024, "<P>Your browser sent a bad request, ");
    send(client, buf, strlen(buf), 0);
    snprintf(buf, 1024, "such as a POST without a Content-Length.\r\n");
    send(client, buf, strlen(buf), 0);
}


void print_error(const char *sc)
{
    printf(sc);
    exit(1);
}


int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(sock, &c, 1, 0);

        if (n > 0)
        {
            if (c == '\r')
            {
                n = recv(sock, &c, 1, MSG_PEEK);
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';
    printf(buf);

    return(i);
}


int startup(u_short *port)
{
    int httpd = 0;
    struct sockaddr_in name;

    httpd = socket(PF_INET, SOCK_STREAM, 0);
    if (httpd == -1)
        print_error("socket");
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(*port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
        print_error("bind");
    if (*port == 0)  
    {
        unsigned int namelen = (unsigned int) sizeof(name);
        if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
            print_error("getsockname");
        *port = ntohs(name.sin_port);
    }
    if (listen(httpd, 5) < 0)
        print_error("listen");
    return(httpd);
}



int main(int argc, const char **argv)
{
    int server_sock = -1;
    u_short port = 0;
    int client_sock = -1;
    struct sockaddr_in client_name;
    unsigned int client_name_len = (unsigned int) sizeof(client_name);
    pthread_t newthread;

    if (argc == 2)
    {
        port = (u_short) atoi(argv[1]);
    }

    server_sock = startup(&port);
    printf("httpd running on port %d\n", port);

    while (1)
    {
        client_sock = accept(server_sock,
                             (struct sockaddr *)&client_name,
                             &client_name_len);
        if (client_sock == -1)
            print_error("accept");
        if (pthread_create(&newthread , NULL, &accept_request, (void *)(long)client_sock) != 0)
            perror("pthread_create");
    }

    close(server_sock);

    return(0);
}
