/*
// compile with
// gcc *.c -lssl -lcrypto -O3 -o OUTFULE.NAME
*/
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define COLOR_NC "\e[0m"
#define COLOR_BLACK "\e[0;30m"
#define COLOR_BLUE "\e[0;34m"
#define COLOR_LIGHT_BLUE "\e[1;34m"
#define COLOR_GREEN "\e[0;32m"
#define COLOR_LIGHT_GREEN "\e[1;32m"
#define COLOR_CYAN "\e[0;36m"
#define COLOR_LIGHT_CYAN "\e[1;36m"
#define COLOR_RED "\e[0;31m"
#define COLOR_LIGHT_RED "\e[1;31m"
#define COLOR_PURPLE "\e[0;35m"
#define COLOR_LIGHT_PURPLE "\e[1;35m"
#define COLOR_BROWN "\e[0;33m"
#define COLOR_YELLOW "\e[1;33m"
#define COLOR_GRAY "\e[0;30m"
#define COLOR_LIGHT_GRAY "\e[0;37m"

#define FAIL -1

// holy fuck this is so BAD

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);
    if (connect(sd, &addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX *InitCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();              // THANKS GOOGLE
    OpenSSL_add_all_algorithms();    /* Load cryptos, et.al. */
    SSL_load_error_strings();        /* Bring in and register error messages */
    method = SSLv23_client_method(); /* Create new client-method instance */
    ctx = SSL_CTX_new(method);       /* Create new context */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

int server;
char sbuf[512];
SSL *ssl;

void raw(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(sbuf, 512, fmt, ap);
    va_end(ap);
    printf("<< %s", sbuf);
    SSL_write(ssl, sbuf, strlen(sbuf)); /* encrypt & send message */
}

// wrote this to make life easier
void sendMessage(char *target, char *message)
{
    raw("PRIVMSG %s :%s\r\n", target, message);
}

void checkForCMD(char *user, char *command, char *where, char *target, char *message)
{
// some black magic voodoo from russia
#define strcmp0(a, b) strncmp(a, b, sizeof(b))

    //printf("[from: %s] [reply-with: %s] [where: %s] [reply-to: %s] %s", user, command, where, target, message);
    printf(COLOR_GREEN "[%s] " COLOR_CYAN "%s: " COLOR_NC "%s", where, user, message);

    if (strstr(message, "@forsen") != NULL) // alerts on certain messages, just an example of possibilities
        printf("\a");


    // test func
    char *reply = "funky shit";
    //if (!strncmp(message, ".test", 5)) // if you want to use _native_ method
    if (!strcmp0(message, ".test"))
    {
        //sendMessage(where, reply);
    }
}

int main()
{
    SSL_CTX *ctx;
    char buf[513]; // not experienced enough to tell if this size matters
    int bytes;

    char *nick = "justinfan14488";     // bot's NICKNAME
    char *channel = "#forsen";         // channel to join
    char *host = "irc.chat.twitch.tv"; // server address/ip
    char *port = "6697";               // server's port

    ctx = InitCTX();
    server = OpenConnection(host, atoi(port));
    ssl = SSL_new(ctx);           /* create new SSL connection state */
    SSL_set_fd(ssl, server);      /* attach the socket descriptor */
    if (SSL_connect(ssl) == FAIL) /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        raw("NICK %s\r\n", nick);
        raw("JOIN %s\r\n", channel); // todo: add multichannel support i.e. an array of channels

        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

        char *user, *command, *where, *message, *sep, *target;
        int i, j, l, sl, o = -1, start, wordcount;
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof hints);

        while ((sl = SSL_read(ssl, sbuf, 512)))
        {
            for (i = 0; i < sl; i++)
            {
                o++;
                buf[o] = sbuf[i];
                if ((i > 0 && sbuf[i] == '\n' && sbuf[i - 1] == '\r') || o == 512)
                {
                    buf[o + 1] = '\0';
                    l = o;
                    o = -1;

                    //printf(">> %s", buf);

                    if (!strncmp(buf, "PING", 4))
                    {
                        buf[1] = 'O';
                        raw(buf);
                    }
                    else if (buf[0] == ':')
                    {
                        wordcount = 0;
                        user = command = where = message = NULL;
                        for (j = 1; j < l; j++)
                        {
                            if (buf[j] == ' ')
                            {
                                buf[j] = '\0';
                                wordcount++;
                                switch (wordcount)
                                {
                                case 1:
                                    user = buf + 1;
                                    break;
                                case 2:
                                    command = buf + start;
                                    break;
                                case 3:
                                    where = buf + start;
                                    break;
                                }
                                if (j == l - 1)
                                    continue;
                                start = j + 1;
                            }
                            else if (buf[j] == ':' && wordcount == 3)
                            {
                                if (j < l - 1)
                                    message = buf + j + 1;
                                break;
                            }
                        }

                        if (wordcount < 2)
                            continue;

                        if (!strncmp(command, "001", 3) && channel != NULL)
                        {
                            raw("JOIN %s\r\n", channel); // todo: add multichannel support i.e. an array of channels
                        }
                        else if (!strncmp(command, "PRIVMSG", 7) || !strncmp(command, "NOTICE", 6))
                        {
                            if (where == NULL || message == NULL)
                                continue;
                            if ((sep = strchr(user, '!')) != NULL)
                                user[sep - user] = '\0';
                            if (where[0] == '#' || where[0] == '&' || where[0] == '+' || where[0] == '!')
                                target = where;
                            else
                                target = user;
                            checkForCMD(user, command, where, target, message);
                        }
                    }
                }
            }
        }
        SSL_free(ssl); /* release connection state */
    }
    close(server); /* close socket */
    SSL_CTX_free(ctx);
    return 0;
}
