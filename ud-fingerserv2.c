/* $Id# */
/* compile: gcc -Wall -o ud-fingerserv2 ud-fingerserv2.c */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#define PROGNAME         "ud-fingerserv"
#define VERSION          "0.90"
#define PROGDATE         "1999/12/10"

#define FINGERPORT       79
#define TIMEOUT          600 /* seconds */
#define PERROR(ctx)      do { perror(ctx); exit(1); } while (0);
#define DEFAULTLOGFILE   "/var/log/ud-fingerserv.log"

#define OPT_INETD     1
#define OPT_LOGSCR    (1 << 1)

static FILE *g_logfs = NULL;
static char *g_logfn = NULL;
static int g_options = 0;

int processcxn(int, struct sockaddr_in *);
void logf(char *fmt, ...);
void cleanup(void);
void timeout(void);
void usage(void);
void sendhelp(void);

/* ********************************************************************** */

int processcxn(int s, struct sockaddr_in *rmtaddr)
{
    printf("connected\n");
    return 0;
}

void sendhelp(void)
{
}

void logf(char *fmt, ...)
{
    va_list ap;
    time_t t;
    char logline[1024];
    char *ts;
   
    t = time(NULL);
    ts = ctime(&t);
    ts[strlen(ts)-1] = 0; /* remove stupid newline */
    
    if (g_logfs == NULL) {
        if (g_logfn == NULL) g_logfn = DEFAULTLOGFILE;
        if ((g_logfs = fopen(g_logfn, "a")) == NULL && !(g_options & OPT_LOGSCR)) PERROR("logf");        
    }   
   
    vsnprintf(logline, sizeof(logline), fmt, ap);
    if (g_logfs) {
        fprintf(g_logfs, "[%s] " PROGNAME ": %s\n", ts, logline);
        fflush(g_logfs);
    }
	
    if (g_options & OPT_LOGSCR) printf("[%s] " PROGNAME ": %s\n", ts, logline);
}

void cleanup(void)
{
    if (g_logfs) fclose(g_logfs);
}

void usage(void)
{
    fprintf(stderr, "ud-fingerserv " VERSION " " PROGDATE "\n");
    fprintf(stderr, "\t(c) 1999 Randolph Chung <tausq@debian.org>. Released under the GPL\n");
    fprintf(stderr, "\tThe following options are recognized:\n");
    fprintf(stderr, "\t\t-h : this help text\n");
    fprintf(stderr, "\t\t-i : run in inetd mode; otherwise runs in standalone mode\n");
    fprintf(stderr, "\t\t-v : logs messages to stdout in addition to log file\n");
    fprintf(stderr, "\t\t-l <file> : use <file> as the log file, instead of " DEFAULTLOGFILE "\n"); 
    exit(0);
}

int main(int argc, char *argv[])
{
    int ls, as;
    int r;
    struct sockaddr_in myaddr, rmtaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);  
   
    atexit(cleanup);
   
    while ((r = getopt(argc, argv, "hivl:")) > 0) {
        switch (r) {
	 case 'i': g_options |= OPT_INETD; break;
	 case 'v': g_options |= OPT_LOGSCR; break;
	 case 'l': g_logfn = strdup(optarg); break;
	 default: usage();
	}
    }

    if (g_options & OPT_INETD) {
        getsockname(fileno(stdin), &rmtaddr, &addrlen);
        processcxn(fileno(stdin), &rmtaddr);
    } else {
        if ((ls = socket(AF_INET, SOCK_STREAM, 0)) < 0) PERROR("socket");
        memset(&myaddr, 0, sizeof(myaddr));
        myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        myaddr.sin_port = htons(FINGERPORT);
        if (bind(ls, &myaddr, sizeof(myaddr)) < 0) PERROR("bind");
        if (listen(ls, SOMAXCONN) < 0) PERROR("listen");
        logf("Waiting for connection");
        while ((as = accept(ls, &rmtaddr, &addrlen))) {
            if ((r = fork()) == 0) {
	        processcxn(as, &rmtaddr);
   	        exit(0);
            } else {
	        if (r < 0) PERROR("fork");
  	    }
        }
    }
   
    return 0;
}

