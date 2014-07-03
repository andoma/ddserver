#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "libsvc/libsvc.h"
#include "libsvc/cfg.h"
#include "libsvc/trace.h"
#include "libsvc/misc.h"

#ifdef WITH_HTTP_SERVER
#include "libsvc/http.h"
#endif

#ifdef WITH_CTRLSOCK
#include "libsvc/ctrlsock.h"
#endif


static int running = 1;
static int reload = 0;

/**
 *
 */
static void
handle_sigpipe(int x)
{
  return;
}


/**
 *
 */
static void
doexit(int x)
{
  running = 0;
}


/**
 *
 */
static void
doreload(int x)
{
  reload = 1;
}


/**
 *
 */
static void
refresh_subsystems(void)
{
}


#ifdef WITH_HTTP_SERVER
/**
 *
 */
static void
http_init(void)
{
  cfg_root(cr);

  int port = cfg_get_int(cr, CFG("http", "port"), 9000);
  const char *bindaddr = cfg_get_str(cr, CFG("http", "bindAddress"),
                                     "127.0.0.1");
  if(http_server_init(port, bindaddr))
    exit(1);
}
#endif


/**
 *
 */

static int
ddns_update(http_connection_t *hc, const char *remain, void *opaque)
{
  cfg_root(root);

  const char *keypath = cfg_get_str(root, CFG("ddns", "keyfile"), NULL);
  const char *server  = cfg_get_str(root, CFG("ddns", "server"), NULL);
  const char *zone    = cfg_get_str(root, CFG("ddns", "zone"), NULL);

  if(keypath == NULL || server == NULL || zone == NULL)
    return 500;

  if(hc->hc_username == NULL || hc->hc_password == NULL)
    return 403;


  const char *pw = cfg_get_str(root, CFG("users",
                                         hc->hc_username,
                                         "password"), NULL);

  if(pw == NULL || strcmp(pw, hc->hc_password))
    return 403;

  const char *hostname = http_arg_get(&hc->hc_req_args, "hostname");
  if(hostname == NULL)
    return 400;

  char *hostnames[20];
  char *h = mystrdupa(hostname);
  int num_hostnames = str_tokenize(h, hostnames, 20, ',');

  const char *myip = http_arg_get(&hc->hc_req_args, "myip");

  if(myip != NULL) {
    int x = inet_addr(myip);
    if(x == 0)
      myip = NULL;

    x = ntohl(x);
    if((x & 0xff000000) == 0x0a000000)
      myip = NULL;
    if((x & 0xffff0000) == 0xc0a80000)
      myip = NULL;
    if((x & 0xfff00000) == 0xac100000)
      myip = NULL;
  }

  if(myip == NULL)
    myip = http_arg_get(&hc->hc_args, "X-Forwarded-For");

  if(myip == NULL) {
    char buf[64];
    inet_ntop(AF_INET, &hc->hc_peer->sin_addr, buf, 64);
    myip = buf;
  }

  for(int i = 0; i < num_hostnames; i++) {
    const char *h = hostnames[i];

    for(int j = 0; ; j++) {
      const char *okhost = cfg_get_str(root, CFG("users",
                                                 hc->hc_username,
                                                 "hostnames",
                                                 CFG_INDEX(j)), NULL);
      if(okhost == NULL)
        break;

      if(strcmp(okhost, h))
        return 403;
    }

  }

  for(int i = 0; i < num_hostnames; i++)
    trace(LOG_INFO, "Update %s -> %s (by user %s)",
          hostnames[i], myip, hc->hc_username);

  char cmd[512];

  snprintf(cmd, sizeof(cmd), "nsupdate -k %s", keypath);
  FILE *f = popen(cmd, "w");
  if(f == NULL)
    return 502;

  fprintf(f, "server %s\n", server);
  fprintf(f, "zone %s\n", zone);

  for(int i = 0; i < num_hostnames; i++)
    fprintf(f, "update delete %s\n", hostnames[i]);

  for(int i = 0; i < num_hostnames; i++)
    fprintf(f, "update add %s 60 A %s\n", hostnames[i], myip);

  fprintf(f, "send\n");
  fclose(f);
  return 200;
}



/**
 *
 */
int
main(int argc, char **argv)
{
  int c;
  sigset_t set;
  const char *cfgfile = NULL;
#ifdef WITH_CTRLSOCK
  const char *ctrlsockpath = "/tmp/"PROGNAME"ctrl";
#endif
  const char *defconf = PROGNAME".json";

  signal(SIGPIPE, handle_sigpipe);

  while((c = getopt(argc, argv, "c:s:")) != -1) {
    switch(c) {
    case 'c':
      cfgfile = optarg;
      break;
    case 's':
      enable_syslog(PROGNAME, optarg);
      break;
    }
  }

  sigfillset(&set);
  sigprocmask(SIG_BLOCK, &set, NULL);

  srand48(getpid() ^ time(NULL));

  if(cfg_load(cfgfile, defconf)) {
    fprintf(stderr, "Unable to load config (check -c option). Giving up\n");
    exit(1);
  }

  libsvc_init();

#ifdef WITH_CTRLSOCK
  ctrlsock_init(ctrlsockpath);
#endif

#ifdef WITH_HTTP_SERVER
  http_init();
#endif

  http_path_add("/update", NULL, ddns_update);

  running = 1;
  sigemptyset(&set);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGHUP);

  signal(SIGTERM, doexit);
  signal(SIGINT, doexit);
  signal(SIGHUP, doreload);

  pthread_sigmask(SIG_UNBLOCK, &set, NULL);

  while(running) {
    if(reload) {
      reload = 0;
      if(!cfg_load(NULL, defconf)) {
        refresh_subsystems();
      }
    }
    pause();
  }

  return 0;
}
