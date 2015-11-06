
//############################################################################//

/** \file mcsak.cpp
 * \brief multicast swiss army knife
 */

// I N C L U D E S ###########################################################//

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>

#include <syslog.h>
#include <ini.h>

#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

// D E F I N E S #############################################################//

#ifdef PACKAGE_VERSION
# define MCSAK_VERSION PACKAGE_VERSION
#else
# define MCSAK_VERSION "unknown"
#endif

// TODO - change to enable/disable from ac
#ifdef HAVE_CLOCK_GETTIME
# define MCSAK_TIME_PREC 1000000000
# define MCSAK_TIME_FRAC_TOUSEC(a) (a / 1000)
#else
# define MCSAK_TIME_PREC 1000000
# define MCSAK_TIME_FRAC_TOUSEC(a) a
#endif

#define MCSAK__TOSTRING(a) #a
#define MCSAK_TOSTRING(a) MCSAK__TOSTRING(a)

#define MCSAK_DEBUG(lvl, ...) \
  { \
  if(opt_debuglvl >= lvl) \
    { \
    char *fmt_msg__ = fmt_string(__VA_ARGS__); \
    if(fmt_msg__) \
      { \
      if(!opt_quiet && opt_logfile) \
        log_file(fmt_msg__); \
      if(opt_syslog) \
        log_syslog(fmt_msg__); \
      free(fmt_msg__); \
      } \
    else \
      perror("fmt_string"); \
    } \
  }

#define MCSAK_ERROR(...)  MCSAK_DEBUG(0, __VA_ARGS__)

#define MCSAK_PRINT(...) \
  { \
  if(!opt_quiet) \
    { \
    char *fmt_msg__ = fmt_string(__VA_ARGS__); \
    if(fmt_msg__) \
      { \
      fputs(fmt_msg__, stdout); \
      free(fmt_msg__); \
      } \
    else \
      perror("fmt_string"); \
    } \
  }


#define MCSAK_DIE_USAGE(...) \
  { \
  char *fmt_msg__ = fmt_string(__VA_ARGS__); \
  if(fmt_msg__) \
    { \
    die_usage(fmt_msg__); \
    free(fmt_msg__); \
    } \
  else \
    die_usage(0); \
  }

#define MCSAK_DIE_ERROR(...) \
  { \
  MCSAK_ERROR(__VA_ARGS__); \
  exit(EXIT_FAILURE); \
  }

#define MCSAK_RET_SYSLOG_FAC(fac) \
  { \
  MCSAK_DEBUG(1, "setting syslog to " #fac); \
  return fac; \
  }

// host + port + dividing char + null
#define MCSAK_MAXNAME NI_MAXHOST + NI_MAXSERV + 2

//############################################################################//

typedef struct
  {
  time_t sec;
  int64_t frac;
  } mcsak_timestamp_t;

typedef struct
  {
  char *group;
  char *port;
  char *name;
  char *interface;
  char *decoder;
  char *mtu;
  char *capture_file;
  char *capture_format;
  } group_def_t;

typedef struct group_t group_t;
typedef const char* (*decoder_t)(struct group_t*);

struct group_t
  {
  int fd;

  char group[NI_MAXHOST];
  int port;
  char name[MCSAK_MAXNAME];

  uint16_t mtu;
  uint16_t sz;
  char *buf;
  decoder_t decode;

  int count;
  int gaps;
  uint32_t seq;

  FILE *capture_file;
  decoder_t capture;
  };

uint64_t opt_count = 0;
int opt_daemon = 0;
int opt_debuglvl = 0;
uint8_t opt_quiet = 0;
FILE *opt_logfile = 0;
int opt_syslog = 0;
int opt_syslog_fac = 0;
char *opt_fmt_timestamp = 0;

int opt_namelookup = 0;

mcsak_timestamp_t start;
int mtu = 0;

group_def_t *grpdef[255];
int ngrpdefs = 0;

//############################################################################//

void
die_usage(const char *msg)
  {
  if(msg)
    fprintf(stderr, "%s\n", msg);

  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: mcsak [OPTIONS] <multicast_address:port>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -CN          max packet count, exit when hit\n");
  fprintf(stderr, "  -cFILE       config FILE\n");
  fprintf(stderr, "  -d           daemonize\n");
  fprintf(stderr, "  -eFORMAT     capture file encoding format [lv]\n");
  fprintf(stderr, "                 lv    simple length value <uint16_t><data...>\n");
  fprintf(stderr, "                 pcap  <header><packet header><packet data> incomplete\n");
  fprintf(stderr, "                 raw   <data>\n");
  fprintf(stderr, "  -FFILE       capture FILE\n");
  fprintf(stderr, "  -fFORMAT     decode packets based on FORMAT [none]\n");
  fprintf(stderr, "                 (t)ext, (h)ex, (f)ast, (i)ce\n");
  fprintf(stderr, "  -h           show help and exit\n");
  fprintf(stderr, "  -iI          use interface I\n");
  fprintf(stderr, "  -lFILE       log alerts to FILE\n");
  fprintf(stderr, "  -mN          use max packet size of N\n");
  fprintf(stderr, "  -NNAME       use NAME instead of group port when logging\n");
  fprintf(stderr, "  -n           don't convert host addresses to names\n");
  fprintf(stderr, "  -q           quiet, squelch output except for alerts\n");
  fprintf(stderr, "  -SFACILITY   log to syslog FACILITY [user]\n");
  fprintf(stderr, "                 0-7 for local\n");
  fprintf(stderr, "  -TFORMAT     timestamp FORMAT as passed to strftime\n");
  fprintf(stderr, "  -V           display version and exit\n");
  fprintf(stderr, "  -v           verbosity (up to 3)\n");
  fprintf(stderr, "\n");
  exit(EXIT_FAILURE);
  }

//############################################################################//

int
to_bool(const char *str)
  {
  if(!strcmp(str, "1"))
    return 1;
  if(!strcmp(str, "y"))
    return 1;
  if(!strcmp(str, "yes"))
    return 1;

  return 0;
  }

//############################################################################//

char*
fmt_string(const char *fmt, ...)
  {
  int n, size = 100;
  char *str, *tmp;
  va_list ap;


  if(!fmt)
    return 0;

  if(!(str = malloc(size)))
    {
    perror("malloc");
    return 0;
    }

  while(1)
    {
    va_start(ap, fmt);
    n = vsnprintf (str, size, fmt, ap);
    va_end(ap);

    // If that worked, return the string
    if(n > -1 && n < size)
      return str;

    // glibc 2.0
    if(n == -1)
      size *= 2;
    else
      size = n + 1;

    if(!(tmp = realloc(str, size)))
      {
      free(str);
      perror("realloc");
      return 0;
      }
    str = tmp;
    }
  }

//############################################################################//
// @params flags 1 for realtime (default monotick if available)
// @return 0 on success, -1 on failure

int
time_get(mcsak_timestamp_t *rv, int flags)
  {
#ifdef HAVE_CLOCK_GETTIME
  struct timespec ts;

  if(clock_gettime(flags == 1 ? CLOCK_MONOTONIC : CLOCK_REALTIME, &ts))
    {
    perror("clock_gettime");
    return -1;
    }

  rv->sec = ts.tv_sec;
  rv->frac = ts.tv_nsec;
  return 0;

#else
  struct timeval ts;

  if(gettimeofday(&ts, 0))
    {
    perror("clock_gettime");
    return -1;
    }

  rv->sec = ts.tv_sec;
  rv->frac = ts.tv_usec;
  return 0;
#endif
  }

//############################################################################//

double
time_elapsed()
  {
  time_t seconds;
  double frac;
  mcsak_timestamp_t end;

  if(time_get(&end, 0))
    return 0;

  seconds = (end.sec - start.sec);
  frac = (double)((end.frac < start.frac) ?
   ((MCSAK_TIME_PREC - start.frac) + end.frac) : end.frac - start.frac);
  return(seconds + frac / MCSAK_TIME_PREC);
  }

//############################################################################//

char*
fmt_timestamp()
  {
  static char tsbuf[128];
  size_t sz;
  mcsak_timestamp_t ts;
  struct tm ltm;


  time_get(&ts, 1);
  localtime_r(&ts.sec, &ltm);
  sz = strftime(tsbuf, sizeof(tsbuf), opt_fmt_timestamp, &ltm);
  snprintf(tsbuf + sz, sizeof(tsbuf) - sz, ".%" PRIi64, ts.frac);
  return tsbuf;
  }

//############################################################################//

void
log_syslog(const char *msg)
  {
  syslog(LOG_ERR, "%s", msg);
  }

//############################################################################//

void
log_file(const char *msg)
  {
  if(!opt_logfile)
    return;

  fprintf(opt_logfile, "%s %s\n", fmt_timestamp(), msg);
  }

//############################################################################//

void
alert_gap(const group_t *grp, uint32_t seq)
  {
  MCSAK_ERROR("group:%s seq:%d eseq:%d gaps:%d count:%d", grp->name, seq, grp->seq, grp->gaps, grp->count);
  }

//############################################################################//
//! find : and set to null, then return the next byte

char *
port_from_addr(char *str)
  {
  char *rv;

  if(!(rv = strrchr(str, ':')))
    MCSAK_DIE_ERROR("could not find port in address='%s'", str);

  *rv = '\0';
  return ++rv;
  }

//############################################################################//

const char*
capture_lv(group_t *grp)
  {
  if(fwrite(&grp->sz, sizeof(uint16_t), 1, grp->capture_file) != 1)
    {
    MCSAK_ERROR("malformed packet");
    return 0;
    }
  MCSAK_DEBUG(1, "writing %u\n", grp->sz);
  if(fwrite(grp->buf, grp->sz, 1, grp->capture_file) != 1)
    {
    MCSAK_ERROR("malformed packet");
    return 0;
    }

  return 0;
  }

//# pcap v1 ##################################################################//

typedef struct
  {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t linktype;
  } pcap_file_hdr;

typedef struct
  {
  uint32_t tv_sec;
  uint32_t tv_usec;
  uint32_t caplen;
  uint32_t origlen;
  } pcap_pkt_hdr;

//############################################################################//

const char*
pcap_capture_init(group_t *grp)
  {
  pcap_file_hdr hdr;

  hdr.magic = 0xa1b2c3d4;
  hdr.version_major = 2;
  hdr.version_minor = 4;
  // FIXME - get zone
  hdr.thiszone = 0;
  hdr.sigfigs = 0;
  hdr.snaplen = grp->mtu;
  // 1 is ethernet
  hdr.linktype = 1;

  if(fwrite(&hdr, sizeof(pcap_file_hdr), 1, grp->capture_file) != 1)
    {
    MCSAK_ERROR("failed to write file header");
    return 0;
    }

  return 0;
  }

//############################################################################//

const char*
capture_pcap(group_t *grp)
  {
  pcap_pkt_hdr hdr;
  mcsak_timestamp_t ts;
  uint8_t zero = 0;
  size_t hdr_sz = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);


  if(time_get(&ts, 1))
    {
    perror("time_get");
    return 0;
    }

  hdr.tv_sec = ts.sec;
  hdr.tv_usec = MCSAK_TIME_FRAC_TOUSEC(ts.frac);
  hdr.caplen = hdr.origlen = grp->sz;
//  hdr.caplen = hdr.origlen = htonl(grp->sz);

  if(fwrite(&zero, 1, hdr_sz, grp->capture_file) != hdr_sz)
    {
    MCSAK_ERROR("malformed packet");
    return 0;
    }

  if(fwrite(&hdr, sizeof(pcap_pkt_hdr), 1, grp->capture_file) != 1)
    {
    MCSAK_ERROR("malformed packet");
    return 0;
    }
  if(fwrite(grp->buf, grp->sz, 1, grp->capture_file) != 1)
    {
    MCSAK_ERROR("malformed packet");
    return 0;
    }

  return 0;
  }

//############################################################################//

const char*
capture_raw(group_t *grp)
  {
  MCSAK_DEBUG(1, "writing %u\n", grp->sz);
  if(fwrite(grp->buf, grp->sz, 1, grp->capture_file) != 1)
    {
    MCSAK_ERROR("malformed packet");
    return 0;
    }

  return 0;
  }

//############################################################################//
//! decode CME FAST 2.0 or MDP 3.0 packets
//! sequence number is the first 32 bits of the preamble in big endian

const char*
decode_cme(group_t *grp)
  {
  const char *buf = grp->buf;


  if(grp->sz < 4)
    {
    MCSAK_ERROR("malformed packet");
    return 0;
    }

  // big endian
  uint32_t seq = ((uint32_t) ((uint8_t)buf[0]) << 24)
               | ((uint32_t) ((uint8_t)buf[1]) << 16)
               | ((uint32_t) ((uint8_t)buf[2]) << 8)
               |  (uint32_t) ((uint8_t)buf[3]);


  ++grp->count;

  if(grp->seq && grp->seq + 1 != seq)
    {
    if(seq == 0 || seq == 1)
      {
      MCSAK_ERROR("group:%s seq reset to %d", grp->name, seq);
      grp->count = grp->gaps = 0;
      grp->seq = seq;
      }
    else
      {
      ++grp->gaps;
      alert_gap(grp, seq);
      }
    }

  MCSAK_PRINT("  seq:%d gaps:%d count:%d time:%gs\n", grp->seq, grp->gaps, grp->count, time_elapsed());
  grp->seq = seq;
  return 0;
  }

//############################################################################//

const char*
decode_hex(group_t *grp)
  {
  size_t i;

  size_t sz = grp->sz;
  const char *buf = grp->buf;


  for(i=0; i<sz; ++i)
    {
    if(!(i % 16))
      {
      if(i)
        MCSAK_PRINT("\n");
      MCSAK_PRINT("  %04ld  ", i);
      }
    MCSAK_PRINT("%02x %c", (unsigned char)buf[i], i % 8 == 7 ? ' ' : '\0');
    }
  MCSAK_PRINT("\n");
  return 0;
  }

//############################################################################//
//! decode ICE iMpact
//! message count is the first 16 bits of the packet
//! sequence number is the next 32 bits of the preamble
//! both big endian

const char*
decode_ice(group_t *grp)
  {
  const char *buf = grp->buf;


  if(grp->sz < 8)
    {
    MCSAK_ERROR("malformed packet");
    return 0;
    }

  // big endian
  uint32_t seq = ((uint32_t) ((uint8_t)buf[2]) << 24)
               | ((uint32_t) ((uint8_t)buf[3]) << 16)
               | ((uint32_t) ((uint8_t)buf[4]) << 8)
               |  (uint32_t) ((uint8_t)buf[5]);
  uint16_t mcnt = ((uint32_t) ((uint8_t)buf[6]) << 8)
                |  (uint32_t) ((uint8_t)buf[7]);

  ++grp->count;

  if(grp->seq && grp->seq != seq)
    {
    if(seq == 0 || seq == 1)
      {
      MCSAK_ERROR("group:%s seq reset to %d", grp->name, seq);
      grp->count = grp->gaps = 0;
      grp->seq = seq + mcnt;
      }
    else
      {
      ++grp->gaps;
      alert_gap(grp, seq);
      }
    }

  MCSAK_PRINT("  seq:%d mcnt:%d gaps:%d count:%d time:%g\n", seq, mcnt, grp->gaps, grp->count, time_elapsed());
  grp->seq = seq + mcnt;
  return 0;
  }

//############################################################################//

const char*
decode_text(group_t *grp)
  {
  size_t i;

  size_t sz = grp->sz;
  const char *buf = grp->buf;


  MCSAK_PRINT("  ");
  for(i=0; i<sz; ++i)
    MCSAK_PRINT("%c", buf[i]);
  MCSAK_PRINT("\n");
  return 0;
  }

//############################################################################//

decoder_t
parse_capture(const char *fmt)
  {
// TODO - make capture struct with init, capture, close
  if(!fmt)
    return capture_lv;
  if(!strcmp(fmt, "lv"))
    return capture_lv;
  if(!strcmp(fmt, "pcap"))
    return capture_pcap;
  if(!strcmp(fmt, "raw"))
    return capture_raw;

  MCSAK_ERROR("invalid capture format");
  return 0;
  }

//############################################################################//

decoder_t
parse_decoder(const char *fmt)
  {
  if(!fmt)
    return 0;
  if(!strcmp(fmt, "cme"))
    return decode_cme;
  if(!strcmp(fmt, "hex"))
    return decode_hex;
  if(!strcmp(fmt, "ice"))
    return decode_ice;
  if(!strcmp(fmt, "text"))
    return decode_text;

  MCSAK_ERROR("invalid decode format");
  return 0;
  }

//############################################################################//

void
free_group(group_t *grp)
  {
  free(grp->buf);
  free(grp);
  }

//############################################################################//
//! @param flags 1 for passive/receiving

group_t*
new_group(const group_def_t *def, int flags)
  {
  char *endptr;
  char capture_mode;
  int i;
  struct addrinfo hints;
  struct addrinfo *res;


  group_t *grp;
  if(!(grp = calloc(1, sizeof(group_t))))
    {
    perror("malloc");
    return 0;
    }


  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

  // receiving
  if(flags & 0x01)
    {
    hints.ai_flags = AI_PASSIVE;
    capture_mode = 'w';
    }
  // sending
  else
    {
    }

  if((i = getaddrinfo(def->group, def->port, &hints, &res)))
    {
    perror(gai_strerror(i));
    free_group(grp);
    return 0;
    }

  if(res->ai_next)
    MCSAK_DEBUG(1, "multiple results from getaddrinfo, using first");

  // init group struct defaults
  strncpy(grp->group, def->group, sizeof(grp->group));
  if(def->name)
    strncpy(grp->name, def->name, sizeof(grp->name));
  else
    snprintf(grp->name, sizeof(grp->name), "%s/%s", def->group, def->port);

  if(def->mtu)
    {
    grp->mtu = strtol(def->mtu, &endptr, 10);

    if(def->mtu == endptr)
      {
      MCSAK_ERROR("invalid mtu '%s'", def->mtu);
      free_group(grp);
      return 0;
      }
    }
  else
    grp->mtu = mtu;

  if(!(grp->buf = malloc(grp->mtu)))
    {
    perror("malloc buf");
    free_group(grp);
    return 0;
    }

  if(def->capture_file && !(grp->capture = parse_capture(def->capture_format)))
    {
    MCSAK_ERROR("invalid capture format");
    free_group(grp);
    return 0;
    }

  if(def->decoder && !(grp->decode = parse_decoder(def->decoder)))
    {
    MCSAK_ERROR("invalid decoder format");
    free_group(grp);
    return 0;
    }

  if((grp->fd = socket(res->ai_family, res->ai_socktype, 0)) == -1)
    {
    perror("socket");
    free_group(grp);
    freeaddrinfo(res);
    return NULL;
    }

  if(flags & 0x01)
    {
    i = 1;
    // bind on socket
    if(setsockopt(grp->fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1)
      {
      perror("failed reuse addr setsockopt");
      free_group(grp);
      freeaddrinfo(res);
      return NULL;
      }

    if(bind(grp->fd, (struct sockaddr*)res->ai_addr, res->ai_addrlen) == -1)
      {
      perror("bind");
      free_group(grp);
      freeaddrinfo(res);
      return NULL;
      }

    // capture file
    if(def->capture_file)
      {
      if(!(grp->capture_file = fopen(def->capture_file, &capture_mode)))
        {
        perror("failed to open capture file");
        MCSAK_DIE_USAGE(0);
        free_group(grp);
        return 0;
        }

// TODO - make capture struct with init, capture, close
      if(grp->capture == capture_pcap)
        pcap_capture_init(grp);
      }
    }

  switch(res->ai_family)
    {
  // IPv4
  case AF_INET:
    {
    struct ip_mreq ipm;

    if(def->interface)
      {
      struct ifreq ifr;


      MCSAK_DEBUG(1, "using interface %s\n", def->interface);

      strncpy(ifr.ifr_name, def->interface, sizeof(ifr.ifr_name));
      if(ioctl(grp->fd, SIOCGIFADDR, &ifr) == -1)
        {
        perror("failed to find interface");
        return 0;
        }

      MCSAK_DEBUG(1, "got ifip %s\n", inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

      memcpy(&ipm.imr_interface, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr,
       sizeof(struct in_addr));
      }
    else
      ipm.imr_interface.s_addr = htonl(INADDR_ANY);

    ipm.imr_multiaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

    MCSAK_DEBUG(2, "group %s", grp->group);
    MCSAK_DEBUG(2, "add membership %x %x", ipm.imr_interface.s_addr, ipm.imr_multiaddr.s_addr);

    if(setsockopt(grp->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ipm, sizeof(ipm)) == -1)
      {
      perror("failed to add membership");
      return 0;
      }
    }
    break;

  // IPv6
  case AF_INET6:
    {
    struct ipv6_mreq ipm;

    ipm.ipv6mr_interface = 0;

    memcpy(&ipm.ipv6mr_multiaddr, &((struct sockaddr_in6*)
     res->ai_addr)->sin6_addr,  sizeof(struct in6_addr));

    if(setsockopt(grp->fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &ipm, sizeof(ipm))
     == -1)
      {
      perror("failed to add membership");
      return 0;
      }
    }
    break;

  default:
    fprintf(stderr, "unknown address family %d\n", res->ai_family);
    return 0;
    }

  freeaddrinfo(res);
  return grp;
  }

//############################################################################//

int
looprecv(int ngrps, group_t **grpa)
  {
  char peer_host[NI_MAXHOST];
  char peer_serv[NI_MAXSERV];
  int cnt = 0;
  int i = 0;
  struct sockaddr_storage peer;
  struct pollfd *fds;
  socklen_t peer_len;
  group_t *grp;


  if(!(fds = calloc(sizeof(struct pollfd), ngrps)))
    {
    perror("alloc");
    return EXIT_FAILURE;
    }

  for(i=0; i<ngrps; ++i)
    {
    fds[i].fd = grpa[i]->fd;
    fds[i].events = POLLIN;
    }

  while(poll(fds, ngrps, -1) != -1)
    for(i=0; i<ngrps; i++)
      if(fds[i].revents & POLLIN)
        {
        grp = grpa[i];

        peer_len = sizeof(struct sockaddr_storage);

        if((grp->sz = recvfrom(grp->fd, grp->buf, grp->mtu, 0, (struct sockaddr *)&peer, &peer_len)) == -1)
          {
          perror("recvfrom");
          free(fds);
          return EXIT_FAILURE;
          }

        // always call get name info since it does ntop
        if(!opt_quiet)
          {
          if(getnameinfo((struct sockaddr *)&peer, peer_len, peer_host,
           sizeof(peer_host), peer_serv, sizeof(peer_serv), opt_namelookup))
            perror("failed to get peer name info");

// TODO - save timestamp for passing to decode/capture
            MCSAK_PRINT("%s %s/%s > %s length %u\n", fmt_timestamp(), peer_host, peer_serv, grp->name, grp->sz);
          }

        if(grp->decode)
          grp->decode(grp);

        if(grp->capture_file)
          grp->capture(grp);

        if(opt_count && ++cnt >= opt_count)
          {
          free(fds);
          return EXIT_SUCCESS;
          }
        }

  perror("poll");
  free(fds);
  return EXIT_FAILURE;
  }

//############################################################################//

void
daemonize()
  {
  if(daemon(0, 0))
    perror("daemonize");
  }

//############################################################################//

int
get_syslog_fac(const char *facstr)
  {
  char *endptr;
  int fac = strtol(facstr, &endptr, 10);


  if(facstr != endptr)
    {
    switch(fac)
      {
    case 0:
      MCSAK_RET_SYSLOG_FAC(LOG_LOCAL0)
    case 1:
      MCSAK_RET_SYSLOG_FAC(LOG_LOCAL1)
    case 2:
      MCSAK_RET_SYSLOG_FAC(LOG_LOCAL2)
    case 3:
      MCSAK_RET_SYSLOG_FAC(LOG_LOCAL3)
    case 4:
      MCSAK_RET_SYSLOG_FAC(LOG_LOCAL4)
    case 5:
      MCSAK_RET_SYSLOG_FAC(LOG_LOCAL5)
    case 6:
      MCSAK_RET_SYSLOG_FAC(LOG_LOCAL6)
    case 7:
      MCSAK_RET_SYSLOG_FAC(LOG_LOCAL7)
    default:
      return -1;
      }
    }

  if(!strcmp(facstr, "auth"))
    MCSAK_RET_SYSLOG_FAC(LOG_AUTH)
  else if(!strcmp(facstr, "authpriv"))
    MCSAK_RET_SYSLOG_FAC(LOG_AUTHPRIV)
  else if(!strcmp(facstr, "cron"))
    MCSAK_RET_SYSLOG_FAC(LOG_CRON)
  else if(!strcmp(facstr, "daemon"))
    MCSAK_RET_SYSLOG_FAC(LOG_DAEMON)
  else if(!strcmp(facstr, "ftp"))
    MCSAK_RET_SYSLOG_FAC(LOG_FTP)
  else if(!strcmp(facstr, "kern"))
    MCSAK_RET_SYSLOG_FAC(LOG_KERN)
  else if(!strcmp(facstr, "lpr"))
    MCSAK_RET_SYSLOG_FAC(LOG_LPR)
  else if(!strcmp(facstr, "mail"))
    MCSAK_RET_SYSLOG_FAC(LOG_MAIL)
  else if(!strcmp(facstr, "news"))
    MCSAK_RET_SYSLOG_FAC(LOG_NEWS)
  else if(!strcmp(facstr, "syslog"))
    MCSAK_RET_SYSLOG_FAC(LOG_SYSLOG)
  else if(!strcmp(facstr, "user"))
    MCSAK_RET_SYSLOG_FAC(LOG_USER)
  else if(!strcmp(facstr, "uucp"))
    MCSAK_RET_SYSLOG_FAC(LOG_UUCP)

  return -1;
  }

//############################################################################//
//! inih config callback

int
conf_cb(void *user, const char *section, const char *name, const char *val)
  {
  static char cursect[MCSAK_MAXNAME] = "";
  static group_def_t *def;


  // new section
  if(strncmp(cursect, section, MCSAK_MAXNAME))
    {
    strncpy(cursect, section, MCSAK_MAXNAME);
    if(strcmp(section, "mcsak"))
      {
      if(!(def = malloc(sizeof(group_def_t))))
        {
        MCSAK_ERROR("failed to malloc for group def: %s", strerror(errno));
        exit(EXIT_FAILURE);
        }

      memset(def, 0, sizeof(group_def_t));
      def->name = strdup(section);
      grpdef[ngrpdefs++] = def;
      }

    }

  // global config
  if(!strcmp(section, "mcsak"))
    {
    if(!strcmp(name, "daemonize"))
      opt_daemon = to_bool(val);
    else if(!strcmp(name, "nolookup"))
      opt_namelookup = NI_NUMERICHOST|NI_NUMERICSERV;
    else if(!strcmp(name, "quiet"))
      opt_quiet = to_bool(val);
    else if(!strcmp(name, "syslog"))
      opt_syslog_fac = get_syslog_fac(val);
    else
      {
      MCSAK_ERROR("unknown config option '%s'", name);
      exit(EXIT_FAILURE);
      }

    return 1;
    }

  // group config
  if(!strcmp(name, "decode_format"))
    def->decoder = strdup(val);
  else if(!strcmp(name, "address"))
    {
    def->group = strdup(val);
    def->port = port_from_addr(def->group);
    }
  else if(!strcmp(name, "interface"))
    def->interface = strdup(val);
  else if(!strcmp(name, "capture_file"))
    def->capture_file = strdup(val);
  else if(!strcmp(name, "capture_format"))
    def->capture_format = strdup(val);
  else if(!strcmp(name, "max"))
    def->mtu = strdup(val);
  else
    {
    MCSAK_ERROR("unknown config option '%s'", name);
    exit(EXIT_FAILURE);
    }

  return 1;
  }

//############################################################################//

int
main(int argc, char **argv)
  {
  int i;
  int opt;
  int rv;
  char *endptr;
  char *config_file = 0;
  group_def_t def;
  group_t **grp;
  extern int optind, opterr, optopt;
  extern char *optarg;

  // defaults
  opt_logfile = stderr;
  opt_syslog_fac = LOG_USER;
  opt_fmt_timestamp = "%H:%M:%S";
  mtu = 1500;

  memset(&def, 0, sizeof(def));

  while((opt = getopt(argc, argv, "C:c:de:F:f:hi:lm:N:nqS::T:Vv")) != -1)
    {
    switch(opt)
      {
      // max count
      case 'C':
        if(!optarg || !(opt_count = atoi(optarg)))
          MCSAK_DIE_USAGE("invalid count");
        break;

      // config file
      case 'c':
        config_file = strdup(optarg);
        break;

      // daemonize
      case 'd':
        opt_daemon = 1;
        break;

      // capture file encoding
      case 'e':
        if(!optarg)
          MCSAK_DIE_USAGE("missing capture file");
        def.capture_format = strdup(optarg);
        break;

      // capture file
      case 'F':
        if(!optarg)
          MCSAK_DIE_USAGE("missing capture file");
        def.capture_file = strdup(optarg);
        break;

      // decode format
      case 'f':
        if(def.decoder)
          MCSAK_DIE_USAGE("decoder already specified");
        def.decoder = strdup(optarg);
        break;

      case 'h':
        MCSAK_DIE_USAGE(0);
        break;

      // interface
      case 'i':
        if(!optarg)
          MCSAK_DIE_USAGE("invalid interface");
        def.interface = strdup(optarg);
        break;

      // log alerts to file
      case 'l':
        if(!optarg)
          MCSAK_DIE_USAGE("invalid logfile");
        if(!(opt_logfile = fopen(optarg, "a")))
          {
          perror("failed to open logfile");
          MCSAK_DIE_USAGE(0);
          }
        break;

      // max packet size / mtu
      case 'm':
        if(!optarg)
          MCSAK_DIE_USAGE("invalid max packet size");
        mtu = strtol(optarg, &endptr, 10);
        if(optarg != endptr)
          MCSAK_DIE_USAGE("invalid max packet size");
        break;

      // group name
      case 'N':
        if(!optarg)
          MCSAK_DIE_USAGE("invalid group name");
        if(def.name)
          MCSAK_DIE_USAGE("group name already specified");
        def.name = strdup(optarg);
        break;

      // name lookup
      case 'n':
        opt_namelookup = NI_NUMERICHOST|NI_NUMERICSERV;
        break;

      // quiet
      case 'q':
        opt_quiet = 1;
        break;

      // syslog
      case 'S':
        if(optarg)
          opt_syslog_fac = get_syslog_fac(optarg);
        else
          opt_syslog_fac = LOG_USER;

        if(opt_syslog_fac == -1)
          MCSAK_DIE_USAGE("invalid syslog target '%s'", optarg);

        openlog("mcsak", 0, opt_syslog_fac);
        opt_syslog = 1;
        break;

      // strftime fmt
      case 'T':
        opt_fmt_timestamp = strdup(optarg);
        break;

      // version
      case 'V':
        fprintf(stderr, "Version %s\n", MCSAK_VERSION);
        MCSAK_DIE_USAGE(0);
        break;

      // verbosity / debug
      case 'v':
        ++opt_debuglvl;
        break;

      default:
        MCSAK_DIE_USAGE(0);
        }
      }

  if(config_file)
    {
    if(argc != optind)
      MCSAK_DIE_USAGE("config cannot be specified on the command line with config file option");
    ini_parse(config_file, conf_cb, NULL);
    free(config_file);
    }
  else
    {
    if(argc - optind != 1)
      MCSAK_DIE_USAGE(0);

    def.group = strdup(argv[optind]);
    def.port = port_from_addr(def.group);

    ngrpdefs = 1;
    grpdef[0] = &def;
    }

  if(!(grp = malloc(sizeof(group_t) * ngrpdefs)))
    {
    perror("malloc");
    return EXIT_FAILURE;
    }

  for(i=0; i<ngrpdefs; ++i)
    if(!(grp[i] = new_group(grpdef[i], 1)))
      return EXIT_FAILURE;

  // get time for elapsed runtime
  if(time_get(&start, 0))
    return EXIT_FAILURE;

  if(opt_daemon)
    daemonize();

  rv = looprecv(ngrpdefs, grp);
  free(grp);
  return rv;
  }

//############################################################################//

