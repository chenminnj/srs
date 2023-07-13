// add by chenmin 4 quic
#ifndef SRS_APP_QUIC_LISTENER
#define SRS_APP_QUIC_LISTENER

#include <stdlib.h>
#include <sys/socket.h>
#include <vector>

using namespace std;

extern "C" {
#include "lsquic.h"
}

#include "openssl/crypto.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "srs_app_hourglass.hpp"
#include "srs_app_server.hpp"

class SrsQuicConn;

#if defined(IP_RECVORIGDSTADDR)
#define DST_MSG_SZ sizeof(struct sockaddr_in)
#else
#define DST_MSG_SZ sizeof(struct in_pktinfo)
#endif

#define ECN_SZ CMSG_SPACE(sizeof(int))

#define MAX(a, b) ((a) > (b) ? (a) : (b))
/* Amount of space required for incoming ancillary data */
#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ,                    \
                               sizeof(struct in6_pktinfo))) + \
                ECN_SZ)

struct lsquic_conn_ctx {
    lsquic_conn_t *m_quicConn;
    void *m_pSrsQuicNetWorkBase;
};

struct lsquic_stream_ctx {
    lsquic_stream_t *m_pQuicStream = NULL;
    SrsQuicConn *m_pSrsQuicConn = NULL;
    // msg to send or read
    char buf[4096];
    size_t buf_used = 0; /* 已消费过的buffer大小 */
    void *m_pSrsQuicNetWorkBase;
};

typedef struct SrsQuicState {
    // lsquic
    int sockfd;
    srs_netfd_t srsNetfd;
    struct sockaddr_storage local_sas;
    lsquic_engine_t *engine = NULL;
    lsquic_stream_t *stream = NULL;
    struct lsquic_engine_settings engine_settings;

    // msg to send or read
    char buf[1*1024*1024];
    size_t buf_used = 0;   /* 已消费过的buffer大小 */
    size_t buf_offset = 0; /* 已写入的buffer大小 */

    void *m_pSrsQuicNetWorkBase = NULL;

    SSL_CTX *ssl_ctx = NULL;
    lsquic_conn_t *m_quicConn;
    SrsHourGlass *m_pTimer;
} SrsQuicState;

extern srs_error_t udp_read_net_data(SrsQuicState *state, srs_utime_t timeout, void *handle);
extern int send_packets_out(void *ctx, const struct lsquic_out_spec *specs, unsigned n_specs);
extern srs_error_t create_sock(SrsQuicState *state, const char *ip, unsigned int port, struct sockaddr_storage *local_sas, bool isServer);
extern struct sockaddr_in new_addr(const char *ip, unsigned int port);
extern void process_conns(SrsQuicState *state);
extern void tut_proc_ancillary(struct msghdr *msg,
                               struct sockaddr_storage *storage, int *ecn);

class SrsQuicListener : public SrsListener, public ISrsCoroutineHandler, public ISrsHourGlass {
  private:
    SrsHourGlass *m_pTimer;
    SrsQuicState *m_State;
    SrsQuicConn *m_pSrsQuicConn;    

    struct lsquic_engine_api m_engine_api;
    struct lsquic_stream_if m_stream_if;

  private:
    char m_alpn[256] = {0}; /* lsquic设置alpn的字符串 */

    vector<lsquic_conn_ctx_t *> m_quicConns; /* server端使用，维护的客户端链接 */
    SrsCoroutine *m_trd;

    std::string m_cert_file;
    std::string m_key_file;

    map<string, SSL_CTX *> m_certs_map; /* server端使用, first--唯一标志 */
  public:
    SrsQuicListener(SrsServer *svr, SrsListenerType t);
    virtual ~SrsQuicListener();

  public:
    virtual srs_error_t listen(std::string ip, int port);
    virtual srs_error_t cycle();

  private:
    /* lsquic的回调函数 */
    static lsquic_conn_ctx_t *server_on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn);
    static void server_on_conn_closed_cb(lsquic_conn_t *conn);

    static lsquic_stream_ctx_t *server_on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream);
    static void server_on_stream_close_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *streamCtx); /* stream close 是调用的回调函数 */
    static void server_on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
    static void server_on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
    /* lsquic的回调函数结束 */

    srs_error_t init_ssl_ctx();
    srs_error_t init_ssl_ctx_map();
    virtual srs_error_t notify(int event, srs_utime_t interval, srs_utime_t tick);

    /* lsquic引擎内部调用函数 */
    static SSL_CTX *get_ssl_ctx(void *ctx, const struct sockaddr *);
    static struct ssl_ctx_st *lookup_cert(void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni);
    static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                           const unsigned char *in, unsigned int inlen, void *arg);
};

#endif
