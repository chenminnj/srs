// add by chenmin 4 quic

#include <algorithm>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
#include "lsquic.h"
#include "lsquic_logger.h"
}
#include "srs_app_config.hpp"
#include "srs_app_hourglass.hpp"
#include "srs_app_quic_conn.hpp"
#include "srs_app_quic_listener.hpp"
#include "srs_app_utility.hpp"
#include "srs_core_autofree.hpp"
#include "srs_kernel_log.hpp"
#include "srs_kernel_utility.hpp"
#include "srs_rtmp_stack.hpp"

SrsQuicListener::SrsQuicListener(SrsServer *svr, SrsListenerType t) : SrsListener(svr, t) {
    m_State = new SrsQuicState();
    m_State->ssl_ctx = NULL;

    m_pTimer = new SrsHourGlass("sources", this, 1 * SRS_UTIME_SECONDS);
    m_State->m_pTimer = m_pTimer;

    m_trd = new SrsSTCoroutine("quic listener", this, _srs_context->get_id());
    // TODO
    m_cert_file = "/home/chenmin/ssl/dtls.pem";
    m_key_file = "/home/chenmin/ssl/privatekey.pem";

    m_pSrsQuicConn = NULL;
}

SrsQuicListener::~SrsQuicListener() {
    m_trd->stop();
    srs_freep(m_trd);

    SSL_CTX_free(m_State->ssl_ctx);
    m_State->ssl_ctx = NULL;

    if (m_State->engine) {
        lsquic_engine_destroy(m_State->engine);
    }

    srs_close_stfd(m_State->srsNetfd);

    srs_freep(m_State);
    srs_freep(m_pTimer);
}

srs_error_t SrsQuicListener::listen(std::string ip, int port) {
    srs_error_t err = srs_success;

    const char *alpn = "quic4rtmp";
    size_t alpn_len = 0, all_len = 0;
    alpn_len = strlen(alpn);
    m_alpn[all_len] = strlen(alpn);
    memcpy(&m_alpn[all_len + 1], alpn, strlen(alpn));
    m_alpn[all_len + 1 + alpn_len] = '\0';

    if (!m_cert_file.empty() && !m_key_file.empty()) {
        if ((err = init_ssl_ctx_map()) != srs_success) {
            return srs_error_wrap(err, "init_ssl_ctx_map faile");
        }

        if ((err = init_ssl_ctx()) != srs_success) {
            return srs_error_wrap(err, "init_ssl_ctx faile");
        }
    } else {
        return srs_error_new(ERROR_HTTPS_KEY_CRT, "Init server fail with missing cert or key file ");
    }

    m_State->m_pSrsQuicNetWorkBase = (void *)this;

    // m_State->buf_total_size = 4096;
    // m_State->buf  = new char[m_State->buf_total_size];
    // memset(m_State->buf, 0, m_State->buf_total_size);
    if ((err = create_sock(m_State, ip.c_str(), port, &m_State->local_sas, true)) != srs_success) {
        return srs_error_wrap(err, "create udp sock error");
    }

    if (srs_get_log_level(_srs_config->get_log_level()) > SrsLogLevelWarn) {
        lsquic_log_to_fstream(stderr, LLTS_HHMMSSUS);
        lsquic_set_log_level("debug");
    }

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER)) {
        return srs_error_new(ERROR_SOCKET_CREATE, "lsquic_global_init Fail");
    }

    /* At the time of this writing, using the loss bits extension causes
     * decryption failures in Wireshark.  For the purposes of the demo, we
     * override the default.
     */
    // m_State->engine_settings.es_ql_bits = 0;

    lsquic_engine_init_settings(&m_State->engine_settings, LSENG_SERVER);
    m_State->engine_settings.es_ecn = LSQUIC_DF_ECN;
    m_State->engine_settings.es_cfcw = 1 * 1024 * 1024;
    m_State->engine_settings.es_sfcw = 1 * 1024 * 1024;
    m_State->engine_settings.es_init_max_stream_data_uni = 1 * 1024 * 1024;

    char err_buf[100] = {0};
    if (0 != lsquic_engine_check_settings(&m_State->engine_settings, LSENG_SERVER, err_buf, sizeof(err_buf))) {
        return srs_error_new(ERROR_SOCKET_CREATE, "###### Error in settings: { %s }", err_buf);
    }

    memset(&m_stream_if, 0, sizeof(m_stream_if));
    m_stream_if.on_new_conn = SrsQuicListener::server_on_new_conn_cb;
    m_stream_if.on_conn_closed = SrsQuicListener::server_on_conn_closed_cb;
    m_stream_if.on_new_stream = SrsQuicListener::server_on_new_stream_cb;
    m_stream_if.on_read = SrsQuicListener::server_on_read_cb;
    // m_stream_if.on_write = SrsQuicListener::server_on_write_cb;
    m_stream_if.on_close = SrsQuicListener::server_on_stream_close_cb;

    memset(&m_engine_api, 0, sizeof(m_engine_api));
    m_engine_api.ea_settings = &m_State->engine_settings;
    m_engine_api.ea_packets_out = send_packets_out;
    m_engine_api.ea_packets_out_ctx = m_State;
    m_engine_api.ea_stream_if = &m_stream_if;
    m_engine_api.ea_stream_if_ctx = (void *)this;

    m_engine_api.ea_get_ssl_ctx = SrsQuicListener::get_ssl_ctx;
    m_engine_api.ea_lookup_cert = SrsQuicListener::lookup_cert;
    m_engine_api.ea_cert_lu_ctx = this;

    // m_engine_api.ea_lookup_cert     = SrsQuicListener::no_cert;
    m_engine_api.ea_alpn = alpn;

    m_State->engine = lsquic_engine_new(LSENG_SERVER, &m_engine_api);
    if (!m_State->engine) {
        return srs_error_new(ERROR_SOCKET_CREATE, "cannot create quic engine");
    }

    if ((err = m_trd->start()) != srs_success) {
        return srs_error_wrap(err, "quic listener coroutine");
    }

    return err;
}

srs_error_t SrsQuicListener::cycle() {
    srs_error_t err = srs_success;
    while (true) {
        if ((err = m_trd->pull()) != srs_success) {
            return srs_error_wrap(err, "quic listener thread");
        }
        srs_utime_t NO_TIMEOUT = -1;
        if ((err = udp_read_net_data(m_State, NO_TIMEOUT, this)) != srs_success) {
            return srs_error_wrap(err, "quic listener thread");
        }
    }
    return err;
}

srs_error_t SrsQuicListener::init_ssl_ctx() {
    srs_error_t err = srs_success;

    unsigned char ticket_keys[48] = {0};
    m_State->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!m_State->ssl_ctx) {
        return srs_error_new(ERROR_HTTPS_KEY_CRT, "Cannot allocate SSL context");
    }

    SSL_CTX_set_min_proto_version(m_State->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(m_State->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(m_State->ssl_ctx);

    if (1 != SSL_CTX_set_tlsext_ticket_keys(m_State->ssl_ctx, ticket_keys, sizeof(ticket_keys))) {
        return srs_error_new(ERROR_HTTPS_KEY_CRT, "SSL_CTX_set_tlsext_ticket_keys failed");
    }

    srs_trace("init_ssl_ctx SUCCESS");

    return err;
}

srs_error_t SrsQuicListener::init_ssl_ctx_map() {
    srs_error_t err = srs_success;

    struct ssl_ctx_st *ce_ssl_ctx;
    ce_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ce_ssl_ctx) {
        return srs_error_new(ERROR_HTTPS_KEY_CRT, "Cannot allocate SSL context");
    }

    string key(m_alpn);
    SSL_CTX_set_min_proto_version(ce_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ce_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(ce_ssl_ctx, SrsQuicListener::select_alpn, this);
    SSL_CTX_set_default_verify_paths(ce_ssl_ctx);

    {
        const char *const s = getenv("LSQUIC_ENABLE_EARLY_DATA");
        if (!s || atoi(s))
            SSL_CTX_set_early_data_enabled(ce_ssl_ctx, 1); /* XXX */
    }

    if (1 != SSL_CTX_use_certificate_chain_file(ce_ssl_ctx, m_cert_file.c_str())) {
        return srs_error_new(ERROR_HTTPS_KEY_CRT, "SSL_CTX_use_certificate_chain_file failed");
    }

    if (1 != SSL_CTX_use_PrivateKey_file(ce_ssl_ctx, m_key_file.c_str(), SSL_FILETYPE_PEM)) {
        return srs_error_new(ERROR_HTTPS_KEY_CRT, "SSL_CTX_use_PrivateKey_file failed");
    }

    SSL_CTX_set_session_cache_mode(ce_ssl_ctx, 1);
    m_certs_map.emplace(key, ce_ssl_ctx);

    srs_trace("init_ssl_ctx_map SUCCESS");

    return err;
}

srs_error_t SrsQuicListener::notify(int event, srs_utime_t interval, srs_utime_t tick) {
    // TODO: return process_conns' error
    process_conns(m_State);
    return srs_success;
}

SSL_CTX *SrsQuicListener::get_ssl_ctx(void *ctx, const sockaddr *) {
    SrsQuicListener *handle = (SrsQuicListener *)ctx;
    return handle->m_State->ssl_ctx;
}

struct ssl_ctx_st *SrsQuicListener::lookup_cert(void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni) {
    SrsQuicListener *handle = (SrsQuicListener *)cert_lu_ctx;
    ssl_ctx_st *ret = nullptr;

    if (sni) {
        string sni_str = sni;
        auto iter = handle->m_certs_map.find(sni_str);
        if (iter != handle->m_certs_map.end()) {
            ret = iter->second;
        } else {
            srs_error("1 Not found cert");
        }
    } else {
        if (handle->m_certs_map.size() > 0) {
            auto iter = handle->m_certs_map.begin();
            ret = iter->second;
        } else {
            srs_error("2 Not found cert");
        }
    }

    if (ret) {
        srs_trace("Get ssl_ctx { %p }", (void *)ret);
    }

    return ret;
}

int SrsQuicListener::select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
    int r = 0;
    SrsQuicListener *handle = (SrsQuicListener *)arg;

    srs_trace("in [{ %s }] inlen { %d } m_alpn [{ %s }] m_alpn_size { %d }", in, inlen, handle->m_alpn, strlen(handle->m_alpn));

    r = SSL_select_next_proto((unsigned char **)out, outlen, in, inlen,
                              (unsigned char *)handle->m_alpn, strlen(handle->m_alpn));
    if (r == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    else {
        srs_error("no supported protocol can be selected  { %s }", (char *)in);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

lsquic_conn_ctx_t *SrsQuicListener::server_on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn) {
    srs_trace("On new connection");
    lsquic_conn_ctx *connCtx = new lsquic_conn_ctx;
    memset(connCtx, 0, sizeof(lsquic_conn_ctx));

    connCtx->m_pSrsQuicNetWorkBase = ea_stream_if_ctx;
    connCtx->m_quicConn = conn;

    SrsQuicListener *handle = (SrsQuicListener *)ea_stream_if_ctx;
    handle->m_quicConns.push_back(connCtx); // 目前没用处 TODO 可做连接统计之类的监控数据上报？

    return connCtx;
}

void SrsQuicListener::server_on_conn_closed_cb(lsquic_conn_t *conn) {
    srs_trace("On connection close");
    lsquic_conn_ctx_t *connCtx = lsquic_conn_get_ctx(conn);

    SrsQuicListener *pSrsQuicListener = (SrsQuicListener *)connCtx->m_pSrsQuicNetWorkBase;
    pSrsQuicListener->m_pTimer->stop();

    char errbuf[2048] = {0};
    lsquic_conn_status(conn, errbuf, 2048);
    srs_trace("udp server_on_conn_closed_cb,errbuf { %s }", errbuf);

    lsquic_conn_set_ctx(conn, NULL);
    if (connCtx) {
        SrsQuicListener *handle = (SrsQuicListener *)connCtx->m_pSrsQuicNetWorkBase;
        vector<lsquic_conn_ctx_t *>::iterator iter = find(handle->m_quicConns.begin(), handle->m_quicConns.end(), connCtx);
        if (iter != handle->m_quicConns.end()) {
            handle->m_quicConns.erase(iter);
        }
        delete connCtx;
    }

    srs_trace("client connection closed -- stop reading from socket");
}

lsquic_stream_ctx_t *SrsQuicListener::server_on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream) {
    srs_trace("On new stream");

    lsquic_stream_ctx *streamCtx = new lsquic_stream_ctx;

    streamCtx->m_pSrsQuicNetWorkBase = ea_stream_if_ctx; // 目前没用处
    streamCtx->m_pQuicStream = stream;

    SrsQuicListener *p = (SrsQuicListener *)ea_stream_if_ctx;
    if (p->m_pSrsQuicConn) {
        delete p->m_pSrsQuicConn;
    }
    p->m_pSrsQuicConn = streamCtx->m_pSrsQuicConn = new SrsQuicConn(stream, p->m_State);

    // want to read request : host | app_name | stream_name
    lsquic_stream_wantread(stream, 1);
    return streamCtx;
}

void SrsQuicListener::server_on_stream_close_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *streamCtx) {
    srs_trace("On close stream");
    if (streamCtx->m_pSrsQuicConn) {
        streamCtx->m_pSrsQuicConn->interrupt();
        // delete streamCtx->m_pSrsQuicConn; 同一个协程 stop 自己, 会导致 st thread assert 异常,改成在 server_on_new_stream_cb 里释放
    }
    delete streamCtx;
}

void SrsQuicListener::server_on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *streamCtx) {
    char buf[256] = {0};

    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nr > 0) {
        // fwrite(buf, 1, nread, stdout);
        srs_error("Read { %d } from remote: { %s } ", nr, buf);

        if (buf[0] == '1') {
            // read quic client req: 1|host|live|livestream
            SrsRequest *req = new SrsRequest();
            SrsAutoFree(SrsRequest, req);

            std::string strBuf = string(buf);
            vector<string> strs = srs_string_split(strBuf, "|");

            if (strs.size() >= 4) {
                req->host = strs[1];
                req->app = strs[2];
                req->stream = strs[3];

                streamCtx->m_pSrsQuicConn->start(req);
            } else {
                srs_error("lsquic : read client request error,want host|live|livestream,but got %s", buf);
                lsquic_conn_abort(lsquic_stream_conn(stream));
            }
        }else if(buf[0] == '2'){
            srs_error("-------------server_on_read_cb %s,%d",buf,nr);
            if( nr == strlen("2|you need to close this stream") ){
                srs_trace(" client want to close the stream: close it ");
                lsquic_stream_close(stream);
            }
        }
        // fflush(stdout);
    } else if (nr == 0) {
        /* EOF */
        srs_trace(" read to end-of-stream: close it ");
        lsquic_stream_close(stream);
    } else {
        srs_error(" read to end-of-stream: close it ");
        lsquic_stream_close(stream);
        // lsquic_conn_abort(lsquic_stream_conn(stream));
    }
    // TODO receive all messages from client, then drop them
    lsquic_stream_wantread(stream, 1);
}

void SrsQuicListener::server_on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *streamCtx) {
    // useless
    lsquic_stream_wantwrite(stream, 0);
}

int send_packets_out(void *ctx, const lsquic_out_spec *specs, unsigned n_specs) {
    struct msghdr msg;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    SrsQuicState *pState = (SrsQuicState *)ctx;

    for (n = 0; n < n_specs; ++n) {
        msg.msg_name = (void *)specs[n].dest_sa;
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_iov = specs[n].iov;
        msg.msg_iovlen = specs[n].iovlen;
        if (sendmsg(pState->sockfd, &msg, 0) < 0) {
            perror("cannot send\n");
            break;
        }
    }
    return (int)n;
}

srs_error_t create_sock(SrsQuicState *state, const char *ip, unsigned int port, sockaddr_storage *local_sas, bool isServer) {
    state->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->sockfd == -1) {
        return srs_error_new(ERROR_SOCKET_CREATE, "create udp socket error");
    }

    /* 非阻塞模式 */
    int flags = fcntl(state->sockfd, F_GETFL);
    if (-1 == flags)
        return srs_error_new(ERROR_SOCKET_CREATE, "fcntl F_GETFL udp socket error");

    flags |= O_NONBLOCK;
    if (0 != fcntl(state->sockfd, F_SETFL, flags))
        return srs_error_new(ERROR_SOCKET_CREATE, "fcntl F_SETFL udp socket error");

    /* ToS is used to get ECN value */
    /* Set up the socket to return original destination address in ancillary data */
    struct sockaddr_in local_addr = new_addr(ip, port);
    int on = 1, s = 0, s1 = 0;
    if (AF_INET == local_addr.sin_family) {
        s = setsockopt(state->sockfd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
        if (isServer == true) {
            s1 = setsockopt(state->sockfd, IPPROTO_IP,
#if defined(IP_RECVORIGDSTADDR)
                            IP_RECVORIGDSTADDR,
#else
                            IP_PKTINFO,
#endif
                            &on, sizeof(on));
        }
    } else {
        s = setsockopt(state->sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
        s1 = setsockopt(state->sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
    }

    if (s != 0 || s1 != 0) {
        return srs_error_new(ERROR_SOCKET_CREATE, "setsockopt udp socket error");
    }

    if (isServer == true) {
        if (bind(state->sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
            return srs_error_new(ERROR_SOCKET_BIND, "server bind udp port error");
        }

        if (!memcpy(local_sas, &local_addr, sizeof(struct sockaddr_storage))) {
            return srs_error_new(ERROR_SOCKET_CREATE, "memcpy local_sas error\n");
        }
    } else {
        local_sas->ss_family = AF_INET; // TODO ipv6
        if (bind(state->sockfd, (struct sockaddr *)local_sas, sizeof(*local_sas)) != 0) {
            return srs_error_new(ERROR_SOCKET_BIND, "client bind udp port error");
        }
    }

    // set send buffer
    int default_sndbuf = 0;
    int expect_sndbuf = 1024 * 1024 * 10; // 10M
    int actual_sndbuf = expect_sndbuf;
    int r0_sndbuf = 0;
    if (true) {
        socklen_t opt_len = sizeof(default_sndbuf);
        // TODO: FIXME: check err
        getsockopt(state->sockfd, SOL_SOCKET, SO_SNDBUF, (void *)&default_sndbuf, &opt_len);

        if ((r0_sndbuf = setsockopt(state->sockfd, SOL_SOCKET, SO_SNDBUF, (void *)&actual_sndbuf, sizeof(actual_sndbuf))) < 0) {
            srs_warn("set SO_SNDBUF failed, expect=%d, r0=%d", expect_sndbuf, r0_sndbuf);
        }

        opt_len = sizeof(actual_sndbuf);
        getsockopt(state->sockfd, SOL_SOCKET, SO_SNDBUF, (void *)&actual_sndbuf, &opt_len);
    }

    int default_rcvbuf = 0;
    int expect_rcvbuf = 1024 * 1024 * 10; // 10M
    int actual_rcvbuf = expect_rcvbuf;
    int r0_rcvbuf = 0;
    if (true) {
        socklen_t opt_len = sizeof(default_rcvbuf);
        getsockopt(state->sockfd, SOL_SOCKET, SO_RCVBUF, (void *)&default_rcvbuf, &opt_len);

        if ((r0_rcvbuf = setsockopt(state->sockfd, SOL_SOCKET, SO_RCVBUF, (void *)&actual_rcvbuf, sizeof(actual_rcvbuf))) < 0) {
            srs_warn("set SO_RCVBUF failed, expect=%d, r0=%d", expect_rcvbuf, r0_rcvbuf);
        }

        opt_len = sizeof(actual_rcvbuf);
        getsockopt(state->sockfd, SOL_SOCKET, SO_RCVBUF, (void *)&actual_rcvbuf, &opt_len);
    }

    srs_trace("UDP #%d LISTEN at %s:%d, SO_SNDBUF(default=%d, expect=%d, actual=%d, r0=%d), SO_RCVBUF(default=%d, expect=%d, actual=%d, r0=%d)",
              state->sockfd, ip, port, default_sndbuf, expect_sndbuf, actual_sndbuf, r0_sndbuf, default_rcvbuf, expect_rcvbuf, actual_rcvbuf, r0_rcvbuf);

    if ((state->srsNetfd = srs_netfd_open_socket(state->sockfd)) == NULL) {
        return srs_error_new(ERROR_ST_OPEN_SOCKET, "st open");
    }

    return srs_success;
}

sockaddr_in new_addr(const char *ip, unsigned int port) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET; // TODO ipv6
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    return addr;
}

srs_error_t udp_read_net_data(SrsQuicState *state, srs_utime_t timeout, void *handle) {
    ssize_t nread;
    struct sockaddr_storage peer_sas, local_sas;
    unsigned char buf[8192];
    unsigned char ctl_buf[CTL_SZ];
    struct iovec vec[1] = {{buf, sizeof(buf)}};

    struct msghdr msg = {
        .msg_name = &peer_sas,
        .msg_namelen = sizeof(peer_sas),
        .msg_iov = vec,
        .msg_iovlen = 1,
        .msg_control = ctl_buf,
        .msg_controllen = sizeof(ctl_buf),
    };
    // nread = recvmsg(state->sockfd, &msg, 0);
    nread = srs_recvmsg(state->srsNetfd, &msg, 0, timeout);
    if (-1 == nread) {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno))
            return srs_error_new(ERROR_SOCKET_READ, "quic udp recvmsg: %s", strerror(errno));

        srs_trace("read nothing......");
        return srs_success;
    }

    local_sas = state->local_sas;
    // TODO handle ECN properly
    int ecn = 0;

    tut_proc_ancillary(&msg, &local_sas, &ecn);

    (void)lsquic_engine_packet_in(state->engine, buf, nread,
                                  (struct sockaddr *)&local_sas,
                                  (struct sockaddr *)&peer_sas,
                                  (void *)handle, ecn);

    process_conns(state);
    return srs_success;
}

void tut_proc_ancillary(struct msghdr *msg,
                        struct sockaddr_storage *storage, int *ecn) {
    const struct in6_pktinfo *in6_pkt;
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP &&
            cmsg->cmsg_type ==
#if defined(IP_RECVORIGDSTADDR)
                IP_ORIGDSTADDR
#else
                IP_PKTINFO
#endif
        ) {
#if defined(IP_RECVORIGDSTADDR)
            memcpy(storage, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
#else
            const struct in_pktinfo *in_pkt;
            in_pkt = (void *)CMSG_DATA(cmsg);
            ((struct sockaddr_in *)storage)->sin_addr = in_pkt->ipi_addr;
#endif
        } else if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                   cmsg->cmsg_type == IPV6_PKTINFO) {
            in6_pkt = (in6_pktinfo *)CMSG_DATA(cmsg);
            ((struct sockaddr_in6 *)storage)->sin6_addr =
                in6_pkt->ipi6_addr;
        } else if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) || (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS)) {
            memcpy(ecn, CMSG_DATA(cmsg), sizeof(*ecn));
            *ecn &= IPTOS_ECN_MASK;
        }
    }
}

void process_conns(SrsQuicState *state) {
    int diff;

    state->m_pTimer->stop();
    lsquic_engine_process_conns(state->engine);
    if (lsquic_engine_earliest_adv_tick(state->engine, &diff)) {
        if (diff <= LSQUIC_DF_CLOCK_GRANULARITY) {
            diff = LSQUIC_DF_CLOCK_GRANULARITY;
        }
        state->m_pTimer->tick(diff);
        state->m_pTimer->start();
    } else {
        srs_error("lsquic adv_tick  return abnormal");
    }
    return;
}
