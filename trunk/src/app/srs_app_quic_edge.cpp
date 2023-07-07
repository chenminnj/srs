// add by chenmin 4 quic

extern "C" {
#include "lsquic.h"
#include "lsquic_logger.h"
}
#include "srs_app_config.hpp"
#include "srs_app_pithy_print.hpp"
#include "srs_app_quic_edge.hpp"
#include "srs_app_quic_listener.hpp"
#include "srs_app_utility.hpp"
#include "srs_core_autofree.hpp"
#include "srs_kernel_balance.hpp"
#include "srs_kernel_buffer.hpp"
#include "srs_kernel_flv.hpp"
#include "srs_kernel_log.hpp"
#include "srs_kernel_utility.hpp"
#include "srs_protocol_amf0.hpp"
#include "srs_protocol_utility.hpp"
#include "srs_rtmp_stack.hpp"

SrsQuicEdgeIngester::SrsQuicEdgeIngester() {
}

SrsQuicEdgeIngester::~SrsQuicEdgeIngester() {
}

srs_error_t SrsQuicEdgeIngester::ingest(std::string &redirect) {
    srs_error_t err = srs_success;

    SrsPithyPrint *pprint = SrsPithyPrint::create_edge();
    SrsAutoFree(SrsPithyPrint, pprint);

    // we only use the redict once.
    // reset the redirect to empty, for maybe the origin changed.
    redirect = "";

    while (true) {
        if ((err = trd->pull()) != srs_success) {
            return srs_error_wrap(err, "thread quit");
        }

        pprint->elapse();

        // pithy print
        if (pprint->can_print()) {
            upstream->kbps_sample(SRS_CONSTS_LOG_EDGE_PLAY, pprint->age());
        }
        SrsEdgeQuicUpstream *pSrsEdgeQuicUpstream = dynamic_cast<SrsEdgeQuicUpstream *>(upstream);
        if ((err = udp_read_net_data(pSrsEdgeQuicUpstream->getSrsQuicState(), 5000 * SRS_UTIME_MILLISECONDS, this)) != srs_success) {
            return srs_error_wrap(err, "udp read data err");
        }
    }
    return err;
}

SrsEdgeQuicUpstream::SrsEdgeQuicUpstream(SrsEdgeIngester *pSrsEdgeIngester) {
    m_hasReadFlvHeader = false;

    m_State = new SrsQuicState();
    m_State->ssl_ctx = NULL;

    m_pTimer = new SrsHourGlass("sources", this, 1 * SRS_UTIME_SECONDS);
    m_State->m_pTimer = m_pTimer;

    m_pSrsEdgeIngester = pSrsEdgeIngester;
    m_pDecoder = new SrsQuicFlvDecoder();
}

SrsEdgeQuicUpstream::~SrsEdgeQuicUpstream() {
}

srs_error_t SrsEdgeQuicUpstream::connect(SrsRequest *r, SrsLbRoundRobin *lb) {
    srs_error_t err = srs_success;

    m_pReq = r;

    if (true) {
        SrsConfDirective *conf = _srs_config->get_vhost_edge_origin(m_pReq->vhost);

        if (!conf) {
            return srs_error_new(ERROR_EDGE_VHOST_REMOVED, "vhost %s removed", m_pReq->vhost.c_str());
        }

        // select the origin.
        std::string server = lb->select(conf->args);
        int port = SRS_CONSTS_RTMP_DEFAULT_PORT;
        srs_parse_hostport(server, server, port);

        // Remember the current selected server.
        selected_ip = server;
        selected_port = port;
    }

    if ((err = do_quic_connect()) != srs_success) {
        return srs_error_wrap(err, "do quic connect");
    };

    return err;
}

srs_error_t SrsEdgeQuicUpstream::recv_message(SrsCommonMessage **pmsg) {
    // do nothing
    return srs_success;
}

int SrsEdgeQuicUpstream::read_message(const int nr, SrsCommonMessage **pmsg) {
    srs_error_t err = srs_success;
    size_t iTempUsed = 0;

    int iHeaderSize = 9 + 4;
    if (m_hasReadFlvHeader == false) {
        if (nr >= 9) {
            char flvHeader[9];
            m_pDecoder->read_header(m_State->buf + m_State->buf_used, flvHeader);
        } else {
            return 0;
        }
        m_State->buf_used += 9;
        iTempUsed += 9;

        if (nr >= 9 + 4) {
            char pts[4];
            m_pDecoder->read_previous_tag_size(m_State->buf + m_State->buf_used, pts);
        } else {
            m_State->buf_used -= iTempUsed;
            return 0;
        }
        m_State->buf_used += 4;
        iTempUsed += 4;

        m_hasReadFlvHeader = true;
    } else {
        iHeaderSize = 0;
    }

    char type;
    int32_t size;
    uint32_t time;
    if (nr >= 11 + iHeaderSize) {
        m_pDecoder->read_tag_header(m_State->buf + m_State->buf_used, &type, &size, &time);
    } else {
        m_State->buf_used -= iTempUsed;
        return 0;
    }
    m_State->buf_used += 11;
    iTempUsed += 11;

    srs_error("read_message_: tag size  %d", size);

    char *data = NULL;
    if (nr >= 11 + size + iHeaderSize) {
        data = new char[size];
        m_pDecoder->read_tag_data(m_State->buf + m_State->buf_used, data, size);
    } else {
        m_State->buf_used -= iTempUsed;
        return 0;
    }
    m_State->buf_used += size;
    iTempUsed += size;

    if (nr >= 11 + size + 4 + iHeaderSize) {
        char pts[4];
        m_pDecoder->read_previous_tag_size(m_State->buf + m_State->buf_used, pts);
    } else {
        m_State->buf_used -= iTempUsed;
        return 0;
    }
    m_State->buf_used += 4;

    int stream_id = 1;
    SrsCommonMessage *msg = NULL;
    if ((err = srs_rtmp_create_msg(type, time, data, size, stream_id, &msg)) != srs_success) {
        srs_warn("create message %s", SrsCplxError::description(err).c_str());
        return 0;
    }

    *pmsg = msg;

    return 1;
}

srs_error_t SrsEdgeQuicUpstream::notify(int event, srs_utime_t interval, srs_utime_t tick) {
    // TODO: return process_conns' error
    process_conns(m_State);
    return srs_success;
}

srs_error_t SrsEdgeQuicUpstream::decode_message(SrsCommonMessage *msg, SrsPacket **ppacket) {
    srs_error_t err = srs_success;

    SrsPacket *packet = NULL;
    SrsBuffer stream(msg->payload, msg->size);
    SrsMessageHeader &header = msg->header;

    if (header.is_amf0_data() || header.is_amf3_data()) {
        std::string command;
        if ((err = srs_amf0_read_string(&stream, command)) != srs_success) {
            return srs_error_wrap(err, "decode command name");
        }

        stream.skip(-1 * stream.pos());

        if (command == SRS_CONSTS_RTMP_SET_DATAFRAME) {
            *ppacket = packet = new SrsOnMetaDataPacket();
            return packet->decode(&stream);
        } else if (command == SRS_CONSTS_RTMP_ON_METADATA) {
            *ppacket = packet = new SrsOnMetaDataPacket();
            return packet->decode(&stream);
        }
    }

    return err;
}

void SrsEdgeQuicUpstream::close() {
    m_hasReadFlvHeader = false;

    SSL_CTX_free(m_State->ssl_ctx);
    m_State->ssl_ctx = NULL;

    srs_close_stfd(m_State->srsNetfd);
    m_pTimer->stop();

    srs_freep(m_State);
    srs_freep(m_pTimer);
    srs_freep(m_pReq);
    srs_freep(m_pDecoder);
}

srs_error_t SrsEdgeQuicUpstream::do_quic_connect() {
    srs_error_t err = srs_success;

    m_State->m_pSrsQuicNetWorkBase = (void *)this;

    // TODO
    if ((err = create_sock(m_State, "127.0.0.1", 12345, &m_State->local_sas, false)) != srs_success) {
        return srs_error_wrap(err, "create udp sock error");
    }

    if (srs_get_log_level(_srs_config->get_log_level()) < SrsLogLevelWarn) {
        lsquic_log_to_fstream(stderr, LLTS_HHMMSSUS);
        lsquic_set_log_level("info");
    }

    lsquic_engine_init_settings(&m_State->engine_settings, 0);
    m_State->engine_settings.es_ecn = LSQUIC_DF_ECN;

    init_ssl_ctx();

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT)) {
        return srs_error_new(ERROR_SOCKET_CREATE, "lsquic_global_init Fail");
    }

    memset(&m_stream_if, 0, sizeof(m_stream_if));
    m_stream_if.on_new_conn = SrsEdgeQuicUpstream::client_on_new_conn_cb;
    m_stream_if.on_conn_closed = SrsEdgeQuicUpstream::client_on_conn_closed_cb;
    m_stream_if.on_new_stream = SrsEdgeQuicUpstream::client_on_new_stream_cb;
    m_stream_if.on_read = SrsEdgeQuicUpstream::client_on_read_cb;
    m_stream_if.on_write = SrsEdgeQuicUpstream::client_on_write_cb;
    m_stream_if.on_hsk_done = SrsEdgeQuicUpstream::client_on_hsk_done;
    m_stream_if.on_close = SrsEdgeQuicUpstream::client_on_stream_close_cb;

    memset(&m_engine_api, 0, sizeof(m_engine_api));
    m_engine_api.ea_pmi = NULL;
    m_engine_api.ea_pmi_ctx = NULL;

    m_engine_api.ea_settings = &m_State->engine_settings;

    m_engine_api.ea_packets_out = send_packets_out;
    m_engine_api.ea_packets_out_ctx = m_State;
    m_engine_api.ea_stream_if = &m_stream_if;
    m_engine_api.ea_stream_if_ctx = this;

    m_engine_api.ea_alpn = "quic4rtmp";

    char err_buf[100] = {0};
    if (0 != lsquic_engine_check_settings(&m_State->engine_settings, 0, err_buf, sizeof(err_buf))) {
        return srs_error_new(ERROR_SOCKET_CREATE, "Error in settings: { %s }", err_buf);
    }

    m_State->engine = lsquic_engine_new(0, &m_engine_api);

    struct sockaddr_in peer_addr = new_addr(selected_ip.c_str(), selected_port);
    if (NULL == lsquic_engine_connect(m_State->engine, N_LSQVER,
                                      (struct sockaddr *)&m_State->local_sas,
                                      (struct sockaddr *)&peer_addr, (void *)&m_State->sockfd, NULL,
                                      NULL, 0, NULL, 0, NULL, 0)) {
        return srs_error_new(ERROR_SOCKET_CREATE, "Cannot create connection: { %s }", err_buf);
    }

    process_conns(m_State);

    return err;
}

void SrsEdgeQuicUpstream::selected(std::string &server, int &port) {
    server = selected_ip;
    port = selected_port;
    return;
}

void SrsEdgeQuicUpstream::set_recv_timeout(srs_utime_t tm) {
    return;
}

void SrsEdgeQuicUpstream::kbps_sample(const char *label, int64_t age) {
    return;
}

int SrsEdgeQuicUpstream::init_ssl_ctx() {
    unsigned char ticket_keys[48];

    m_State->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!m_State->ssl_ctx) {
        printf("cannot allocate SSL context\n");
        return -1;
    }

    SSL_CTX_set_min_proto_version(m_State->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(m_State->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(m_State->ssl_ctx);

    /* This is obviously test code: the key is just an array of NUL bytes */
    memset(ticket_keys, 0, sizeof(ticket_keys));
    if (1 != SSL_CTX_set_tlsext_ticket_keys(m_State->ssl_ctx,
                                            ticket_keys, sizeof(ticket_keys))) {
        printf("SSL_CTX_set_tlsext_ticket_keys failed \n");
        return -1;
    }

    return 0;
}

lsquic_conn_ctx_t *SrsEdgeQuicUpstream::client_on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn) {
    srs_error("On new connection");

    lsquic_conn_make_stream(conn);
    SrsEdgeQuicUpstream *pSrsEdgeQuicUpstream = (SrsEdgeQuicUpstream *)ea_stream_if_ctx;
    pSrsEdgeQuicUpstream->m_State->m_quicConn = conn;

    return (lsquic_conn_ctx_t *)ea_stream_if_ctx;
}

void SrsEdgeQuicUpstream::client_on_conn_closed_cb(lsquic_conn_t *conn) {
    srs_error("On connection close");
    SrsEdgeQuicUpstream *pSrsEdgeQuicUpstream = (SrsEdgeQuicUpstream *)lsquic_conn_get_ctx(conn);
    pSrsEdgeQuicUpstream->m_pTimer->stop();

    char errbuf[2048] = {0};
    lsquic_conn_status(conn, errbuf, 2048);
    srs_info("client connection closed : errbuf { %s } , -- stop reading from socket", errbuf);

    return;
}

lsquic_stream_ctx_t *SrsEdgeQuicUpstream::client_on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream) {
    srs_error("On new stream");
    SrsEdgeQuicUpstream *pSrsEdgeQuicUpstream = (SrsEdgeQuicUpstream *)ea_stream_if_ctx;
    // pSrsEdgeQuicUpstream->m_State->stream = stream;

    // write req to remote srs origin
    string sendStr = "1|";
    sendStr += pSrsEdgeQuicUpstream->m_pReq->host + "|" + pSrsEdgeQuicUpstream->m_pReq->app + "|" + pSrsEdgeQuicUpstream->m_pReq->stream;

    lsquic_stream_write(stream, sendStr.c_str(), sendStr.length());
    lsquic_stream_flush(stream);

    lsquic_stream_wantread(stream, 1);

    return (lsquic_stream_ctx_t *)ea_stream_if_ctx;
}

void SrsEdgeQuicUpstream::client_on_stream_close_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h) {
    srs_info("on client_on_stream_close_cb");
}

void SrsEdgeQuicUpstream::client_on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    SrsEdgeQuicUpstream *pSrsEdgeQuicUpstream = (SrsEdgeQuicUpstream *)h;

    char *pBuf = pSrsEdgeQuicUpstream->m_State->buf;
    size_t *pOffset = &(pSrsEdgeQuicUpstream->m_State->buf_offset);
    size_t *pBufUsed = &(pSrsEdgeQuicUpstream->m_State->buf_used);
    size_t remainderSize = sizeof(pSrsEdgeQuicUpstream->m_State->buf) - *pOffset;

    ssize_t nr = lsquic_stream_read(stream, pBuf + *pOffset, remainderSize);
    srs_error("client_on_read_cb: offset %d, remainderSize %d, nr %d, used: %d ", *pOffset, remainderSize, nr, *pBufUsed);
    if (nr > 0) {
        srs_info("Read { %d } frome server: { %s } ", nr, pBuf + *pOffset);

        *pOffset += nr;
        srs_assert( (*pOffset) <= sizeof(pSrsEdgeQuicUpstream->m_State->buf));

        SrsCommonMessage *msg = NULL;
        SrsAutoFree(SrsCommonMessage, msg);

        ssize_t leftBytes = *pOffset - *pBufUsed;
        while (leftBytes > 0) {
            if (pSrsEdgeQuicUpstream->read_message(leftBytes, &msg) == 1) {
                string redirect = "";
                if (msg != NULL) {
                    pSrsEdgeQuicUpstream->m_pSrsEdgeIngester->process_publish_message(msg, redirect);
                    srs_error("client_on_read_cb: right right right right ,---------------- leftBytes %d", leftBytes);
                }
                leftBytes = *pOffset - *pBufUsed;
            } else {
                break;
            }
        }

        // TODO 如果buf结尾，并不是一个完整的tag，需要把buf realloc 下,否则就读不到新数据包了
        if (leftBytes > 0) {
            memcpy(pBuf, pBuf + *pBufUsed, leftBytes);
            *pOffset = leftBytes;
            *pBufUsed = 0;
            srs_error("client_on_read_cb: buffer reset");
        }

        lsquic_stream_wantread(stream, 1);
    } else {
        /* EOF */
        srs_info(" read to end-of-stream: close and read from remote server again ");
        lsquic_stream_close(stream);

        /* 重新开始一个stream */
        lsquic_conn_make_stream(pSrsEdgeQuicUpstream->m_State->m_quicConn);
    }
}

void SrsEdgeQuicUpstream::client_on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    // do nothing;
    return;
}

void SrsEdgeQuicUpstream::client_on_hsk_done(lsquic_conn_t *conn, lsquic_hsk_status status) {
    // ClientState *tmpClientState = (ClientState *) lsquic_conn_get_ctx(conn);

    switch (status) {
    case LSQ_HSK_OK:
    case LSQ_HSK_RESUMED_OK:
        srs_info("handshake successful, start stdin watcher");
        break;
    default:
        srs_info("handshake failed");
        break;
    }
}

SrsQuicFlvDecoder::SrsQuicFlvDecoder() {
}

SrsQuicFlvDecoder::~SrsQuicFlvDecoder() {
}

srs_error_t SrsQuicFlvDecoder::initialize(ISrsReader *fr) {
    srs_assert(fr);
    reader = fr;
    return srs_success;
}

srs_error_t SrsQuicFlvDecoder::read_header(const char *th, char header[9]) {
    srs_error_t err = srs_success;

    srs_assert(header);

    // TODO: FIXME: Should use readfully.
    memcpy(header, th, 9);

    char *h = header;
    if (h[0] != 'F' || h[1] != 'L' || h[2] != 'V') {
        return srs_error_new(ERROR_KERNEL_FLV_HEADER, "flv header must start with FLV");
    }

    return err;
}

void SrsQuicFlvDecoder::read_tag_header(const char *th, char *ptype, int32_t *pdata_size, uint32_t *ptime) {
    // Reserved UB [2]
    // Filter UB [1]
    // TagType UB [5]
    *ptype = (th[0] & 0x1F);

    // DataSize UI24
    char *pp = (char *)pdata_size;
    pp[3] = 0;
    pp[2] = th[1];
    pp[1] = th[2];
    pp[0] = th[3];

    // Timestamp UI24
    pp = (char *)ptime;
    pp[2] = th[4];
    pp[1] = th[5];
    pp[0] = th[6];

    // TimestampExtended UI8
    pp[3] = th[7];

    return;
}

void SrsQuicFlvDecoder::read_tag_data(const char *th, char *data, int32_t size) {
    memcpy(data, th, size);
    return;
}

void SrsQuicFlvDecoder::read_previous_tag_size(const char *th, char previous_tag_size[4]) {
    // ignore 4bytes tag size.
    // TODO: FIXME: Should use readfully.
    memcpy(previous_tag_size, th, 4);
    return;
}
