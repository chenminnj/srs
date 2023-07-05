// add by chenmin 4 quic
#ifndef SRS_APP_QUIC_EDGE
#define SRS_APP_QUIC_EDGE

#include <sys/socket.h>

extern "C" {
#include "lsquic.h"
}

#include "srs_app_edge.hpp"
#include "srs_app_quic_listener.hpp"

class SrsQuicEdgeIngester : public SrsEdgeIngester {
  public:
    SrsQuicEdgeIngester();
    virtual ~SrsQuicEdgeIngester();

  private:
    virtual srs_error_t ingest(std::string &redirect);
};

class SrsQuicFlvDecoder {
  private:
    ISrsReader *reader;

  public:
    SrsQuicFlvDecoder();
    virtual ~SrsQuicFlvDecoder();

  public:
    // Initialize the underlayer file stream
    // @remark user can initialize multiple times to decode multiple flv files.
    // @remark user must free the @param fr, flv decoder never close/free it
    virtual srs_error_t initialize(ISrsReader *fr);

  public:
    // Read the flv header, donot including the 4bytes previous tag size.
    // @remark assert header not NULL.
    virtual srs_error_t read_header(char header[9]);
    // Read the tag header infos.
    // @remark assert ptype/pdata_size/ptime not NULL.
    virtual void read_tag_header(const char *th, char *ptype, int32_t *pdata_size, uint32_t *ptime);
    // Read the tag data.
    // @remark assert data not NULL.
    virtual void read_tag_data(const char *th, char *data, int32_t size);
    // Read the 4bytes previous tag size.
    // @remark assert previous_tag_size not NULL.
    virtual void read_previous_tag_size(const char *th, char previous_tag_size[4]);
};

class SrsEdgeQuicUpstream : public ISrsHourGlass, public SrsEdgeUpstream {
  private:
    SrsHourGlass *m_pTimer;
    SrsQuicState *m_State;

    struct lsquic_engine_api m_engine_api;
    struct lsquic_stream_if m_stream_if;

  private:
    SrsEdgeIngester *m_pSrsEdgeIngester;
    // We might modify the request by HTTP redirect.
    SrsRequest *m_pReq;
    SrsQuicFlvDecoder *m_pDecoder;
    // Current selected server, the ip:port.
    std::string selected_ip;
    int selected_port;

  public:
    SrsEdgeQuicUpstream(SrsEdgeIngester *pSrsEdgeIngester);
    virtual ~SrsEdgeQuicUpstream();

  public:
    virtual srs_error_t connect(SrsRequest *r, SrsLbRoundRobin *lb);
    virtual srs_error_t recv_message(SrsCommonMessage **pmsg);
    virtual srs_error_t decode_message(SrsCommonMessage *msg, SrsPacket **ppacket);
    virtual void close();
    virtual SrsQuicState *getSrsQuicState() { return m_State; }

  public:
    virtual void selected(std::string &server, int &port);
    virtual void set_recv_timeout(srs_utime_t tm);
    virtual void kbps_sample(const char *label, int64_t age);

  private:
    srs_error_t do_quic_connect();
    int init_ssl_ctx();
    virtual int read_message(const int nr, SrsCommonMessage **pmsg);
    virtual srs_error_t notify(int event, srs_utime_t interval, srs_utime_t tick);

  private:
    /* quic客户端的回调函数 */
    static lsquic_conn_ctx_t *client_on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn);
    static void client_on_conn_closed_cb(lsquic_conn_t *conn);
    static void client_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status);

    static lsquic_stream_ctx_t *client_on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream);
    static void client_on_stream_close_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h);
    static void client_on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
    static void client_on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
    /* quic客户端的回调函数结束 */
};

#endif
