// add by chenmin 4 quic
#ifndef SRS_APP_QUIC_CONN
#define SRS_APP_QUIC_CONN

extern "C"
{
#include "lsquic.h"
}

#include "srs_app_server.hpp"

class SrsRequest;

class SrsQuicConn : public ISrsCoroutineHandler
{
private:
    lsquic_stream_t *m_pStream;
    SrsCoroutine *m_trd;
    SrsRequest *m_pReq;

public:
    SrsQuicConn(lsquic_stream_t *pStream);
    virtual ~SrsQuicConn();

public:
    virtual srs_error_t start(SrsRequest *r);
    virtual srs_error_t cycle();

private:
    virtual srs_error_t do_cycle();
};

#endif
