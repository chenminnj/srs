// add by chenmin 4 quic
#ifndef SRS_APP_QUIC_RESPONSEWRITER
#define SRS_APP_QUIC_RESPONSEWRITER

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>

extern "C" {
#include "lsquic.h"
}

#include "srs_app_server.hpp"
#include "srs_http_stack.hpp"

class SrsHttpHeader;
struct SrsQuicState;
class SrsQuicResponseWriter : public ISrsHttpResponseWriter {
  private:
    lsquic_stream_t *m_pStream;
    SrsQuicState *m_pSrsQuicState;

  public:
    SrsQuicResponseWriter(lsquic_stream_t *pStream, SrsQuicState *state);
    virtual ~SrsQuicResponseWriter();

  public:
    virtual srs_error_t final_request(){return NULL;};
    virtual SrsHttpHeader *header(){ return NULL;};
    virtual srs_error_t write(char *data, int size);
    virtual srs_error_t writev(const iovec *iov, int iovcnt, ssize_t *pnwrite);
    virtual void write_header(int code){};
    virtual srs_error_t send_header(char *data, int size){return NULL;};
};

#endif
