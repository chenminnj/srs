// add by chenmin 4 quic

extern "C" {
#include "lsquic.h"
}
#include "srs_app_quic_writer.hpp"
#include "srs_kernel_log.hpp"

SrsQuicResponseWriter::SrsQuicResponseWriter(lsquic_stream_t *pStream) {
    m_pStream = pStream;
}

SrsQuicResponseWriter::~SrsQuicResponseWriter() {}

srs_error_t SrsQuicResponseWriter::write(char *data, int size) {
    srs_error_t err = srs_success;

    ssize_t nwrite = 0;
    nwrite = lsquic_stream_write(m_pStream, data, size);

    if (nwrite < 0) {
        return srs_error_new(ERROR_SOCKET_WRITE, "lsquic write");
    }
    lsquic_stream_flush(m_pStream);

    return err;
}

srs_error_t SrsQuicResponseWriter::writev(const iovec *iov, int iovcnt,
                                          ssize_t *pnwrite) {
    srs_error_t err = srs_success;

    ssize_t nwrite = 0;
    if ((nwrite = lsquic_stream_writev(m_pStream, iov, iovcnt)) < 0) {
        return srs_error_new(ERROR_SOCKET_WRITE, "lsquic writev");
    }
    lsquic_stream_flush(m_pStream);

    if (pnwrite) {
        *pnwrite = nwrite;
    }

    return err;
}
