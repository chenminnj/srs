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

    srs_error("SrsQuicResponseWriter::write ,+++++++++++++++++ nwrite %d", nwrite);

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
    size_t nwritten;
    for (int i = 0; i < iovcnt; ++i) {
        nwritten = 0;
        // nwrite = lsquic_stream_writev(m_pStream, iov, iovcnt);
        while (nwritten < iov[i].iov_len) {
            nwrite = lsquic_stream_write(m_pStream, iov[i].iov_base + nwritten, iov[i].iov_len - nwritten);
            lsquic_stream_flush(m_pStream);
            srs_error("SrsQuicResponseWriter::writev in while,+++++++++++++++++ nwritten:  %d, iovs[i].iov_len: %d", nwritten, iov[i].iov_len);
            nwritten += nwrite;
        }
        // nwrite = lsquic_stream_write(m_pStream, iov[i].iov_base, iov[i].iov_len);
    }

    if (nwrite < 0) {
        return srs_error_new(ERROR_SOCKET_WRITE, "lsquic writev");
    }
    // lsquic_stream_flush(m_pStream);

    if (pnwrite) {
        *pnwrite = nwrite;
    }

    return err;
}
