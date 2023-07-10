// add by chenmin 4 quic

extern "C" {
#include "lsquic.h"
}
#include "srs_app_quic_listener.hpp"
#include "srs_app_quic_writer.hpp"
#include "srs_kernel_log.hpp"
#include "srs_service_st.hpp"

SrsQuicResponseWriter::SrsQuicResponseWriter(lsquic_stream_t *pStream, SrsQuicState *state) {
    m_pStream = pStream;
    m_pSrsQuicState = state;
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
    process_conns(m_pSrsQuicState);

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
            nwrite = lsquic_stream_write(m_pStream, (char *)iov[i].iov_base + nwritten, iov[i].iov_len - nwritten);
            if (nwrite == 0) {
                srs_usleep(5);
            }else{
                lsquic_stream_flush(m_pStream);
                process_conns(m_pSrsQuicState);
                nwritten += nwrite;
            }
            srs_error("SrsQuicResponseWriter::writev in while,+++++++++++++++++ nwritten:  %d, iovs[i].iov_len: %d", nwritten, iov[i].iov_len);
            
        }
        srs_error("SrsQuicResponseWriter::writev in for,+444444444444444444444+ nwritten:  %d, iovs[i].iov_len: %d", nwritten, iov[i].iov_len);
    }

    // nwrite = lsquic_stream_writev(m_pStream, iov, iovcnt);
    // process_conns(m_pSrsQuicState);
    // srs_error("SrsQuicResponseWriter::writev ,+++++++++++++++++ nwrite:  %d", nwrite);

    if (nwrite < 0) {
        return srs_error_new(ERROR_SOCKET_WRITE, "lsquic writev");
    }
    // lsquic_stream_flush(m_pStream);

    if (pnwrite) {
        *pnwrite = nwrite;
    }

    return err;
}
