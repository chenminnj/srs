// add by chenmin 4 quic

extern "C" {
#include "lsquic.h"
}
#include "srs_app_http_stream.hpp"
#include "srs_app_pithy_print.hpp"
#include "srs_app_quic_conn.hpp"
#include "srs_app_quic_writer.hpp"
#include "srs_core_autofree.hpp"
#include "srs_core_performance.hpp"
#include "srs_http_stack.hpp"
#include "srs_kernel_log.hpp"
#include "srs_rtmp_msg_array.hpp"
#include "srs_rtmp_stack.hpp"
#include "srs_app_config.hpp"

SrsQuicConn::SrsQuicConn(lsquic_stream_t *pStream) {
    m_pReq = NULL;
    m_pStream = pStream;
    m_trd = new SrsSTCoroutine("quic server", this, _srs_context->get_id());
}

SrsQuicConn::~SrsQuicConn() {
    m_trd->interrupt();
    srs_freep(m_trd);
    srs_freep(m_pReq);
}

srs_error_t SrsQuicConn::start(SrsRequest *r) {
    srs_error_t err = srs_success;

    m_pReq = r->copy();

    if ((err = m_trd->start()) != srs_success) {
        return srs_error_wrap(err, "quic server coroutine");
    }

    return err;
}

srs_error_t SrsQuicConn::cycle() {
    srs_error_t err = srs_success;
    if ((err = do_cycle()) != srs_success) {
        err = srs_error_wrap(err, "SrsQuicConn cycle");
    }

    // TODO
    // // Notify handler to handle it.
    // // @remark The error may be transformed by handler.
    // err = handler_->on_conn_done(err);

    // // success.
    // if (err == srs_success) {
    //     srs_trace("client finished.");
    //     return err;
    // }

    // // It maybe success with message.
    // if (srs_error_code(err) == ERROR_SUCCESS) {
    //     srs_trace("client finished%s.", srs_error_summary(err).c_str());
    //     srs_freep(err);
    //     return err;
    // }

    // // client close peer.
    // // TODO: FIXME: Only reset the error when client closed it.
    // if (srs_is_client_gracefully_close(err)) {
    //     srs_warn("client disconnect peer. ret=%d", srs_error_code(err));
    // } else if (srs_is_server_gracefully_close(err)) {
    //     srs_warn("server disconnect. ret=%d", srs_error_code(err));
    // } else {
    //     srs_error("serve error %s", srs_error_desc(err).c_str());
    // }

    // srs_freep(err);

    return err;
}

srs_error_t SrsQuicConn::do_cycle() {
    srs_error_t err = srs_success;

    // create quic writer with lsquic stream
    ISrsHttpResponseWriter *pResponseWriter = new SrsQuicResponseWriter(m_pStream);
    SrsAutoFree(ISrsHttpResponseWriter, pResponseWriter);

    // create flv encoder
    ISrsBufferEncoder *pEnc = new SrsFlvStreamEncoder();
    SrsAutoFree(ISrsBufferEncoder, pEnc);

    SrsPithyPrint *pprint = SrsPithyPrint::create_http_stream();
    SrsAutoFree(SrsPithyPrint, pprint);

    // create rtmp source
    SrsLiveSource *pRtmpSource = NULL;
    pRtmpSource = _srs_sources->fetch(m_pReq);
    if (NULL == pRtmpSource) {
        return srs_error_wrap(err, "quic server fetch source: do not has this live stream %s.", m_pReq->get_stream_url().c_str());
    }
    // rtmpSource->set_cache(false);

    // create rtmp consumer
    SrsLiveConsumer *pConsumer = NULL;
    SrsAutoFree(SrsLiveConsumer, pConsumer);
    if ((err = pRtmpSource->create_consumer(pConsumer)) != srs_success) {
        return srs_error_wrap(err, "quic server create consumer");
    }
    if ((err = pRtmpSource->consumer_dumps(pConsumer, true, true, !pEnc->has_cache())) !=
        srs_success) {
        return srs_error_wrap(err, "quic server dumps consumer");
    }

    // create memory writer.
    SrsBufferWriter writer(pResponseWriter);
    if ((err = pEnc->initialize(&writer, NULL)) != srs_success) {
        return srs_error_wrap(err, "init encoder");
    }

    // if gop cache enabled for encoder, dump to consumer.
    if (pEnc->has_cache()) {
        if ((err = pEnc->dump_cache(pConsumer, pRtmpSource->jitter())) != srs_success) {
            return srs_error_wrap(err, "encoder dump cache");
        }
    }

    SrsMessageArray msgs(SRS_PERF_MW_MSGS);
    while (true) {
        if ((err = m_trd->pull()) != srs_success) {
            return srs_error_wrap(err, "quic server thread");
        }
        pprint->elapse();

        // get messages from consumer.
        // each msg in msgs.msgs must be free, for the SrsMessageArray never
        // free them.
        int count = 0;
        if ((err = pConsumer->dump_packets(&msgs, count)) != srs_success) {
            return srs_error_wrap(err, "quic server consumer dump packets");
        }

        // TODO: FIXME: Support merged-write wait.
        srs_utime_t mw_sleep = _srs_config->get_mw_sleep(m_pReq->vhost);
        if (count <= 0) {
            // Directly use sleep, donot use consumer wait, because we couldn't
            // awake consumer.
            srs_usleep(mw_sleep);
            // ignore when nothing got.
            continue;
        }

        if (pprint->can_print()) {
            srs_trace("-> " SRS_CONSTS_LOG_HTTP_STREAM
                      " quic server: got %d msgs, age=%d, min=%d, mw=%d",
                      count, pprint->age(), SRS_PERF_MW_MIN_MSGS,
                      srsu2msi(mw_sleep));
        }

        // sendout all messages.
        SrsFlvStreamEncoder *ffe = dynamic_cast<SrsFlvStreamEncoder *>(pEnc);
        err = ffe->write_tags(msgs.msgs, count);

        // free the messages.
        for (int i = 0; i < count; i++) {
            SrsSharedPtrMessage *msg = msgs.msgs[i];
            srs_freep(msg);
        }

        // check send error code.
        if (err != srs_success) {
            return srs_error_wrap(err, "quic server send messages");
        }
    }
    return err;
}
