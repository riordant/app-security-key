/*
 * Nano S transaction ownership for the pinned legacy SDK. Apache-2.0.
 *
 * G_io_apdu_buffer is shared by FIDO, Ledger HID and raw APDUs. Keep its owner
 * through review AND the final USB IN acknowledgement. Refusals use one small
 * deferred CID, never the pending request/response or an in-flight packet.
 */
#include <string.h>
#include "os.h"
#include "os_io_seproxyhal.h"
#include "u2f_io.h"
#include "u2f_transport.h"
#include "transport.h"

// Private SDK global, pinned and checked by compat/prepare_sdk.py.
extern volatile unsigned int G_io_usb_hid_remaining_length;
void u2f_transport_reset(u2f_service_t *service);
void u2f_handle_cmd_init(u2f_service_t *service, uint8_t *buffer,
                        uint16_t length, uint8_t *channelInit);

static bool tx_busy;
static bool refusal_pending;
static uint8_t refusal_cid[4];
static bool resync_pending;
static bool resync_prepared;
static uint8_t resync_packet[15]; // owner CID, INIT header, eight-byte nonce
static uint8_t app_depth;
static bool polling;
static bool cancel_pending;
static bool request_clear_pending;

static bool apdu_owns_buffer(void) {
    return G_io_usb_hid_remaining_length != 0 ||
           (G_io_app.apdu_state != APDU_IDLE && G_io_app.apdu_state != APDU_U2F);
}

static bool fido_owns_buffer(void) {
    return G_io_u2f.transportState != U2F_IDLE;
}

void sk_transport_init(void) {
    tx_busy = false;
    refusal_pending = false;
    memset(refusal_cid, 0, sizeof(refusal_cid));
    resync_pending = false;
    resync_prepared = false;
    memset(resync_packet, 0, sizeof(resync_packet));
    app_depth = 0;
    polling = false;
    cancel_pending = false;
    request_clear_pending = false;
}

void sk_transport_app_enter(void) {
    if (app_depth == UINT8_MAX) THROW(EXCEPTION_IO_RESET);
    app_depth++;
}

void sk_transport_app_leave(void) {
    if (app_depth == 0) THROW(EXCEPTION_IO_RESET);
    app_depth--;
    sk_transport_poll();
}

bool sk_transport_callback_enter(void) {
    if (!app_depth && !fido_owns_buffer() && !apdu_owns_buffer() &&
        !resync_pending && !sk_transport_ui_busy()) return false;
    sk_transport_app_enter();
    return true;
}

bool sk_transport_tx_busy(void) {
    return tx_busy;
}

void sk_transport_tx_started(void) {
    // Every producer must wait for the completion callback before reusing the EP.
    if (tx_busy) {
        THROW(EXCEPTION_IO_RESET);
    }
    tx_busy = true;
}

void sk_transport_request_clear(void) {
    request_clear_pending = true;
    sk_transport_poll();
}

static void clear_released_request(void) {
    if (request_clear_pending && !app_depth && !tx_busy &&
        !fido_owns_buffer() && !apdu_owns_buffer()) {
        explicit_bzero(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        request_clear_pending = false;
    }
}

void sk_transport_poll(void) {
    if (app_depth || polling || sk_transport_ui_busy()) return;
    if (resync_pending && !tx_busy &&
        (G_io_u2f.transportState == U2F_IDLE ||
         G_io_u2f.transportState == U2F_HANDLE_SEGMENTED ||
         (G_io_u2f.transportState == U2F_PROCESSING_COMMAND && sk_transport_can_abort_review()))) {
        polling = true;
        if (!resync_prepared) {
            // Invalidate the request once, after the old IN packet is acknowledged.
            // An actual review queues its redraw for a normal UI event.
            sk_transport_abort_review();
            u2f_transport_reset(&G_io_u2f);
            G_io_app.apdu_state = APDU_IDLE;
            G_io_app.apdu_media = IO_APDU_MEDIA_NONE;
            G_io_app.apdu_length = 0;
            cancel_pending = false;
            request_clear_pending = true;
            clear_released_request();
            resync_prepared = true;
        }
        if (sk_transport_ui_busy()) {
            // Leave the USB callback before drawing. Keep INIT pending until
            // that UI event completes, so the INIT reply means fully ready.
            polling = false;
            return;
        }
        // BAGL may have sent SCREEN_DISPLAY_STATUS during the callback that
        // just drew home. No USB command can follow that status until another
        // MCU event reopens the SPI window. Keep ownership and the queued INIT.
        if (io_seproxyhal_spi_is_status_sent()) {
            polling = false;
            return;
        }
        resync_pending = false;
        resync_prepared = false;
        G_io_u2f.media = U2F_MEDIA_USB;
        G_io_u2f.transportMedia = U2F_MEDIA_USB;
        // The queued INIT header/CID/length were validated at reception. Call
        // the pinned SDK's INIT handler directly instead of recursively entering
        // the entire RX parser from its own receive/completion callback.
        sk_transport_app_enter();
        u2f_handle_cmd_init(&G_io_u2f, resync_packet + 7, 8, resync_packet);
        sk_transport_app_leave();
        polling = false;
        return;
    }
    if (cancel_pending) {
        cancel_pending = false;
        if (G_io_u2f.transportState == U2F_PROCESSING_COMMAND && sk_transport_can_abort_review()) {
            polling = true;
            ctap2_handle_cmd_cancel(&G_io_u2f, NULL, 0);
            polling = false;
        }
    }
    clear_released_request();
    if (!refusal_pending || tx_busy || apdu_owns_buffer() || io_seproxyhal_spi_is_status_sent() ||
        G_io_u2f.transportState == U2F_SENDING_RESPONSE ||
        G_io_u2f.transportState == U2F_SENDING_ERROR) {
        return;
    }
    uint8_t packet[8];
    memcpy(packet, refusal_cid, 4);
    packet[4] = U2F_STATUS_ERROR;
    packet[5] = 0;
    packet[6] = 1;
    packet[7] = ERROR_CHANNEL_BUSY;
    refusal_pending = false;
    // u2f_io_send copies this packet to the persistent EP buffer synchronously.
    u2f_io_send(packet, sizeof(packet), U2F_MEDIA_USB);
}

void sk_transport_tx_complete(void) {
    if (!tx_busy) {
        return; // A duplicate/spurious completion must not advance a response.
    }
    tx_busy = false;
    u2f_transport_sent(&G_io_u2f, U2F_MEDIA_USB);
    sk_transport_poll();
}

bool sk_transport_apdu_blocked(void) {
    return fido_owns_buffer() || tx_busy || resync_pending || app_depth || polling || request_clear_pending || sk_transport_ui_busy() ||
           (refusal_pending && !apdu_owns_buffer());
}

bool sk_transport_raw_blocked(void) {
    return sk_transport_apdu_blocked() || G_io_usb_hid_remaining_length != 0;
}

static void refuse(const uint8_t *cid) {
    if (!refusal_pending) {
        memcpy(refusal_cid, cid, sizeof(refusal_cid));
        refusal_pending = true;
    }
    // One queued refusal is bounded even under a stream of hostile channels.
    // Additional clients retry. Never overwrite an IN transfer to send BUSY.
    sk_transport_poll();
}

bool sk_transport_receive(u2f_service_t *service, const uint8_t *packet,
                          uint16_t size, u2f_transport_media_t media) {
    if (media != U2F_MEDIA_USB || size < 5 || size > USB_SEGMENT_SIZE) {
        return true;
    }
    bool initial = (packet[4] & 0x80) != 0;
    if (initial && size < 7) {
        return true;
    }
    bool same = memcmp(packet, service->transportChannel, 4) == 0;

    // INIT on the owning CID is the protocol's abort/resynchronization path.
    // Never truncate a reply already in flight; finish it before the INIT reply.
    if (same && packet[4] == U2F_CMD_INIT && size >= 15 &&
        packet[5] == 0 && packet[6] == 8 && service->transportState != U2F_IDLE) {
        if (!resync_pending) {
            memcpy(resync_packet, packet, sizeof(resync_packet));
            resync_pending = true;
            resync_prepared = false;
        }
        sk_transport_poll();
        return true;
    }

    // CANCEL has no standalone reply. Only the owner may cancel a pending CTAP2
    // command; it may queue the final reply behind an in-flight keepalive.
    if (packet[4] == CTAP2_CMD_CANCEL) {
        if (same && size >= 7 && packet[5] == 0 && packet[6] == 0 &&
            service->transportState == U2F_PROCESSING_COMMAND &&
            service->waitAsynchronousResponse == U2F_WAIT_ASYNCH_IDLE) {
            cancel_pending = true;
            sk_transport_poll();
        }
        return true;
    }

    if (apdu_owns_buffer()) {
        if (initial) refuse(packet);
        return true;
    }
    if (service->transportState == U2F_PROCESSING_COMMAND ||
        service->transportState == U2F_SENDING_RESPONSE ||
        service->transportState == U2F_SENDING_ERROR) {
        // Legacy U2F polling checks CRC without modifying the request buffer.
        // Allow only the original channel, and only when the endpoint is free.
        if (same && !tx_busy && !refusal_pending &&
            service->transportState == U2F_PROCESSING_COMMAND &&
            service->waitAsynchronousResponse != U2F_WAIT_ASYNCH_IDLE) {
            return false;
        }
        if (initial) refuse(packet);
        return true;
    }
    if (tx_busy || refusal_pending || resync_pending || app_depth || polling || request_clear_pending || sk_transport_ui_busy() ||
        (service->transportState == U2F_HANDLE_SEGMENTED && !same)) {
        if (initial) refuse(packet);
        return true;
    }
    return false;
}
