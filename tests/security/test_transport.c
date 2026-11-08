/* Exercise the actual patched legacy SDK transport with controlled IN acks. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "os.h"
#include "u2f_service.h"
#include "u2f_transport.h"
#include "u2f_processing.h"
#include "transport.h"

struct test_io_app G_io_app;
u2f_service_t G_io_u2f;
uint8_t G_io_usb_ep_buffer[64];
volatile unsigned int G_io_usb_hid_remaining_length;
uint8_t G_io_apdu_buffer[1031];
#define buffer G_io_apdu_buffer
static uint8_t response[512], snapshot[1031];
static uint8_t sent[1024][64];
static unsigned int sends, messages, cancels, aborts, review_resets;
static bool can_abort = true;
static bool ui_busy, defer_redraw;
static bool spi_status_sent;
static const uint8_t owner[4] = {1,2,3,4}, attacker[4] = {5,6,7,8};

uint16_t cx_crc16_update(uint16_t crc, const void *input, size_t len) {
    const uint8_t *data = input;
    while (len--) {
        crc ^= (uint16_t)*data++ << 8;
        for (int i=0; i<8; i++) crc = (crc & 0x8000) ? (crc<<1)^0x1021 : crc<<1;
    }
    return crc;
}

void u2f_io_send(uint8_t *data, uint16_t len, u2f_transport_media_t media) {
    assert(media == U2F_MEDIA_USB && len <= 64 && sends < 1024);
    assert(!spi_status_sent); // A display/general status has closed this MCU window.
    sk_transport_tx_started();
    memmove(G_io_usb_ep_buffer, data, len);
    memset(G_io_usb_ep_buffer + len, 0, 64-len);
    memcpy(sent[sends++], G_io_usb_ep_buffer, 64);
}

unsigned int io_seproxyhal_spi_is_status_sent(void) { return spi_status_sent; }

void sk_transport_abort_review(void) {
    assert(!sk_transport_tx_busy());
    review_resets++;
    if (can_abort) {
        aborts++;
        if (defer_redraw) ui_busy=true;
    }
    can_abort=false;
    // Model the real hook's end-of-review/request-wipe interaction.
    sk_transport_request_clear();
}
bool sk_transport_can_abort_review(void) { return can_abort; }
bool sk_transport_ui_busy(void) { return ui_busy; }
void ctap2_handle_cmd_cancel(u2f_service_t *service, uint8_t *data, uint16_t len) {
    (void)data; (void)len;
    cancels++;
    response[0] = ERROR_KEEPALIVE_CANCEL;
    u2f_message_reply(service, CTAP2_CMD_CBOR, response, 1);
}
void u2f_handle_cmd_init(u2f_service_t *service, uint8_t *nonce, uint16_t length, uint8_t *cid) {
    assert(length==8);
    memmove(buffer,nonce,8);
    memcpy(buffer+8,cid,4);
    memcpy(service->channel,cid,4);
    memset(buffer+12,0,5);
    u2f_message_reply(service,U2F_CMD_INIT,buffer,17);
}
void u2f_message_complete(u2f_service_t *service) {
    messages++;
    if (service->transportBuffer[0] == U2F_CMD_INIT)
        u2f_handle_cmd_init(service,service->transportBuffer+3,8,service->channel);
}

static void init(void) {
    memset(&G_io_u2f, 0, sizeof(G_io_u2f));
    memset(&G_io_app, 0, sizeof(G_io_app));
    memset(buffer, 0xa5, sizeof(buffer));
    sends=messages=cancels=aborts=review_resets=0;
    can_abort=true;
    ui_busy=defer_redraw=false;
    spi_status_sent=false;
    G_io_usb_hid_remaining_length=0;
    u2f_transport_init(&G_io_u2f, buffer, sizeof(buffer));
}

static void packet(uint8_t *out, const uint8_t *cid, uint8_t cmd, uint16_t len) {
    memset(out, 0, 64); memcpy(out, cid, 4); out[4]=cmd; out[5]=len>>8; out[6]=len;
}
static void receive(const uint8_t *cid, uint8_t cmd, uint16_t len) {
    uint8_t p[64]; packet(p,cid,cmd,len);
    u2f_transport_received(&G_io_u2f,p,64,U2F_MEDIA_USB);
}
static void pending(void) {
    init(); receive(owner,CTAP2_CMD_CBOR,16);
    assert(messages==1 && G_io_u2f.transportState==U2F_PROCESSING_COMMAND);
    memcpy(snapshot,buffer,sizeof(buffer));
}
static void assert_owned(void) {
    assert(memcmp(buffer,snapshot,sizeof(buffer))==0);
    assert(memcmp(G_io_u2f.channel,owner,4)==0);
    assert(memcmp(G_io_u2f.transportChannel,owner,4)==0);
}
static void ack(void) { sk_transport_tx_complete(); }
static void drain(void) { for (int i=0; i<64 && sk_transport_tx_busy(); i++) ack(); assert(!sk_transport_tx_busy()); }

static void test_pending_and_channels(void) {
    pending();
    receive(attacker,U2F_CMD_INIT,8);
    assert_owned(); assert(messages==1 && sends==1);
    assert(memcmp(sent[0],attacker,4)==0 && sent[0][4]==U2F_STATUS_ERROR && sent[0][7]==ERROR_CHANNEL_BUSY);
    receive(owner,CTAP2_CMD_CBOR,30); receive(attacker,U2F_CMD_PING,2);
    assert_owned(); assert(sends==1); // IN packet remains immutable until ack
    drain();
    assert(messages==1 && G_io_u2f.transportState==U2F_PROCESSING_COMMAND);
    assert(sk_transport_apdu_blocked() && sk_transport_raw_blocked());
}

static void test_reply_and_keepalive(void) {
    pending();
    u2f_transport_ctap2_send_keepalive(&G_io_u2f,2);
    assert(sends==1);
    uint8_t first[64]; memcpy(first,G_io_usb_ep_buffer,64);
    u2f_transport_ctap2_send_keepalive(&G_io_u2f,2);
    receive(attacker,U2F_CMD_PING,1);
    assert(sends==1 && memcmp(first,G_io_usb_ep_buffer,64)==0);
    for (unsigned int i=0; i<sizeof(response); i++) response[i]=(uint8_t)i;
    u2f_message_reply(&G_io_u2f,CTAP2_CMD_CBOR,response,200);
    assert(sends==1); // real reply queued behind keepalive
    ack(); assert(sends==2 && memcmp(sent[1],owner,4)==0 && sent[1][4]==CTAP2_CMD_CBOR);
    receive(attacker,U2F_CMD_INIT,8); assert(sends==2);
    assert(sk_transport_apdu_blocked());
    ack(); ack(); ack(); // four response packets have now been sent
    assert(sends==5 && G_io_u2f.transportState==U2F_SENDING_RESPONSE);
    assert(sk_transport_raw_blocked());
    ack(); // last response ack; now flush the queued refusal
    assert(sends==6 && sent[5][4]==U2F_STATUS_ERROR && memcmp(sent[5],attacker,4)==0);
    assert(sk_transport_apdu_blocked());
    ack(); assert(!sk_transport_apdu_blocked());
    uint8_t recovered[200]; memcpy(recovered,sent[1]+7,57);
    memcpy(recovered+57,sent[2]+5,59); memcpy(recovered+116,sent[3]+5,59); memcpy(recovered+175,sent[4]+5,25);
    assert(memcmp(recovered,response,200)==0);
    ack(); assert(sends==6); // duplicate idle completion
}

static void test_cancel(void) {
    pending(); receive(attacker,CTAP2_CMD_CANCEL,0); assert(cancels==0); assert_owned();
    u2f_transport_ctap2_send_keepalive(&G_io_u2f,2);
    receive(owner,CTAP2_CMD_CANCEL,1); assert(cancels==0);
    receive(owner,CTAP2_CMD_CANCEL,0); assert(cancels==1 && sends==1);
    ack(); assert(sends==2 && sent[1][7]==ERROR_KEEPALIVE_CANCEL && memcmp(sent[1],owner,4)==0);
    ack(); assert(!sk_transport_apdu_blocked());
}

static void test_segmented_and_resync(void) {
    init(); receive(owner,CTAP2_CMD_CBOR,100);
    assert(messages==0 && G_io_u2f.transportState==U2F_HANDLE_SEGMENTED);
    memcpy(snapshot,buffer,sizeof(buffer)); receive(attacker,U2F_CMD_INIT,8); assert_owned(); ack();
    uint8_t p[64]; memset(p,0,64); memcpy(p,owner,4);
    u2f_transport_received(&G_io_u2f,p,64,U2F_MEDIA_USB); assert(messages==1);
    u2f_transport_ctap2_send_keepalive(&G_io_u2f,2);
    packet(p,owner,U2F_CMD_INIT,8); memset(p+7,0x55,8);
    u2f_transport_received(&G_io_u2f,p,64,U2F_MEDIA_USB);
    assert(aborts==0 && sk_transport_apdu_blocked()); // old keepalive is still in flight
    ack(); assert(sent[sends-1][4]==U2F_CMD_INIT && sent[sends-1][7]==0x55);
    assert(aborts==1);
    ack(); assert(!sk_transport_apdu_blocked() && aborts==1);
}

static void test_resync_dismisses_review_once(void) {
    pending();
    receive(owner,U2F_CMD_INIT,8);
    drain();
    assert(aborts==1 && review_resets==1); // Clean up once per owner INIT.
    assert(!can_abort && !sk_transport_apdu_blocked());
}

static void test_segmented_resync_has_no_review_to_dismiss(void) {
    init(); can_abort=false;
    receive(owner,CTAP2_CMD_CBOR,100);
    assert(G_io_u2f.transportState==U2F_HANDLE_SEGMENTED);
    receive(owner,U2F_CMD_INIT,8);
    drain();
    assert(aborts==0 && review_resets==1);
    assert(!sk_transport_apdu_blocked());
}

static void test_deferred_ui_still_owns_the_buffer(void) {
    pending(); defer_redraw=true;
    receive(owner,U2F_CMD_INIT,8);
    assert(sends==0 && ui_busy); // INIT reply waits for the normal UI event.
    assert(sk_transport_apdu_blocked() && sk_transport_raw_blocked());
    memcpy(snapshot,buffer,sizeof(buffer));
    unsigned int previous=sends;
    receive(attacker,CTAP2_CMD_CBOR,16);
    assert(messages==1 && sends==previous && memcmp(snapshot,buffer,sizeof(buffer))==0);
    // A normal UI event owns the deferred redraw until all its nested work ends.
    assert(sk_transport_callback_enter());
    ui_busy=false;
    sk_transport_app_leave();
    assert(sent[sends-1][4]==U2F_CMD_INIT && memcmp(sent[sends-1],owner,4)==0);
    assert(review_resets==1); // Resuming after redraw must not repeat cleanup.
    ack();
    assert(sent[sends-1][4]==U2F_STATUS_ERROR && memcmp(sent[sends-1],attacker,4)==0);
    drain();
    assert(!sk_transport_apdu_blocked());
    receive(owner,CTAP2_CMD_CBOR,16);
    assert(messages==2);
}

static void test_resync_waits_for_mcu_window_after_redraw(void) {
    pending(); defer_redraw=true;
    receive(owner,U2F_CMD_INIT,8);
    assert(sends==0 && ui_busy);
    assert(sk_transport_callback_enter());
    ui_busy=false;
    spi_status_sent=true; // Drawing home sent a SCREEN_DISPLAY_STATUS.
    sk_transport_app_leave();
    assert(sends==0 && sk_transport_apdu_blocked());
    memcpy(snapshot,buffer,sizeof(buffer));
    receive(attacker,CTAP2_CMD_CBOR,16);
    assert(sends==0 && memcmp(snapshot,buffer,sizeof(buffer))==0);
    // Receiving a new event reopens the window. Ownership spans its UX callback.
    spi_status_sent=false;
    assert(sk_transport_callback_enter());
    sk_transport_app_leave();
    assert(sends==1 && sent[0][4]==U2F_CMD_INIT);
    assert(review_resets==1);
    drain();
    assert(!sk_transport_apdu_blocked());
}

static void test_refusal_waits_for_mcu_window(void) {
    pending(); spi_status_sent=true;
    receive(attacker,CTAP2_CMD_CBOR,16);
    assert(sends==0); assert_owned();
    spi_status_sent=false;
    sk_transport_poll();
    assert(sends==1 && sent[0][4]==U2F_STATUS_ERROR);
    drain(); assert_owned();
}

static void test_generic_owner_and_malformed(void) {
    init(); memcpy(snapshot,buffer,sizeof(buffer));
    G_io_usb_hid_remaining_length=100;
    receive(attacker,CTAP2_CMD_CBOR,20);
    assert(messages==0 && sends==0 && memcmp(buffer,snapshot,sizeof(buffer))==0);
    assert(!sk_transport_apdu_blocked() && sk_transport_raw_blocked()); // owner may finish HID RX
    G_io_usb_hid_remaining_length=0; G_io_app.apdu_state=APDU_USB_HID;
    sk_transport_poll(); assert(sends==0);
    G_io_app.apdu_state=APDU_IDLE; sk_transport_poll(); assert(sends==1); ack();
    pending();
    for (unsigned int size=0; size<=64; size++) {
        uint8_t p[64]; packet(p,attacker,CTAP2_CMD_CBOR,1028);
        u2f_transport_received(&G_io_u2f,p,size,U2F_MEDIA_USB);
        assert_owned(); drain();
    }
    assert(messages==1);
}

static void test_legacy_u2f_polling(void) {
    init(); receive(owner,U2F_CMD_MSG,8);
    memcpy(snapshot,buffer,sizeof(buffer));
    u2f_message_set_autoreply_wait_user_presence(&G_io_u2f,true);
    assert(sends==1); ack();
    for (int i=0; i<3; i++) {
        receive(owner,U2F_CMD_MSG,8);
        assert_owned(); assert(sent[sends-1][4]==U2F_CMD_MSG);
        ack();
    }
    receive(attacker,U2F_CMD_MSG,8); assert_owned(); drain();
    u2f_message_set_autoreply_wait_user_presence(&G_io_u2f,false);
    receive(owner,U2F_CMD_MSG,8);
    memset(response,0x42,32);
    u2f_message_reply(&G_io_u2f,U2F_CMD_MSG,response,32);
    assert(sent[sends-1][4]==U2F_CMD_MSG && sent[sends-1][7]==0x42);
    ack(); assert(!sk_transport_apdu_blocked());
}

static void test_callback_lifetime(void) {
    pending();
    sk_transport_app_enter(); can_abort=false;
    receive(owner,U2F_CMD_INIT,8);
    assert(aborts==0 && G_io_u2f.transportState==U2F_PROCESSING_COMMAND);
    memset(response,0x99,70);
    u2f_message_reply(&G_io_u2f,CTAP2_CMD_CBOR,response,70);
    drain(); // packet complete, callback still active
    assert(sk_transport_apdu_blocked() && aborts==0);
    receive(attacker,CTAP2_CMD_CBOR,3);
    assert(messages==1); // no reentrant handler while old callback finishes
    sk_transport_app_leave();
    assert(sent[sends-1][4]==U2F_CMD_INIT);
    drain(); assert(!sk_transport_apdu_blocked());
}

static void test_deferred_request_clear(void) {
    pending(); sk_transport_app_enter();
    sk_transport_request_clear(); assert_owned();
    // Nano S uses the same storage for the request and its response.
    memset(buffer,0x73,200);
    u2f_message_reply(&G_io_u2f,CTAP2_CMD_CBOR,buffer,200);
    ack(); ack(); ack();
    assert(buffer[0]==0x73 && G_io_u2f.transportState==U2F_SENDING_RESPONSE);
    ack(); // final IN ACK, but the application callback still owns the data
    assert(buffer[0]==0x73 && sk_transport_apdu_blocked());
    sk_transport_app_leave();
    for(size_t i=0;i<sizeof(buffer);i++) assert(buffer[i]==0);
    assert(!sk_transport_apdu_blocked());
    assert(sent[0][7]==0x73 && sent[3][5]==0x73);
    // General APDU storage follows the same lifetime, including fragmented RX.
    init(); G_io_usb_hid_remaining_length=10;
    sk_transport_request_clear(); assert(buffer[0]==0xa5);
    G_io_usb_hid_remaining_length=0; G_io_app.apdu_state=APDU_USB_HID;
    sk_transport_poll(); assert(buffer[0]==0xa5);
    G_io_app.apdu_state=APDU_IDLE; sk_transport_poll();
    for(size_t i=0;i<sizeof(buffer);i++) assert(buffer[i]==0);
}

int main(void) {
    test_pending_and_channels(); test_reply_and_keepalive(); test_cancel();
    test_segmented_and_resync(); test_generic_owner_and_malformed();
    test_resync_dismisses_review_once(); test_segmented_resync_has_no_review_to_dismiss();
    test_deferred_ui_still_owns_the_buffer();
    test_resync_waits_for_mcu_window_after_redraw(); test_refusal_waits_for_mcu_window();
    test_legacy_u2f_polling();
    test_callback_lifetime();
    test_deferred_request_clear();
    puts("transport ownership: all cases passed");
}
