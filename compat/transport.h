/* Nano S shared-buffer transaction ownership. Apache-2.0. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "u2f_service.h"

#ifdef HAVE_TRANSPORT_GUARD
void sk_transport_init(void);
bool sk_transport_receive(u2f_service_t *service, const uint8_t *packet,
                          uint16_t size, u2f_transport_media_t media);
bool sk_transport_tx_busy(void);
void sk_transport_tx_started(void);
void sk_transport_tx_complete(void);
bool sk_transport_apdu_blocked(void);
bool sk_transport_raw_blocked(void);
void sk_transport_poll(void);
void sk_transport_request_clear(void);
// App hook: dismiss a resynchronized review without producing a stale reply.
void sk_transport_abort_review(void);
bool sk_transport_can_abort_review(void);
bool sk_transport_ui_busy(void);
void sk_transport_app_enter(void);
void sk_transport_app_leave(void);
bool sk_transport_callback_enter(void);
#else
static inline void sk_transport_poll(void) {}
static inline void sk_transport_app_enter(void) {}
static inline void sk_transport_app_leave(void) {}
static inline bool sk_transport_callback_enter(void) { return false; }
static inline bool sk_transport_ui_busy(void) { return false; }
#endif
