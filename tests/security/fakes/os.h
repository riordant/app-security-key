#pragma once
#include <stdint.h>
#include <stdlib.h>
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define U2BE(p,o) ((uint16_t)(((p)[o] << 8) | (p)[(o)+1]))
#define THROW(x) abort()
#define EXCEPTION_IO_RESET 1
#define APDU_IDLE 0
#define APDU_U2F 1
#define APDU_USB_HID 2
#define IO_APDU_MEDIA_NONE 0
#define IO_APDU_MEDIA_USB_HID 1
struct test_io_app { int apdu_state, apdu_media; unsigned int apdu_length; };
extern struct test_io_app G_io_app;
extern uint8_t G_io_usb_ep_buffer[64];
extern struct u2f_service_t G_io_u2f;
#define IO_APDU_BUFFER_SIZE 1031
extern uint8_t G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];
void explicit_bzero(void *ptr, size_t size);
