#!/usr/bin/env python3
"""Prepare a private, hash-pinned Nano S SDK with shared-buffer ownership hooks.

Never changes the original SDK used by other apps. Fails on unexpected input.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

APP = Path(__file__).resolve().parents[1]
PIN = "93fa69b170dd819c6b93d5cf49dd21acee51ffd0"


def prepare(source, destination):
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("SDK source and destination must be separate trees")
    stamp = source / ".source-commit"
    revision = stamp.read_text().strip() if stamp.exists() else (
        subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if (source / ".git").exists() else None)
    if revision != PIN:
        raise ValueError("Expected the pinned Nano S SDK")
    hooks = {
        "lib_u2f/src/u2f_transport.c": [
            ('#include "u2f_io.h"', '#include "u2f_io.h"\n#include "transport.h"'),
            ('    service->next_channel                 = 1;', '    sk_transport_init();\n    service->next_channel                 = 1;'),
            ('    // don\'t process when replying to anti timeout requests', '    if (sk_transport_tx_busy()) return;\n    // don\'t process when replying to anti timeout requests'),
            ('    uint16_t channelHeader = (media == U2F_MEDIA_USB ? 4 : 0);\n    uint16_t xfer_len;', '    if (sk_transport_receive(service, buffer, size, media)) return;\n    uint16_t channelHeader = (media == U2F_MEDIA_USB ? 4 : 0);\n    uint16_t xfer_len;'),
            ('        u2f_message_complete(service);', '        sk_transport_app_enter();\n        u2f_message_complete(service);\n        sk_transport_app_leave();'),
        ],
        "lib_stusb_impl/u2f_io.c": [
            ('#include "u2f_impl.h"', '#include "u2f_impl.h"\n#include "transport.h"'),
            ('    if (media == U2F_MEDIA_USB) {', '    if (media == U2F_MEDIA_USB) {\n        sk_transport_tx_started();'),
        ],
        "lib_stusb_impl/usbd_impl.c": [
            ('            u2f_transport_sent(&G_io_u2f, U2F_MEDIA_USB);', '            sk_transport_tx_complete();'),
        ],
        "src/os_io_usb.c": [
            ('    uint8_t *apdu_buf;', '    if (sk_transport_apdu_blocked() || l < 7 || l > 64) return IO_USB_APDU_MORE_DATA;\n    uint8_t *apdu_buf;'),
            ('        G_io_app.apdu_state = APDU_IDLE;', '        G_io_app.apdu_state = APDU_IDLE;\n        sk_transport_poll();'),
        ],
        "src/os_io_seproxyhal.c": [
            ('    if (G_io_app.apdu_state == APDU_IDLE) {\n        size_t max', '    if (!sk_transport_raw_blocked() && G_io_app.apdu_state == APDU_IDLE) {\n        size_t max'),
        ],
    }
    original = {}
    patched = {}
    expected = json.loads((APP / "compat/sdk-source-hashes.json").read_text())
    for name, replacements in hooks.items():
        data = (source / name).read_bytes()
        original[name] = hashlib.sha256(data).hexdigest()
        if original[name] != expected[name]:
            raise ValueError("SDK source hash mismatch: " + name)
        text = data.decode().replace('\r\n', '\n')
        if name in ("lib_stusb_impl/usbd_impl.c", "src/os_io_usb.c", "src/os_io_seproxyhal.c"):
            text = '#include "transport.h"\n' + text
        for before, after in replacements:
            if text.count(before) != 1:
                raise ValueError("Unexpected hook location: " + name + " / " + before)
            text = text.replace(before, after)
        if name == "lib_u2f/src/u2f_transport.c":
            for function in ("u2f_transport_send_usb_user_presence_required", "u2f_transport_send_wink"):
                before = "void " + function + "(u2f_service_t *service)\n{"
                if text.count(before) != 1:
                    raise ValueError("Unexpected hook location: " + name + " / " + before)
                text = text.replace(before, before + '\n    if (sk_transport_tx_busy()) return;')
            before = "void u2f_transport_ctap2_send_keepalive(u2f_service_t *service, uint8_t reason)\n{"
            if text.count(before) != 1:
                raise ValueError("Unexpected hook location: " + name + " / " + before)
            text = text.replace(before, before + '\n    if (sk_transport_tx_busy() || service->transportState != U2F_PROCESSING_COMMAND) return;')
        patched[name] = text.encode()
    shutil.copytree(source, destination, dirs_exist_ok=True)
    for name, data in patched.items():
        (destination / name).write_bytes(data)
    manifest = {"sdk_commit": PIN, "original_sha256": original,
                "patched_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in patched.items()}}
    (destination / ".transport.json").write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source.resolve(), args.destination.resolve()), indent=2))
