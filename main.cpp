/*
 * Copyright 2020 Matt Sicker
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <sodium.h>
#include <getopt.h>

#include "signcrypt.h"

#define DEFAULT_CONTEXT "https://o1c.dev/"

// TODO: rename output
// TODO: options should be -s secret_key -p public_key -f from_sender_id -t to_recipient_id
void usage() {
    std::cerr << "o1c-sc: signcrypts (-e) or unsigncrypts (-d) stdin to stdout"
              << std::endl
              << "o1c-sc -e -s <sender secret key> -r <recipient public key> [-S <from sender id>] [-R <to recipient id>] [-C <context>]"
              << std::endl
              << "o1c-sc -d -s <sender public key> -r <recipient secret key> [-S <from sender id>] [-R <to recipient id>] [-C <context>]"
              << std::endl
              << "default ids are corresponding public keys; default context is " << DEFAULT_CONTEXT << std::endl;
}

/*
 * break up into:
 * o1c-encrypt
 * o1c-signcrypt
 * o1c-sign
 */

int main(int argc, char *argv[]) {
    if (sodium_init() == -1) {
        return -1;
    }
    if (argc == 1) {
        usage();
        return 0;
    }

    std::string sender_key, sender_id, recipient_key, recipient_id, context;
    bool encrypt = true;

    opterr = 0;
    int c;
    while ((c = getopt(argc, argv, "edhs:r:S:R:C:")) != -1) {
        switch (c) {
            case 's':
                sender_key = optarg;
                break;

            case 'r':
                recipient_key = optarg;
                break;

            case 'S':
                sender_id = optarg;
                break;

            case 'R':
                recipient_id = optarg;
                break;

            case 'C':
                context = optarg;
                break;

            case 'e':
                encrypt = true;
                break;

            case 'd':
                encrypt = false;
                break;

            case 'h':
                usage();
                return 0;

            default:
                usage();
                return 1;
        }
    }

    std::istreambuf_iterator<char> begin(std::cin), end;
    auto input = o1c::buffer(begin, end);
    auto info = o1c::buffer(context.cbegin(), context.cend());

    if (encrypt) {
        auto sk = o1c::parse_secret_key(sender_key);
        auto pk = o1c::parse_public_key(recipient_key);
        o1c::buffer sid, rid;
        if (sender_id.empty()) {
            auto sender_pk = o1c::gen_public_key(sk);
            sid = o1c::buffer(sender_pk.cbegin(), sender_pk.cend());
        } else {
            sid = o1c::buffer(sender_id.cbegin(), sender_id.cend());
        }
        if (recipient_id.empty()) {
            rid = o1c::buffer(pk.cbegin(), pk.cend());
        } else {
            rid = o1c::buffer(recipient_id.cbegin(), recipient_id.cend());
        }
        auto wrapped = o1c::signcrypt(sid, rid, info, sk, pk, input);
        std::move(wrapped.begin(), wrapped.end(), std::ostream_iterator<char>(std::cout));
    } else {
        auto sk = o1c::parse_secret_key(recipient_key);
        auto pk = o1c::parse_public_key(sender_key);
        o1c::buffer rid, sid;
        if (recipient_id.empty()) {
            auto recipient_pk = o1c::gen_public_key(sk);
            rid = o1c::buffer(recipient_pk.cbegin(), recipient_pk.cend());
        } else {
            rid = o1c::buffer(recipient_id.cbegin(), recipient_id.cend());
        }
        if (sender_id.empty()) {
            sid = o1c::buffer(pk.cbegin(), pk.cend());
        } else {
            rid = o1c::buffer(sender_id.cbegin(), sender_id.cend());
        }
        auto unwrapped = o1c::unsigncrypt(sid, rid, info, pk, sk, input);
        std::move(unwrapped.begin(), unwrapped.end(), std::ostream_iterator<char>(std::cout));
    }

    return 0;
}
