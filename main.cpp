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

#include "secure_buffer.h"
#include "sealed_data.h"

void usage() {
    std::cerr << "o1c-gen: encrypts or decrypts stdin to stdout"
              << std::endl
              << "o1c-gen -e -a <sender_sk> -b <recipient_pk> [-s <sender_key id>] [-r <recipient_key id>] [-c <context>]"
              << std::endl
              << "o1c-gen -d -a <sender_pk> -b <recipient_sk> [-s <sender_key id>] [-r <recipient_key id>] [-c <context>]"
              << std::endl;
}

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
    while ((c = getopt(argc, argv, "a:b:s:r:c:hed")) != -1) {
        switch (c) {
            case 'a':
                sender_key = optarg;
                break;

            case 'b':
                recipient_key = optarg;
                break;

            case 's':
                sender_id = optarg;
                break;

            case 'r':
                recipient_id = optarg;
                break;

            case 'c':
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
    auto input = secure_buffer(std::string(begin, end));
    auto info = secure_buffer(context);

    if (encrypt) {
        auto sk = secure_buffer::from_hex(sender_key);
        auto pk = secure_buffer::from_hex(recipient_key);
        secure_buffer sid;
        if (sender_id.empty()) {
            sid = secure_buffer(sk.size());
            crypto_scalarmult_ristretto255_base(sid.data(), sk.data());
        } else {
            sid = secure_buffer(sender_id);
        }
        auto rid = recipient_id.empty() ? secure_buffer(pk) : secure_buffer(recipient_id);
        auto sealed = sealed_data::seal(sid, rid, info, sk, pk, input);
        std::cout << sealed;
    } else {
        auto sk = secure_buffer::from_hex(recipient_key);
        auto pk = secure_buffer::from_hex(sender_key);
        secure_buffer rid;
        if (recipient_id.empty()) {
            rid = secure_buffer(sk.size());
            crypto_scalarmult_ristretto255_base(rid.data(), sk.data());
        } else {
            rid = secure_buffer(recipient_id);
        }
        auto sid = sender_id.empty() ? secure_buffer(pk) : secure_buffer(sender_id);
        auto unsealed = sealed_data::unpack(input).unseal(sid, rid, info, pk, sk);
        std::cout << unsealed;
    }

    return 0;
}
