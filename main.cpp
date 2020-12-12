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
#include <memory>
#include <utility>
#include <vector>
#include <sodium.h>
#include "signcrypt_tbsbr.h"

typedef std::vector<uint8_t> byte_string;

byte_string
make_byte_string(const std::string &str) {
    return std::move(std::vector<uint8_t>(str.begin(), str.end()));
}

std::ostream &operator<<(std::ostream &os, const byte_string &bs) {
    auto hex = std::vector<char>(bs.size() * 2 + 1);
    os << sodium_bin2hex(hex.data(), hex.size(), bs.data(), bs.size());
    return os;
}

struct key_pair {
    byte_string sk;
    byte_string pk;

    key_pair() : sk(crypto_signcrypt_tbsbr_SECRETKEYBYTES), pk(crypto_signcrypt_tbsbr_SECRETKEYBYTES) {
        crypto_signcrypt_tbsbr_keygen(pk.data(), sk.data());
    }

    friend std::ostream &operator<<(std::ostream &os, const key_pair &pair);
};

std::ostream &operator<<(std::ostream &os, const key_pair &pair) {
    os << "sk: " << pair.sk << " pk: " << pair.pk;
    return os;
}

struct sealed_data {
    byte_string nonce;
    byte_string mac;
    byte_string sig;
    byte_string ct;

    sealed_data(byte_string nonce, byte_string mac, byte_string sig, byte_string ct)
            : nonce(std::move(nonce)), mac(std::move(mac)), sig(std::move(sig)), ct(std::move(ct)) {}

    friend std::ostream &operator<<(std::ostream &os, const sealed_data &data);

};

std::ostream &operator<<(std::ostream &os, const sealed_data &data) {
    os << "nonce: " << data.nonce << " mac: " << data.mac << " sig: " << data.sig << " ct: " << data.ct;
    return os;
}

struct sealed_data_exception : std::exception {
};

sealed_data seal(const byte_string &sender_id, const byte_string &recipient_id, const byte_string &info,
                 const byte_string &sender_sk, const byte_string &recipient_pk, const byte_string &msg) {
    byte_string st(crypto_signcrypt_tbsbr_STATEBYTES);
    byte_string key(crypto_secretbox_xchacha20poly1305_KEYBYTES);
    byte_string nonce(crypto_secretbox_xchacha20poly1305_NONCEBYTES);
    byte_string mac(crypto_secretbox_xchacha20poly1305_MACBYTES);
    byte_string sig(crypto_signcrypt_tbsbr_SIGNBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    byte_string ct(msg.size());
    if (crypto_signcrypt_tbsbr_sign_before(st.data(), key.data(), sender_id.data(), sender_id.size(),
                                           recipient_id.data(), recipient_id.size(), info.data(), info.size(),
                                           sender_sk.data(), recipient_pk.data(), msg.data(), msg.size()) != 0 ||
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(ct.data(), mac.data(), nullptr, msg.data(), msg.size(),
                                                            info.data(), info.size(),
                                                            nullptr, nonce.data(), key.data()) != 0 ||
        crypto_signcrypt_tbsbr_sign_after(st.data(), sig.data(), sender_sk.data(), ct.data(), ct.size())) {
        throw sealed_data_exception();
    }
    return std::move(sealed_data(nonce, mac, sig, ct));
}

byte_string unseal(const byte_string &sender_id, const byte_string &recipient_id, const byte_string &info,
                   const byte_string &sender_pk, const byte_string &recipient_sk, const sealed_data &data) {
    byte_string st(crypto_signcrypt_tbsbr_STATEBYTES);
    byte_string key(crypto_secretbox_xchacha20poly1305_KEYBYTES);
    byte_string msg(data.ct.size());
    if (crypto_signcrypt_tbsbr_verify_before(st.data(), key.data(), data.sig.data(), sender_id.data(), sender_id.size(),
                                             recipient_id.data(), recipient_id.size(), info.data(), info.size(),
                                             sender_pk.data(), recipient_sk.data()) != 0 ||
        crypto_aead_xchacha20poly1305_ietf_decrypt_detached(msg.data(), nullptr, data.ct.data(), data.ct.size(),
                                                            data.mac.data(), info.data(), info.size(),
                                                            data.nonce.data(), key.data()) != 0 ||
        crypto_signcrypt_tbsbr_verify_after(st.data(), data.sig.data(), sender_pk.data(), data.ct.data(),
                                            data.ct.size()) != 0) {
        throw sealed_data_exception();
    }
    return std::move(msg);
}

int main() {
    if (sodium_init() == -1) {
        return -1;
    }

    auto alice = key_pair();
    auto aliceId = make_byte_string("Alice");
    auto bob = key_pair();
    auto bobId = make_byte_string("Bob");

    auto info = make_byte_string("whole bean");
    auto msg = make_byte_string(
            "Ristretto is traditionally a short shot of espresso coffee made with the normal amount of ground coffee "
            "but extracted with about half the amount of water in the same amount of time by using a finer grind. "
            "This produces a concentrated shot of coffee per volume. Just pulling a normal shot short will produce a "
            "weaker shot and is not a Ristretto as some believe.");
    auto sealed = seal(aliceId, bobId, info, alice.sk, bob.pk, msg);
    std::cout << "Alice " << alice << std::endl
              << "Bob " << bob << std::endl
              << "Sealed " << sealed << std::endl;

    auto unsealed = unseal(aliceId, bobId, info, alice.pk, bob.sk, sealed);
    std::cout << std::string(unsealed.begin(), unsealed.end()) << std::endl;

    return 0;
}
