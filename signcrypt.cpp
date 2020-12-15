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

#include "signcrypt.h"
#include <sodium.h>
#include "signcrypt_tbsbr.h"

namespace o1c {
    typedef std::array<uint8_t, crypto_signcrypt_tbsbr_STATEBYTES> state_t;
    typedef std::array<uint8_t, crypto_signcrypt_tbsbr_SIGNBYTES> sig_t;
    typedef std::array<uint8_t, crypto_secretbox_xchacha20poly1305_KEYBYTES> shared_key;
    typedef std::array<uint8_t, crypto_secretbox_xchacha20poly1305_NONCEBYTES> nonce_t;
    typedef std::array<uint8_t, crypto_secretbox_xchacha20poly1305_MACBYTES> mac_t;
}

o1c::buffer o1c::signcrypt(const o1c::buffer &sender_id, const o1c::buffer &recipient_id, const o1c::buffer &info,
                           const o1c::secret_key &sender_key, const o1c::public_key &recipient_key,
                           const o1c::buffer &message) {
    auto st = state_t();
    auto key = shared_key();
    auto nonce = nonce_t();
    auto mac = mac_t();
    auto sig = sig_t();
    auto ct = buffer(message.size() + mac.size());

    randombytes_buf(nonce.data(), nonce.size());
    if (crypto_signcrypt_tbsbr_sign_before(st.data(), key.data(), sender_id.data(), sender_id.size(),
                                           recipient_id.data(), recipient_id.size(), info.data(), info.size(),
                                           sender_key.data(), recipient_key.data(), message.data(), message.size()) !=
        0 ||
        crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), nullptr, message.data(), message.size(), info.data(),
                                                   info.size(),
                                                   nullptr, nonce.data(), key.data()) != 0 ||
        crypto_signcrypt_tbsbr_sign_after(st.data(), sig.data(), sender_key.data(), ct.data(), message.size())) {
        throw std::exception();
    }
    auto wrapped = buffer(nonce.size() + ct.size() + sig.size());
    auto out = std::move(std::begin(nonce), std::end(nonce), std::begin(wrapped));
    out = std::move(std::begin(ct), std::end(ct), out);
    std::move(std::begin(sig), std::end(sig), out);
    return std::move(wrapped);
}

o1c::buffer o1c::unsigncrypt(const o1c::buffer &sender_id, const o1c::buffer &recipient_id, const o1c::buffer &info,
                             const o1c::public_key &sender_key, const o1c::secret_key &recipient_key,
                             const o1c::buffer &ciphertext) {
    auto st = state_t();
    auto key = shared_key();
    auto nonce = nonce_t();
    auto sig = sig_t();
    auto clen = ciphertext.size() - nonce.size() - sig.size();
    auto pt = buffer(clen - std::tuple_size<mac_t>::value);
    auto n = std::cbegin(ciphertext);
    auto ct = buffer(n, n + nonce.size());
    auto c = n + nonce.size();
    auto s = c + clen;
    auto end = s + sig.size();
    std::copy(n, c, std::begin(nonce));
    std::copy(s, end, std::begin(sig));
    if (crypto_signcrypt_tbsbr_verify_before(st.data(), key.data(), sig.data(), sender_id.data(), sender_id.size(),
                                             recipient_id.data(), recipient_id.size(), info.data(), info.size(),
                                             sender_key.data(), recipient_key.data()) != 0 ||
        crypto_aead_xchacha20poly1305_ietf_decrypt(pt.data(), nullptr, nullptr, ct.data(), ct.size(), info.data(),
                                                   info.size(), nonce.data(), key.data()) != 0 ||
        crypto_signcrypt_tbsbr_verify_after(st.data(), sig.data(), sender_key.data(), ct.data(), ct.size()) != 0) {
        throw std::exception();
    }
    return std::move(pt);
}

o1c::secret_key o1c::parse_secret_key(const std::string &hex) {
    auto sk = secret_key();
    if (sodium_hex2bin(sk.data(), sk.size(), hex.data(), hex.size(), nullptr, nullptr, nullptr) != 0) {
        throw std::invalid_argument(hex);
    }
    return sk;
}

o1c::public_key o1c::gen_public_key(const o1c::secret_key &key) {
    auto pk = public_key();
    if (crypto_scalarmult_ristretto255_base(pk.data(), key.data()) != 0) {
        throw std::invalid_argument("provided the identity key");
    }
    return pk;
}

o1c::public_key o1c::parse_public_key(const std::string &hex) {
    auto pk = public_key();
    if (sodium_hex2bin(pk.data(), pk.size(), hex.data(), hex.size(), nullptr, nullptr, nullptr) != 0) {
        throw std::invalid_argument(hex);
    }
    if (crypto_core_ristretto255_is_valid_point(pk.data()) != 1) {
        throw std::invalid_argument("invalid ristretto255 point");
    }
    return pk;
}
