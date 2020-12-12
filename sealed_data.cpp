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

#include <utility>
#include <sodium.h>
#include <signcrypt_tbsbr.h>
#include "key_pair.h"
#include "sealed_data.h"

std::ostream &operator<<(std::ostream &os, const sealed_data &data) {
    os << data.nonce << data.ct << data.mac << data.sig;
    return os;
}

sealed_data sealed_data::unpack(const secure_buffer &buffer) {
    // TODO: validate length
    secure_buffer nonce(crypto_secretbox_xchacha20poly1305_NONCEBYTES);
    secure_buffer mac(crypto_secretbox_xchacha20poly1305_MACBYTES);
    secure_buffer sig(crypto_signcrypt_tbsbr_SIGNBYTES);
    secure_buffer ct(buffer.size() - nonce.size() - mac.size() - sig.size());
    auto n = buffer.data();
    auto c = n + nonce.size();
    auto m = c + ct.size();
    auto s = m + mac.size();
    auto end = s + sig.size();
    std::copy(n, c, nonce.data());
    std::copy(c, m, ct.data());
    std::copy(m, s, mac.data());
    std::copy(s, end, sig.data());
    return std::move(sealed_data(nonce, mac, sig, ct));
}

sealed_data
sealed_data::seal(const secure_buffer &sender_id, const secure_buffer &recipient_id, const secure_buffer &info,
                  const secure_buffer &sender_sk, const secure_buffer &recipient_pk, const secure_buffer &msg) {
    secure_buffer st(crypto_signcrypt_tbsbr_STATEBYTES);
    secure_buffer key(crypto_secretbox_xchacha20poly1305_KEYBYTES);
    secure_buffer nonce(crypto_secretbox_xchacha20poly1305_NONCEBYTES);
    nonce.randomize();
    secure_buffer mac(crypto_secretbox_xchacha20poly1305_MACBYTES);
    secure_buffer sig(crypto_signcrypt_tbsbr_SIGNBYTES);
    secure_buffer ct(msg.size());
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

secure_buffer
sealed_data::unseal(const secure_buffer &sender_id, const secure_buffer &recipient_id, const secure_buffer &info,
                    const secure_buffer &sender_pk, const secure_buffer &recipient_sk) const {
    secure_buffer st(crypto_signcrypt_tbsbr_STATEBYTES);
    secure_buffer key(crypto_secretbox_xchacha20poly1305_KEYBYTES);
    secure_buffer msg(ct.size());
    if (crypto_signcrypt_tbsbr_verify_before(st.data(), key.data(), sig.data(), sender_id.data(), sender_id.size(),
                                             recipient_id.data(), recipient_id.size(), info.data(), info.size(),
                                             sender_pk.data(), recipient_sk.data()) != 0 ||
        crypto_aead_xchacha20poly1305_ietf_decrypt_detached(msg.data(), nullptr, ct.data(), ct.size(),
                                                            mac.data(), info.data(), info.size(),
                                                            nonce.data(), key.data()) != 0 ||
        crypto_signcrypt_tbsbr_verify_after(st.data(), sig.data(), sender_pk.data(), ct.data(),
                                            ct.size()) != 0) {
        throw sealed_data_exception();
    }
    return std::move(msg);
}
