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

#include "secure_buffer.h"
#include <sodium.h>
#include <memory>

secure_buffer::secure_buffer() noexcept: len(0), buf(nullptr) {
}

secure_buffer::secure_buffer(const size_t len) noexcept: len(len) {
    buf = static_cast<unsigned char *>(sodium_malloc(len));
}

secure_buffer::secure_buffer(const std::string &string) noexcept: len(string.size()) {
    buf = static_cast<unsigned char *>(sodium_malloc(len));
    std::copy(string.begin(), string.end(), buf);
}

secure_buffer::secure_buffer(const secure_buffer &that) noexcept: len(that.len) {
    buf = static_cast<unsigned char *>(sodium_malloc(len));
    std::memcpy(buf, that.buf, len);
}

secure_buffer::secure_buffer(secure_buffer &&that) noexcept {
    len = that.len;
    buf = that.buf;
    that.len = 0;
    that.buf = nullptr;
}

secure_buffer::~secure_buffer() noexcept {
    if (buf) {
        sodium_free(buf);
        buf = nullptr;
        len = 0;
    }
}

secure_buffer &secure_buffer::operator=(secure_buffer that) noexcept {
    std::swap(len, that.len);
    std::swap(buf, that.buf);
    return *this;
}

secure_buffer secure_buffer::from_hex(const std::string &hex) {
    if ((hex.size() & 1) == 1) {
        throw std::invalid_argument(hex);
    }
    auto buf = secure_buffer(hex.size() >> 1);
    if (sodium_hex2bin(buf.data(), buf.size(), hex.data(), hex.size(), nullptr, nullptr, nullptr) != 0) {
        throw std::invalid_argument(hex);
    }
    return std::move(buf);
}

std::ostream &operator<<(std::ostream &os, const secure_buffer &buffer) {
    std::ostreambuf_iterator<char> out(os);
    std::copy(buffer.buf, buffer.buf + buffer.len, out);
    return os;
}

void secure_buffer::randomize() noexcept {
    randombytes_buf(buf, len);
}
