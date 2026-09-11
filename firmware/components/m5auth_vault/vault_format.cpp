#include "m5auth/vault.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <set>

namespace m5auth::vault {
namespace {

constexpr std::size_t kMaxFieldBytes = 1024;
constexpr std::size_t kMaxSecretBytes = 512;
constexpr char kPlaintextMagic[] = "M5AUTH-VLT-PT1";
constexpr char kVaultAadMagic[] = "M5AUTH-VLT-AAD1";
constexpr char kVmkWrapAadMagic[] = "M5AUTH-VMK-WRAP1";

void secure_zero_memory(void* data, std::size_t size) {
    volatile auto* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) {
        *cursor++ = 0;
    }
}

void wipe_bytes(std::vector<std::uint8_t>* value) {
    if (value == nullptr) return;
    if (!value->empty()) secure_zero_memory(value->data(), value->size());
    value->clear();
}

void wipe_string(std::string* value) {
    if (value == nullptr) return;
    if (!value->empty()) secure_zero_memory(value->data(), value->size());
    value->clear();
}

void wipe_plaintext_candidate(VaultPlaintext* value) {
    if (value == nullptr) return;
    for (auto& credential : value->credentials) {
        credential.credential_id.fill(0);
        wipe_bytes(&credential.secret);
        wipe_string(&credential.issuer);
        wipe_string(&credential.account);
        wipe_string(&credential.display_name);
        credential.digits = 0;
        credential.period_seconds = 0;
        credential.manual_order = 0;
    }
    value->credentials.clear();
    if (value->wifi.has_value()) {
        wipe_string(&value->wifi->ssid);
        wipe_string(&value->wifi->password);
        value->wifi.reset();
    }
}

class ByteVectorWipeGuard final {
public:
    explicit ByteVectorWipeGuard(std::vector<std::uint8_t>& value) : value_(value) {}
    ~ByteVectorWipeGuard() { wipe_bytes(&value_); }

private:
    std::vector<std::uint8_t>& value_;
};

class PlaintextWipeGuard final {
public:
    explicit PlaintextWipeGuard(VaultPlaintext& value) : value_(value) {}
    ~PlaintextWipeGuard() { wipe_plaintext_candidate(&value_); }

private:
    VaultPlaintext& value_;
};

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    output.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
    }
}

bool is_continuation(std::uint8_t byte) {
    return (byte & 0xc0) == 0x80;
}

bool is_valid_utf8(const std::string& text) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(text.data());
    std::size_t index = 0;
    while (index < text.size()) {
        const std::uint8_t first = bytes[index++];
        if (first <= 0x7f) continue;

        if (first >= 0xc2 && first <= 0xdf) {
            if (index >= text.size() || !is_continuation(bytes[index])) return false;
            ++index;
            continue;
        }

        if (first >= 0xe0 && first <= 0xef) {
            if (index + 1 >= text.size()) return false;
            const std::uint8_t second = bytes[index];
            const std::uint8_t third = bytes[index + 1];
            if (!is_continuation(third)) return false;
            if (first == 0xe0) {
                if (second < 0xa0 || second > 0xbf) return false;
            } else if (first == 0xed) {
                if (second < 0x80 || second > 0x9f) return false;
            } else if (!is_continuation(second)) {
                return false;
            }
            index += 2;
            continue;
        }

        if (first >= 0xf0 && first <= 0xf4) {
            if (index + 2 >= text.size()) return false;
            const std::uint8_t second = bytes[index];
            const std::uint8_t third = bytes[index + 1];
            const std::uint8_t fourth = bytes[index + 2];
            if (!is_continuation(third) || !is_continuation(fourth)) return false;
            if (first == 0xf0) {
                if (second < 0x90 || second > 0xbf) return false;
            } else if (first == 0xf4) {
                if (second < 0x80 || second > 0x8f) return false;
            } else if (!is_continuation(second)) {
                return false;
            }
            index += 3;
            continue;
        }

        return false;
    }
    return true;
}

bool append_sized_bytes(
    std::vector<std::uint8_t>& output,
    const std::vector<std::uint8_t>& value,
    std::size_t maximum
) {
    if (value.size() > maximum ||
        value.size() > std::numeric_limits<std::uint16_t>::max()) {
        return false;
    }
    append_u16(output, static_cast<std::uint16_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
    return true;
}

bool append_sized_text(std::vector<std::uint8_t>& output, const std::string& value) {
    if (!is_valid_utf8(value) ||
        value.size() > kMaxFieldBytes ||
        value.size() > std::numeric_limits<std::uint16_t>::max()) {
        return false;
    }
    append_u16(output, static_cast<std::uint16_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
    return true;
}

class Reader {
public:
    explicit Reader(const std::vector<std::uint8_t>& input) : input_(input) {}

    bool read_bytes(std::size_t length, std::uint8_t* output) {
        if (length > input_.size() - offset_) return false;
        if (length != 0) {
            std::copy_n(input_.data() + offset_, length, output);
        }
        offset_ += length;
        return true;
    }

    bool read_u8(std::uint8_t& value) {
        return read_bytes(1, &value);
    }

    bool read_u16(std::uint16_t& value) {
        std::array<std::uint8_t, 2> encoded{};
        if (!read_bytes(encoded.size(), encoded.data())) return false;
        value = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(encoded[0]) << 8) | encoded[1]
        );
        return true;
    }

    bool read_sized_bytes(std::vector<std::uint8_t>& value, std::size_t maximum) {
        std::uint16_t length = 0;
        if (!read_u16(length) || length > maximum || length > input_.size() - offset_) {
            return false;
        }
        value.assign(input_.begin() + static_cast<std::ptrdiff_t>(offset_),
                     input_.begin() + static_cast<std::ptrdiff_t>(offset_ + length));
        offset_ += length;
        return true;
    }

    bool read_sized_text(std::string& value) {
        std::uint16_t length = 0;
        if (!read_u16(length) || length > kMaxFieldBytes ||
            length > input_.size() - offset_) {
            return false;
        }
        if (length == 0) {
            wipe_string(&value);
            return true;
        }
        value.assign(
            reinterpret_cast<const char*>(input_.data() + offset_),
            static_cast<std::size_t>(length)
        );
        offset_ += length;
        if (!is_valid_utf8(value)) {
            wipe_string(&value);
            return false;
        }
        return true;
    }

    bool at_end() const {
        return offset_ == input_.size();
    }

private:
    const std::vector<std::uint8_t>& input_;
    std::size_t offset_ = 0;
};

bool valid_credential(const CredentialRecord& record) {
    return !record.secret.empty() &&
           record.secret.size() <= kMaxSecretBytes &&
           record.algorithm == TotpAlgorithm::kSha1 &&
           record.digits >= 1 &&
           record.digits <= 10 &&
           record.period_seconds >= 1;
}

}  // namespace

bool encode_plaintext(const VaultPlaintext& value, std::vector<std::uint8_t>& encoded) {
    if (value.credentials.size() > kMaxCredentials) return false;

    std::vector<std::uint8_t> candidate;
    ByteVectorWipeGuard candidate_wipe(candidate);
    candidate.insert(
        candidate.end(),
        reinterpret_cast<const std::uint8_t*>(kPlaintextMagic),
        reinterpret_cast<const std::uint8_t*>(kPlaintextMagic) + sizeof(kPlaintextMagic)
    );
    append_u16(candidate, kVaultFormatVersion);
    append_u16(candidate, static_cast<std::uint16_t>(value.credentials.size()));

    std::set<std::array<std::uint8_t, kCredentialIdBytes>> ids;
    for (const auto& record : value.credentials) {
        if (!valid_credential(record) || !ids.insert(record.credential_id).second) {
            return false;
        }

        candidate.insert(
            candidate.end(),
            record.credential_id.begin(),
            record.credential_id.end()
        );
        if (!append_sized_bytes(candidate, record.secret, kMaxSecretBytes) ||
            !append_sized_text(candidate, record.issuer) ||
            !append_sized_text(candidate, record.account) ||
            !append_sized_text(candidate, record.display_name)) {
            return false;
        }
        candidate.push_back(static_cast<std::uint8_t>(record.algorithm));
        candidate.push_back(record.digits);
        append_u16(candidate, record.period_seconds);
        append_u16(candidate, record.manual_order);
    }

    candidate.push_back(value.wifi.has_value() ? 1 : 0);
    if (value.wifi.has_value() &&
        (!append_sized_text(candidate, value.wifi->ssid) ||
         !append_sized_text(candidate, value.wifi->password))) {
        return false;
    }

    encoded.swap(candidate);
    return true;
}

bool decode_plaintext(const std::vector<std::uint8_t>& encoded, VaultPlaintext& value) {
    Reader reader(encoded);
    std::array<std::uint8_t, sizeof(kPlaintextMagic)> magic{};
    if (!reader.read_bytes(magic.size(), magic.data()) ||
        !std::equal(
            magic.begin(),
            magic.end(),
            reinterpret_cast<const std::uint8_t*>(kPlaintextMagic)
        )) {
        return false;
    }

    std::uint16_t version = 0;
    std::uint16_t count = 0;
    if (!reader.read_u16(version) || version != kVaultFormatVersion ||
        !reader.read_u16(count) || count > kMaxCredentials) {
        return false;
    }

    VaultPlaintext candidate;
    PlaintextWipeGuard candidate_wipe(candidate);
    candidate.credentials.reserve(count);
    std::set<std::array<std::uint8_t, kCredentialIdBytes>> ids;
    for (std::uint16_t index = 0; index < count; ++index) {
        candidate.credentials.emplace_back();
        auto& record = candidate.credentials.back();
        if (!reader.read_bytes(record.credential_id.size(), record.credential_id.data()) ||
            !ids.insert(record.credential_id).second ||
            !reader.read_sized_bytes(record.secret, kMaxSecretBytes) ||
            record.secret.empty() ||
            !reader.read_sized_text(record.issuer) ||
            !reader.read_sized_text(record.account) ||
            !reader.read_sized_text(record.display_name)) {
            return false;
        }

        std::uint8_t algorithm = 0;
        if (!reader.read_u8(algorithm) ||
            algorithm != static_cast<std::uint8_t>(TotpAlgorithm::kSha1) ||
            !reader.read_u8(record.digits) ||
            !reader.read_u16(record.period_seconds) ||
            !reader.read_u16(record.manual_order)) {
            return false;
        }
        record.algorithm = TotpAlgorithm::kSha1;
        if (!valid_credential(record)) return false;
    }

    std::uint8_t wifi_present = 0;
    if (!reader.read_u8(wifi_present) || wifi_present > 1) return false;
    if (wifi_present == 1) {
        candidate.wifi.emplace();
        if (!reader.read_sized_text(candidate.wifi->ssid) ||
            !reader.read_sized_text(candidate.wifi->password)) {
            return false;
        }
    }

    if (!reader.at_end()) return false;
    wipe_plaintext_candidate(&value);
    value = std::move(candidate);
    return true;
}

bool build_vault_aad(
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    std::vector<std::uint8_t>& aad,
    std::uint16_t vault_format_version,
    std::uint16_t storage_schema_version
) {
    if (vault_format_version != kVaultFormatVersion ||
        storage_schema_version != kTargetStorageSchemaVersion) {
        return false;
    }

    std::vector<std::uint8_t> candidate;
    candidate.insert(
        candidate.end(),
        reinterpret_cast<const std::uint8_t*>(kVaultAadMagic),
        reinterpret_cast<const std::uint8_t*>(kVaultAadMagic) + sizeof(kVaultAadMagic)
    );
    append_u16(candidate, vault_format_version);
    append_u16(candidate, storage_schema_version);
    candidate.insert(candidate.end(), vault_id.begin(), vault_id.end());
    append_u64(candidate, generation);

    aad.swap(candidate);
    return true;
}

bool build_vmk_wrap_aad(
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::vector<std::uint8_t>& aad,
    std::uint16_t package_version,
    std::uint16_t wrap_version
) {
    if (package_version != kRecoveryPackageVersion || wrap_version != kVmkWrapVersion) {
        return false;
    }

    std::vector<std::uint8_t> candidate;
    candidate.insert(
        candidate.end(),
        reinterpret_cast<const std::uint8_t*>(kVmkWrapAadMagic),
        reinterpret_cast<const std::uint8_t*>(kVmkWrapAadMagic) + sizeof(kVmkWrapAadMagic)
    );
    append_u16(candidate, package_version);
    append_u16(candidate, wrap_version);
    candidate.insert(candidate.end(), vault_id.begin(), vault_id.end());

    aad.swap(candidate);
    return true;
}

}  // namespace m5auth::vault
