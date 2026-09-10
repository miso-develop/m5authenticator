#include "state.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <unordered_set>
#include <utility>

namespace m5auth::storage::internal {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'M', '5', 'A', 'S'};
constexpr std::uint16_t kFormatVersion = 1;
constexpr std::size_t kMaxSnapshotBytes = 64 * 1024;

void append_u16(std::vector<std::uint8_t>* out, std::uint16_t value) {
    out->push_back(static_cast<std::uint8_t>(value & 0xffU));
    out->push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void append_u32(std::vector<std::uint8_t>* out, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out->push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

bool append_string(std::vector<std::uint8_t>* out, const std::string& value) {
    if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
        return false;
    }
    append_u16(out, static_cast<std::uint16_t>(value.size()));
    out->insert(out->end(), value.begin(), value.end());
    return true;
}

class Reader {
public:
    Reader(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}

    bool read_u16(std::uint16_t* value) {
        if (!can_read(2)) {
            return false;
        }
        *value = static_cast<std::uint16_t>(data_[offset_]) |
                 (static_cast<std::uint16_t>(data_[offset_ + 1]) << 8U);
        offset_ += 2;
        return true;
    }

    bool read_u32(std::uint32_t* value) {
        if (!can_read(4)) {
            return false;
        }
        *value = static_cast<std::uint32_t>(data_[offset_]) |
                 (static_cast<std::uint32_t>(data_[offset_ + 1]) << 8U) |
                 (static_cast<std::uint32_t>(data_[offset_ + 2]) << 16U) |
                 (static_cast<std::uint32_t>(data_[offset_ + 3]) << 24U);
        offset_ += 4;
        return true;
    }

    bool read_exact(std::uint8_t* output, std::size_t length) {
        if (!can_read(length)) {
            return false;
        }
        std::copy_n(data_ + offset_, length, output);
        offset_ += length;
        return true;
    }

    bool read_string(std::size_t max_length, std::string* output) {
        std::uint16_t length = 0;
        if (!read_u16(&length) || length > max_length || !can_read(length)) {
            return false;
        }
        output->assign(
            reinterpret_cast<const char*>(data_ + offset_),
            static_cast<std::size_t>(length)
        );
        offset_ += length;
        return true;
    }

    bool finished() const { return offset_ == size_; }

private:
    bool can_read(std::size_t length) const {
        return offset_ <= size_ && length <= size_ - offset_;
    }

    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t offset_{0};
};

}  // namespace

void secure_zero(void* data, std::size_t size) {
    volatile std::uint8_t* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) {
        *cursor++ = 0;
    }
}

void secure_clear(std::string* value) {
    if (value == nullptr) {
        return;
    }
    if (!value->empty()) {
        secure_zero(value->data(), value->size());
    }
    value->clear();
}

void secure_clear_bytes(std::vector<std::uint8_t>* bytes) {
    if (bytes == nullptr) {
        return;
    }
    if (!bytes->empty()) {
        secure_zero(bytes->data(), bytes->size());
    }
    bytes->clear();
}

AccountRecord::AccountRecord(AccountRecord&& other) noexcept
    : id(other.id),
      order(other.order),
      issuer(std::move(other.issuer)),
      account(std::move(other.account)),
      display_name(std::move(other.display_name)),
      secret(other.secret) {
    secure_clear(&other.secret);
}

AccountRecord& AccountRecord::operator=(AccountRecord&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    secure_clear(&secret);
    id = other.id;
    order = other.order;
    issuer = std::move(other.issuer);
    account = std::move(other.account);
    display_name = std::move(other.display_name);
    secret = other.secret;
    secure_clear(&other.secret);
    return *this;
}

AccountRecord::~AccountRecord() {
    secure_clear(&secret);
}

void wipe_state(State* state) {
    if (state == nullptr) {
        return;
    }
    secure_clear(&state->wifi_password);
    for (auto& account : state->accounts) {
        secure_clear(&account.secret);
    }
    state->accounts.clear();
}

Status validate_account_draft(const AccountDraft& draft) {
    if (draft.issuer.size() > kMaxIssuerBytes ||
        draft.account.size() > kMaxAccountBytes ||
        draft.display_name.size() > kMaxDisplayNameBytes ||
        draft.secret.empty() || draft.secret.size() > kMaxSecretBytes) {
        return Status::kInvalidArgument;
    }
    return Status::kOk;
}

Status validate_state(const State& state) {
    if (state.accounts.size() > kMaxAccounts ||
        state.wifi_ssid.size() > kMaxSsidBytes ||
        state.wifi_password.size() > kMaxWifiPasswordBytes ||
        state.next_id == 0) {
        return Status::kCorrupt;
    }

    std::unordered_set<std::uint32_t> ids;
    std::vector<bool> orders(state.accounts.size(), false);
    std::uint32_t max_id = 0;
    bool last_used_found = state.last_used_id == 0;

    for (const auto& account : state.accounts) {
        if (account.issuer.size() > kMaxIssuerBytes ||
            account.account.size() > kMaxAccountBytes ||
            account.display_name.size() > kMaxDisplayNameBytes ||
            account.secret.empty() || account.secret.size() > kMaxSecretBytes ||
            account.id == 0 || !ids.insert(account.id).second ||
            account.order >= state.accounts.size() || orders[account.order]) {
            return Status::kCorrupt;
        }
        orders[account.order] = true;
        max_id = std::max(max_id, account.id);
        if (account.id == state.last_used_id) {
            last_used_found = true;
        }
    }

    if (!last_used_found || state.next_id <= max_id) {
        return Status::kCorrupt;
    }
    return Status::kOk;
}

Status encode_state(const State& state, std::vector<std::uint8_t>* output) {
    if (output == nullptr || validate_state(state) != Status::kOk) {
        return Status::kInvalidArgument;
    }

    output->clear();
    output->reserve(512);
    output->insert(output->end(), kMagic.begin(), kMagic.end());
    append_u16(output, kFormatVersion);
    append_u16(output, 0);
    append_u32(output, state.next_id);
    append_u32(output, state.last_used_id);
    append_u16(output, static_cast<std::uint16_t>(state.accounts.size()));

    if (!append_string(output, state.wifi_ssid) ||
        !append_string(output, state.wifi_password)) {
        secure_clear_bytes(output);
        return Status::kInvalidArgument;
    }

    for (const auto& account : state.accounts) {
        append_u32(output, account.id);
        append_u16(output, account.order);
        if (!append_string(output, account.issuer) ||
            !append_string(output, account.account) ||
            !append_string(output, account.display_name) ||
            !append_string(output, account.secret)) {
            secure_clear_bytes(output);
            return Status::kInvalidArgument;
        }
    }

    if (output->size() > kMaxSnapshotBytes) {
        secure_clear_bytes(output);
        return Status::kFull;
    }
    return Status::kOk;
}

Status decode_state(const std::uint8_t* data, std::size_t size, State* output) {
    if (data == nullptr || output == nullptr || size == 0 || size > kMaxSnapshotBytes) {
        return Status::kCorrupt;
    }

    State decoded;
    Reader reader(data, size);
    std::array<std::uint8_t, 4> magic{};
    std::uint16_t format = 0;
    std::uint16_t reserved = 0;
    std::uint16_t account_count = 0;

    if (!reader.read_exact(magic.data(), magic.size()) || magic != kMagic ||
        !reader.read_u16(&format) || format != kFormatVersion ||
        !reader.read_u16(&reserved) || reserved != 0 ||
        !reader.read_u32(&decoded.next_id) ||
        !reader.read_u32(&decoded.last_used_id) ||
        !reader.read_u16(&account_count) || account_count > kMaxAccounts ||
        !reader.read_string(kMaxSsidBytes, &decoded.wifi_ssid) ||
        !reader.read_string(kMaxWifiPasswordBytes, &decoded.wifi_password)) {
        wipe_state(&decoded);
        return Status::kCorrupt;
    }

    decoded.accounts.reserve(account_count);
    for (std::uint16_t index = 0; index < account_count; ++index) {
        AccountRecord record;
        if (!reader.read_u32(&record.id) || !reader.read_u16(&record.order) ||
            !reader.read_string(kMaxIssuerBytes, &record.issuer) ||
            !reader.read_string(kMaxAccountBytes, &record.account) ||
            !reader.read_string(kMaxDisplayNameBytes, &record.display_name) ||
            !reader.read_string(kMaxSecretBytes, &record.secret)) {
            secure_clear(&record.secret);
            wipe_state(&decoded);
            return Status::kCorrupt;
        }
        decoded.accounts.push_back(record);
        secure_clear(&record.secret);
    }

    if (!reader.finished() || validate_state(decoded) != Status::kOk) {
        wipe_state(&decoded);
        return Status::kCorrupt;
    }

    wipe_state(output);
    *output = decoded;
    wipe_state(&decoded);
    return Status::kOk;
}

}  // namespace m5auth::storage::internal

namespace m5auth::storage {

AccountDraft::AccountDraft(AccountDraft&& other) noexcept
    : issuer(std::move(other.issuer)),
      account(std::move(other.account)),
      display_name(std::move(other.display_name)),
      secret(other.secret) {
    internal::secure_clear(&other.secret);
}

AccountDraft& AccountDraft::operator=(AccountDraft&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    internal::secure_clear(&secret);
    issuer = std::move(other.issuer);
    account = std::move(other.account);
    display_name = std::move(other.display_name);
    secret = other.secret;
    internal::secure_clear(&other.secret);
    return *this;
}

AccountDraft::~AccountDraft() {
    internal::secure_clear(&secret);
}

Status validate_account_draft(const AccountDraft& draft) {
    return internal::validate_account_draft(draft);
}

void secure_zero(void* data, std::size_t size) {
    internal::secure_zero(data, size);
}

void secure_clear(std::string* value) {
    internal::secure_clear(value);
}

}  // namespace m5auth::storage
