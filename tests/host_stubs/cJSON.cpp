#include "cJSON.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

constexpr int kFalse = 1;
constexpr int kTrue = 2;
constexpr int kNull = 4;
constexpr int kNumber = 8;
constexpr int kString = 16;
constexpr int kArray = 32;
constexpr int kObject = 64;

char* duplicate(const std::string& value) {
    char* result = static_cast<char*>(std::malloc(value.size() + 1));
    if (result == nullptr) return nullptr;
    std::memcpy(result, value.c_str(), value.size() + 1);
    return result;
}

cJSON* make_node(int type) {
    cJSON* item = static_cast<cJSON*>(std::calloc(1, sizeof(cJSON)));
    if (item != nullptr) item->type = type;
    return item;
}

void append_child(cJSON* parent, cJSON* child) {
    if (parent == nullptr || child == nullptr) return;
    if (parent->child == nullptr) {
        parent->child = child;
        return;
    }
    cJSON* tail = parent->child;
    while (tail->next != nullptr) tail = tail->next;
    tail->next = child;
    child->prev = tail;
}

cJSON* add_named(cJSON* object, const char* name, cJSON* item) {
    if (object == nullptr || item == nullptr || name == nullptr || object->type != kObject) {
        cJSON_Delete(item);
        return nullptr;
    }
    item->string = duplicate(name);
    if (item->string == nullptr) {
        cJSON_Delete(item);
        return nullptr;
    }
    append_child(object, item);
    return item;
}

class Parser {
public:
    Parser(const char* begin, std::size_t size) : cursor_(begin), end_(begin + size) {}

    cJSON* parse() {
        skip_ws();
        cJSON* result = parse_value();
        skip_ws();
        if (result == nullptr || cursor_ != end_) {
            cJSON_Delete(result);
            return nullptr;
        }
        return result;
    }

private:
    void skip_ws() {
        while (cursor_ < end_ && std::isspace(static_cast<unsigned char>(*cursor_))) ++cursor_;
    }

    bool consume(char expected) {
        skip_ws();
        if (cursor_ >= end_ || *cursor_ != expected) return false;
        ++cursor_;
        return true;
    }

    bool parse_string_value(std::string* output) {
        if (output == nullptr || !consume('"')) return false;
        output->clear();
        while (cursor_ < end_) {
            const char ch = *cursor_++;
            if (ch == '"') return true;
            if (static_cast<unsigned char>(ch) < 0x20) return false;
            if (ch != '\\') {
                output->push_back(ch);
                continue;
            }
            if (cursor_ >= end_) return false;
            const char escaped = *cursor_++;
            switch (escaped) {
                case '"': output->push_back('"'); break;
                case '\\': output->push_back('\\'); break;
                case '/': output->push_back('/'); break;
                case 'b': output->push_back('\b'); break;
                case 'f': output->push_back('\f'); break;
                case 'n': output->push_back('\n'); break;
                case 'r': output->push_back('\r'); break;
                case 't': output->push_back('\t'); break;
                case 'u': {
                    if (end_ - cursor_ < 4) return false;
                    unsigned value = 0;
                    for (int index = 0; index < 4; ++index) {
                        const char hex = *cursor_++;
                        value <<= 4;
                        if (hex >= '0' && hex <= '9') value |= static_cast<unsigned>(hex - '0');
                        else if (hex >= 'a' && hex <= 'f') value |= static_cast<unsigned>(hex - 'a' + 10);
                        else if (hex >= 'A' && hex <= 'F') value |= static_cast<unsigned>(hex - 'A' + 10);
                        else return false;
                    }
                    output->push_back(value <= 0x7f ? static_cast<char>(value) : '?');
                    break;
                }
                default: return false;
            }
        }
        return false;
    }

    bool match_literal(const char* literal) {
        const std::size_t length = std::strlen(literal);
        if (static_cast<std::size_t>(end_ - cursor_) < length ||
            std::memcmp(cursor_, literal, length) != 0) {
            return false;
        }
        cursor_ += length;
        return true;
    }

    cJSON* parse_object() {
        if (!consume('{')) return nullptr;
        cJSON* object = make_node(kObject);
        if (object == nullptr) return nullptr;
        skip_ws();
        if (cursor_ < end_ && *cursor_ == '}') {
            ++cursor_;
            return object;
        }
        for (;;) {
            std::string key;
            if (!parse_string_value(&key) || !consume(':')) {
                cJSON_Delete(object);
                return nullptr;
            }
            cJSON* value = parse_value();
            if (value == nullptr) {
                cJSON_Delete(object);
                return nullptr;
            }
            value->string = duplicate(key);
            if (value->string == nullptr) {
                cJSON_Delete(value);
                cJSON_Delete(object);
                return nullptr;
            }
            append_child(object, value);
            skip_ws();
            if (cursor_ < end_ && *cursor_ == '}') {
                ++cursor_;
                return object;
            }
            if (!consume(',')) {
                cJSON_Delete(object);
                return nullptr;
            }
        }
    }

    cJSON* parse_array() {
        if (!consume('[')) return nullptr;
        cJSON* array = make_node(kArray);
        if (array == nullptr) return nullptr;
        skip_ws();
        if (cursor_ < end_ && *cursor_ == ']') {
            ++cursor_;
            return array;
        }
        for (;;) {
            cJSON* value = parse_value();
            if (value == nullptr) {
                cJSON_Delete(array);
                return nullptr;
            }
            append_child(array, value);
            skip_ws();
            if (cursor_ < end_ && *cursor_ == ']') {
                ++cursor_;
                return array;
            }
            if (!consume(',')) {
                cJSON_Delete(array);
                return nullptr;
            }
        }
    }

    cJSON* parse_number() {
        skip_ws();
        const char* start = cursor_;
        if (cursor_ < end_ && *cursor_ == '-') ++cursor_;
        if (cursor_ >= end_ || !std::isdigit(static_cast<unsigned char>(*cursor_))) return nullptr;
        if (*cursor_ == '0') ++cursor_;
        else while (cursor_ < end_ && std::isdigit(static_cast<unsigned char>(*cursor_))) ++cursor_;
        if (cursor_ < end_ && *cursor_ == '.') {
            ++cursor_;
            if (cursor_ >= end_ || !std::isdigit(static_cast<unsigned char>(*cursor_))) return nullptr;
            while (cursor_ < end_ && std::isdigit(static_cast<unsigned char>(*cursor_))) ++cursor_;
        }
        if (cursor_ < end_ && (*cursor_ == 'e' || *cursor_ == 'E')) {
            ++cursor_;
            if (cursor_ < end_ && (*cursor_ == '+' || *cursor_ == '-')) ++cursor_;
            if (cursor_ >= end_ || !std::isdigit(static_cast<unsigned char>(*cursor_))) return nullptr;
            while (cursor_ < end_ && std::isdigit(static_cast<unsigned char>(*cursor_))) ++cursor_;
        }
        const std::string text(start, cursor_);
        char* parsed_end = nullptr;
        const double number = std::strtod(text.c_str(), &parsed_end);
        if (parsed_end == nullptr || *parsed_end != '\0' || !std::isfinite(number)) return nullptr;
        cJSON* item = make_node(kNumber);
        if (item == nullptr) return nullptr;
        item->valuedouble = number;
        item->valueint = static_cast<int>(number);
        return item;
    }

    cJSON* parse_value() {
        skip_ws();
        if (cursor_ >= end_) return nullptr;
        if (*cursor_ == '{') return parse_object();
        if (*cursor_ == '[') return parse_array();
        if (*cursor_ == '"') {
            std::string value;
            if (!parse_string_value(&value)) return nullptr;
            cJSON* item = make_node(kString);
            if (item == nullptr) return nullptr;
            item->valuestring = duplicate(value);
            if (item->valuestring == nullptr) {
                cJSON_Delete(item);
                return nullptr;
            }
            return item;
        }
        if (*cursor_ == '-' || std::isdigit(static_cast<unsigned char>(*cursor_))) return parse_number();
        if (match_literal("true")) return make_node(kTrue);
        if (match_literal("false")) return make_node(kFalse);
        if (match_literal("null")) return make_node(kNull);
        return nullptr;
    }

    const char* cursor_;
    const char* end_;
};

void append_escaped(std::string* output, const char* value) {
    output->push_back('"');
    if (value != nullptr) {
        for (const unsigned char ch : std::string(value)) {
            switch (ch) {
                case '"': output->append("\\\""); break;
                case '\\': output->append("\\\\"); break;
                case '\b': output->append("\\b"); break;
                case '\f': output->append("\\f"); break;
                case '\n': output->append("\\n"); break;
                case '\r': output->append("\\r"); break;
                case '\t': output->append("\\t"); break;
                default:
                    if (ch < 0x20) {
                        char buffer[7]{};
                        std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch);
                        output->append(buffer);
                    } else {
                        output->push_back(static_cast<char>(ch));
                    }
            }
        }
    }
    output->push_back('"');
}

bool serialize_node(const cJSON* item, std::string* output) {
    if (item == nullptr || output == nullptr) return false;
    switch (item->type) {
        case kFalse: output->append("false"); return true;
        case kTrue: output->append("true"); return true;
        case kNull: output->append("null"); return true;
        case kNumber: {
            char buffer[64]{};
            const int count = std::snprintf(buffer, sizeof(buffer), "%.17g", item->valuedouble);
            if (count <= 0 || static_cast<std::size_t>(count) >= sizeof(buffer)) return false;
            output->append(buffer, static_cast<std::size_t>(count));
            return true;
        }
        case kString:
            append_escaped(output, item->valuestring);
            return true;
        case kArray: {
            output->push_back('[');
            bool first = true;
            for (const cJSON* child = item->child; child != nullptr; child = child->next) {
                if (!first) output->push_back(',');
                first = false;
                if (!serialize_node(child, output)) return false;
            }
            output->push_back(']');
            return true;
        }
        case kObject: {
            output->push_back('{');
            bool first = true;
            for (const cJSON* child = item->child; child != nullptr; child = child->next) {
                if (!first) output->push_back(',');
                first = false;
                append_escaped(output, child->string);
                output->push_back(':');
                if (!serialize_node(child, output)) return false;
            }
            output->push_back('}');
            return true;
        }
        default:
            return false;
    }
}

}  // namespace

extern "C" {

cJSON* cJSON_ParseWithLength(const char* value, size_t buffer_length) {
    if (value == nullptr) return nullptr;
    return Parser(value, buffer_length).parse();
}

void cJSON_Delete(cJSON* item) {
    if (item == nullptr) return;
    cJSON* child = item->child;
    while (child != nullptr) {
        cJSON* next = child->next;
        cJSON_Delete(child);
        child = next;
    }
    std::free(item->valuestring);
    std::free(item->string);
    std::free(item);
}

char* cJSON_PrintUnformatted(const cJSON* item) {
    std::string serialized;
    if (!serialize_node(item, &serialized)) return nullptr;
    return duplicate(serialized);
}

void cJSON_free(void* object) {
    std::free(object);
}

cJSON* cJSON_CreateObject(void) {
    return make_node(kObject);
}

cJSON* cJSON_CreateArray(void) {
    return make_node(kArray);
}

cJSON* cJSON_CreateNumber(double number) {
    cJSON* item = make_node(kNumber);
    if (item != nullptr) {
        item->valuedouble = number;
        item->valueint = static_cast<int>(number);
    }
    return item;
}

cJSON* cJSON_AddObjectToObject(cJSON* object, const char* name) {
    return add_named(object, name, cJSON_CreateObject());
}

cJSON* cJSON_AddArrayToObject(cJSON* object, const char* name) {
    return add_named(object, name, cJSON_CreateArray());
}

cJSON* cJSON_AddStringToObject(cJSON* object, const char* name, const char* value) {
    cJSON* item = make_node(kString);
    if (item != nullptr) {
        item->valuestring = duplicate(value == nullptr ? "" : value);
        if (item->valuestring == nullptr) {
            cJSON_Delete(item);
            item = nullptr;
        }
    }
    return add_named(object, name, item);
}

cJSON* cJSON_AddNumberToObject(cJSON* object, const char* name, double value) {
    return add_named(object, name, cJSON_CreateNumber(value));
}

cJSON* cJSON_AddBoolToObject(cJSON* object, const char* name, int value) {
    return add_named(object, name, make_node(value ? kTrue : kFalse));
}

cJSON* cJSON_AddNullToObject(cJSON* object, const char* name) {
    return add_named(object, name, make_node(kNull));
}

void cJSON_AddItemToArray(cJSON* array, cJSON* item) {
    if (array == nullptr || array->type != kArray) {
        cJSON_Delete(item);
        return;
    }
    append_child(array, item);
}

cJSON* cJSON_GetObjectItemCaseSensitive(const cJSON* object, const char* string) {
    if (object == nullptr || object->type != kObject || string == nullptr) return nullptr;
    for (cJSON* child = object->child; child != nullptr; child = child->next) {
        if (child->string != nullptr && std::strcmp(child->string, string) == 0) return child;
    }
    return nullptr;
}

int cJSON_IsString(const cJSON* item) { return item != nullptr && item->type == kString; }
int cJSON_IsNumber(const cJSON* item) { return item != nullptr && item->type == kNumber; }
int cJSON_IsObject(const cJSON* item) { return item != nullptr && item->type == kObject; }
int cJSON_IsArray(const cJSON* item) { return item != nullptr && item->type == kArray; }
int cJSON_IsTrue(const cJSON* item) { return item != nullptr && item->type == kTrue; }

}  // extern "C"
