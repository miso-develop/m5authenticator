#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cJSON {
    struct cJSON* next;
    struct cJSON* prev;
    struct cJSON* child;
    int type;
    char* valuestring;
    int valueint;
    double valuedouble;
    char* string;
} cJSON;

cJSON* cJSON_ParseWithLength(const char* value, size_t buffer_length);
void cJSON_Delete(cJSON* item);
char* cJSON_PrintUnformatted(const cJSON* item);
void cJSON_free(void* object);

cJSON* cJSON_CreateObject(void);
cJSON* cJSON_CreateArray(void);
cJSON* cJSON_CreateNumber(double number);

cJSON* cJSON_AddObjectToObject(cJSON* object, const char* name);
cJSON* cJSON_AddArrayToObject(cJSON* object, const char* name);
cJSON* cJSON_AddStringToObject(cJSON* object, const char* name, const char* value);
cJSON* cJSON_AddNumberToObject(cJSON* object, const char* name, double value);
cJSON* cJSON_AddBoolToObject(cJSON* object, const char* name, int value);
cJSON* cJSON_AddNullToObject(cJSON* object, const char* name);
void cJSON_AddItemToArray(cJSON* array, cJSON* item);

cJSON* cJSON_GetObjectItemCaseSensitive(const cJSON* object, const char* string);
int cJSON_IsString(const cJSON* item);
int cJSON_IsNumber(const cJSON* item);
int cJSON_IsObject(const cJSON* item);
int cJSON_IsArray(const cJSON* item);
int cJSON_IsTrue(const cJSON* item);

#ifdef __cplusplus
}
#endif
