#include "m5auth/vault.hpp"
#include <algorithm>
#ifdef ESP_PLATFORM
#include "mbedtls/gcm.h"
#else
#include <openssl/evp.h>
#endif
namespace m5auth::vault {
bool encrypt_vault_with_nonce(const std::vector<std::uint8_t>&p,const std::array<std::uint8_t,kVmkBytes>&k,const std::array<std::uint8_t,kVaultIdBytes>&id,std::uint64_t g,const std::array<std::uint8_t,kVaultNonceBytes>&n,VaultEnvelope&out){std::vector<std::uint8_t>a;if(!build_vault_aad(id,g,a))return false;VaultEnvelope t;t.vault_id=id;t.generation=g;t.nonce=n;t.ciphertext.resize(p.size());
#ifdef ESP_PLATFORM
mbedtls_gcm_context c;mbedtls_gcm_init(&c);bool ok=mbedtls_gcm_setkey(&c,MBEDTLS_CIPHER_ID_AES,k.data(),256)==0&&mbedtls_gcm_crypt_and_tag(&c,MBEDTLS_GCM_ENCRYPT,p.size(),n.data(),n.size(),a.data(),a.size(),p.data(),t.ciphertext.data(),t.tag.size(),t.tag.data())==0;mbedtls_gcm_free(&c);
#else
EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();int l=0,z=0;bool ok=c&&EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,n.size(),nullptr)==1&&EVP_EncryptInit_ex(c,nullptr,nullptr,k.data(),n.data())==1&&EVP_EncryptUpdate(c,nullptr,&l,a.data(),a.size())==1&&EVP_EncryptUpdate(c,t.ciphertext.data(),&l,p.data(),p.size())==1;z=l;ok=ok&&EVP_EncryptFinal_ex(c,t.ciphertext.data()+z,&l)==1;z+=l;ok=ok&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,t.tag.size(),t.tag.data())==1;EVP_CIPHER_CTX_free(c);if(ok)t.ciphertext.resize(z);
#endif
if(!ok){std::fill(t.ciphertext.begin(),t.ciphertext.end(),0);return false;}out=std::move(t);return true;}
bool decrypt_vault(const VaultEnvelope&e,const std::array<std::uint8_t,kVmkBytes>&k,std::vector<std::uint8_t>&p){if(e.vault_format_version!=kVaultFormatVersion||e.storage_schema_version!=kTargetStorageSchemaVersion)return false;std::vector<std::uint8_t>a;if(!build_vault_aad(e.vault_id,e.generation,a,e.vault_format_version,e.storage_schema_version))return false;std::vector<std::uint8_t>t(e.ciphertext.size());
#ifdef ESP_PLATFORM
mbedtls_gcm_context c;mbedtls_gcm_init(&c);bool ok=mbedtls_gcm_setkey(&c,MBEDTLS_CIPHER_ID_AES,k.data(),256)==0&&mbedtls_gcm_auth_decrypt(&c,e.ciphertext.size(),e.nonce.data(),e.nonce.size(),a.data(),a.size(),e.tag.data(),e.tag.size(),e.ciphertext.data(),t.data())==0;mbedtls_gcm_free(&c);
#else
EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();int l=0,z=0;bool ok=c&&EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,e.nonce.size(),nullptr)==1&&EVP_DecryptInit_ex(c,nullptr,nullptr,k.data(),e.nonce.data())==1&&EVP_DecryptUpdate(c,nullptr,&l,a.data(),a.size())==1&&EVP_DecryptUpdate(c,t.data(),&l,e.ciphertext.data(),e.ciphertext.size())==1;z=l;ok=ok&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,e.tag.size(),const_cast<std::uint8_t*>(e.tag.data()))==1&&EVP_DecryptFinal_ex(c,t.data()+z,&l)==1;z+=l;EVP_CIPHER_CTX_free(c);if(ok)t.resize(z);
#endif
if(!ok){std::fill(t.begin(),t.end(),0);return false;}p.swap(t);return true;}
}  // namespace m5auth::vault
