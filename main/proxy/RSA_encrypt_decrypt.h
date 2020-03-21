/*
Author : SiegeBreaker Devs.
*/
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
int padding = RSA_PKCS1_PADDING;


RSA * createRSA(unsigned char * key, int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    return rsa;
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}


int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n\n",msg, err);
    free(err);
}

 char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2KaAblCENWsSit6jLtYh\n"\
"HKfjBC/qs8A7B8w8kONgb3rfZcpgPpKDY80GGzIsxDDg5FTOw4bVZvryC9sTsTOw\n"\
"dv9vd4hlEW8Eul3p6Weo/9kuQw9ZqrfL4yXw0gJWzD90EMXgawX/7uF9qEgBfv+N\n"\
"PEqHR4g54Ubd3P+/wzLIm4gvMZnOuVFT9Z1dBnJQMjpc7WGA4Fnp+/y8gkoTS2Yw\n"\
"MtKqx9z3q5Xcdmi/N0iYEgfhKgMekURrCcrC1W8Z5U8nTM68QVNhla1u0yiINGyE\n"\
"JnVaGIq5DI2OQ8JLvk9tfQg1lh0JlqtqWjrzZEZPxN+4Wj5BuJxf06urHtUclmHg\n"\
"cwIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEpQIBAAKCAQEA2KaAblCENWsSit6jLtYhHKfjBC/qs8A7B8w8kONgb3rfZcpg\n"\
"PpKDY80GGzIsxDDg5FTOw4bVZvryC9sTsTOwdv9vd4hlEW8Eul3p6Weo/9kuQw9Z\n"\
"qrfL4yXw0gJWzD90EMXgawX/7uF9qEgBfv+NPEqHR4g54Ubd3P+/wzLIm4gvMZnO\n"\
"uVFT9Z1dBnJQMjpc7WGA4Fnp+/y8gkoTS2YwMtKqx9z3q5Xcdmi/N0iYEgfhKgMe\n"\
"kURrCcrC1W8Z5U8nTM68QVNhla1u0yiINGyEJnVaGIq5DI2OQ8JLvk9tfQg1lh0J\n"\
"lqtqWjrzZEZPxN+4Wj5BuJxf06urHtUclmHgcwIDAQABAoIBAQCnVpPEoTQ8/mLo\n"\
"GGb6ejJBK/vQ9CHYjRYLQ9lUIAwQj1uWB+am7gvGPkoFH5AsSYSrWEYMCE00qYfj\n"\
"WGexazdV8p5qOVO3T4TbXkaaHZMPavSsn2Km1igJXvjPfTcFs802V2CryYqRPGIO\n"\
"ZO+i5Eh21SoAOlxagJ5FYNUBNGx2lCGi0dfJHoi/ZQ8zJremIDmiDuHSzl21syU6\n"\
"jeuF/mTq7WQERyhj04hMUUPnm0Ylxasb5Y3AOuiq6nmX7IwEgDmFPUtzHwzSATw0\n"\
"zfsza+lyaNalLPvtwpGeWndEdptAa5SNls03zL9ZR6MVydarXUhR0XpZePfXy3DF\n"\
"tixuN92BAoGBAPVZO9UdATda7rWlpOzR0dJnHZP4BX4hLVuhdWVEFA4rb1PbOhMF\n"\
"ODz+umR5eEmBFXfUvRjUIf88QLRCFlTS69hFGLtjaFmhFzKfQswzOLA7TUZ0POqP\n"\
"S+9LSmFiSY2KPwjCHeU7gtY4jn3d9uAVE6/kvyyw1wGPeEgcjkYZTa6DAoGBAOIO\n"\
"UiXlwNbigcCP941EVLe+zaA7AWDE0RAYOPcoTg1ZFPolHssbBxT6vOXp5a4kyFSR\n"\
"7/q+z2VmuAPXjHSiqTsOeTYWcimCoCgQfD1DDYeVDLi4xxhVAgYNv8Lgp/PHIyEW\n"\
"23a8fcSXIRk7ZaVEhaMdjRmgr8btn6FPEmnLm2NRAoGBAJc6pZK7CiDgv/rfW0VO\n"\
"H5MdVDH80wXn1VmBsCb3S5VgWILLwoQu13dhW+rKpMZJ9r2iN9yyBTKaJRf3FGS8\n"\
"jfsEvDXlFFEK5o2hdT8A45RdOUiQJWw/X4LkWbilKMlByZDQdjTx9betrMcQpjeB\n"\
"Rl1JFj2p0x13HaD1WQ0EU8mZAoGBAOGDr+gmwK6e4RqdhTTlCi8UpkZHFyTWtEn+\n"\
"IDZReyxNxmOWTJYKrJH9Yh1rrbqA72mO/X2EhZp/UuxiSLjC3VkRI1MWKWXH7saJ\n"\
"S6hCEGlGBJ7zl4tqos4vQTLEtEi6TQ1hpCdb+4v3yQlG/CxXo4oKnQ0IBNPLkwh1\n"\
"vcTVXntBAoGAPcRTkKtJo14OdqWroEsa1uQR6w/4Axjtl10AjVWndC5ZVip5IWMJ\n"\
"t2VTenhwWQHVjGX4d5wTfbScvD8WXIh/25WGqfR744UQlxV5b9UaxZz76fIe1Qdg\n"\
"C1guAKACDrH9O8YH23SZFxlGM8DjE33LdjU208AEDSYV7PJtRqo5GXY=\n"\
"-----END RSA PRIVATE KEY-----\n";

