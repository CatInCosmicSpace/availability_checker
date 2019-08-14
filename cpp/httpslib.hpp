#pragma once

#include <iostream>
#include <cstring>
#include <utility>
#include <stdexcept>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>


void print_cn_name(const char *label, X509_NAME *const name) {
    int idx = -1;
    unsigned char *utf8 = nullptr;
    X509_NAME_ENTRY *entry;
    ASN1_STRING *data;

    if (!name)
        return;

    idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (idx < 0)
        return;

    entry = X509_NAME_get_entry(name, idx);
    if (!entry)
        return;

    data = X509_NAME_ENTRY_get_data(entry);
    if (!data)
        return;

    if (!ASN1_STRING_to_UTF8(&utf8, data) || !utf8)
        return;

    printf("%s: %s\n", label, utf8);
    OPENSSL_free(utf8);
}


void print_san_name(const char *label, X509 *const cert) {
    int success = 0;
    GENERAL_NAMES *names = nullptr;
    unsigned char *utf8 = nullptr;
    do {
        if (!cert) break; /* failed */

        names = (GENERAL_NAMES *) X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0);
        if (!names) break;

        int i = 0, count = sk_GENERAL_NAME_num(names);
        if (!count) break; /* failed */

        for (i = 0; i < count; ++i) {
            GENERAL_NAME *entry = sk_GENERAL_NAME_value(names, i);
            if (!entry) continue;

            if (GEN_DNS == entry->type) {
                int len1 = 0, len2 = -1;

                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if (utf8) {
                    len2 = (int) strlen((const char *) utf8);
                }

                if (len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2,
                            len1);
                }

                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if (utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }

                if (utf8) {
                    OPENSSL_free(utf8), utf8 = nullptr;
                }
            } else {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }
    } while (false);

    if (names)
        GENERAL_NAMES_free(names);

    if (utf8)
        OPENSSL_free(utf8);

    if (!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}


class SSLInit {
public:
    SSLInit() {
        /* https://www.openssl.org/docs/ssl/SSL_library_init.html */
        (void) SSL_library_init();
        /* Cannot fail (always returns success) ??? */

        /* https://www.openssl.org/docs/crypto/ERR_load_crypto_strings.html */
        SSL_load_error_strings(); // NOLINT(hicpp-signed-bitwise)
        /* Cannot fail ??? */

        /* SSL_load_error_strings loads both libssl and libcrypto strings */
//        ERR_load_crypto_strings();
        /* Cannot fail ??? */
    }

    ~SSLInit() = default;
};

static SSLInit _SSLInit();


struct HTTPResponse {
    std::string head;
    std::string body;
    int ret_code;
    std::string message;

    explicit HTTPResponse(const std::string &response) {
        std::string delimer("\r\n\r\n");
        size_t pos = response.find(delimer);
        head = response.substr(0, pos);
        body = response.substr(pos + delimer.length());

        std::string ans_line = head.substr(0, head.find("\r\n"));
        size_t left = ans_line.find(' ');
        size_t right = ans_line.find(' ', left + 1);
        ret_code = stoi(ans_line.substr(left + 1, right - left - 1));
        message = ans_line.substr(right + 1, ans_line.length() - right - 1);
    }

    operator bool() {
        return ret_code == 200;
    }
};


class HTTPSClient {
    std::string _host;
    uint16_t _port;
    BIO *_web;
    BIO *_out;
    SSL *_ssl;


    static int verify_callback(int preverify, X509_STORE_CTX *x509_ctx) {
        /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

        int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
        int err = X509_STORE_CTX_get_error(x509_ctx);

        X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
        X509_NAME *iname = cert ? X509_get_issuer_name(cert) : nullptr;
        X509_NAME *sname = cert ? X509_get_subject_name(cert) : nullptr;

//        fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);

        /* Issuer is the authority we trust that warrants nothing useful */
//        print_cn_name("Issuer (cn)", iname);

        /* Subject is who the certificate is issued to by the authority  */
//        print_cn_name("Subject (cn)", sname);

        if (depth == 0) {
            /* If depth is 0, its the server's certificate. Print the SANs */
//            print_san_name("Subject (san)", cert);
        }

//        if (preverify == 0) {
//            if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
//                fprintf(stderr, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
//            else if (err == X509_V_ERR_CERT_UNTRUSTED)
//                fprintf(stderr, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
//            else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
//                fprintf(stderr, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
//            else if (err == X509_V_ERR_CERT_NOT_YET_VALID)
//                fprintf(stderr, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
//            else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
//                fprintf(stderr, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
//            else if (err == X509_V_OK)
//                fprintf(stderr, "  Error = X509_V_OK\n");
//            else
//                fprintf(stderr, "  Error = %d\n", err);
//        }

        return 1;
    }


    static void print_error_string(unsigned long err, const char *const label) {
        const char *const str = ERR_reason_error_string(err);
        if (str)
            fprintf(stderr, "%s\n", str);
        else
            fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
    }

public:
    HTTPSClient(std::string host, uint16_t port, const std::string &cafile) :
            _host(std::move(host)),
            _port(port),
            _web(nullptr),
            _out(nullptr),
            _ssl(nullptr) {

        long res = 1;
        int ret = 1;
        unsigned long ssl_err = 0;

        SSL_CTX *ctx = nullptr;

        /* https://www.openssl.org/docs/ssl/SSL_CTX_new.html */
        const SSL_METHOD *method = SSLv23_method();
        ssl_err = ERR_get_error();

        if (method == nullptr) {
            print_error_string(ssl_err, "SSLv23_method");
            throw std::runtime_error("");
        }

        /* http://www.openssl.org/docs/ssl/ctx_new.html */
        ctx = SSL_CTX_new(method);
        /* ctx = SSL_CTX_new(TLSv1_method()); */
        ssl_err = ERR_get_error();

        if (ctx == nullptr) {
            print_error_string(ssl_err, "SSL_CTX_new");
            throw std::runtime_error("SSL_CTX_new");
        }

        /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
        /* Cannot fail ??? */

        /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
        // SSL_CTX_set_verify_depth(ctx, 5);
        /* Cannot fail ??? */

        /* Remove the most egregious. Because SSLv2 and SSLv3 have been      */
        /* removed, a TLSv1.0 handshake is used. The client accepts TLSv1.0  */
        /* and above. An added benefit of TLS 1.0 and above are TLS          */
        /* extensions like Server Name Indicatior (SNI).                     */
        const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        long old_opts = SSL_CTX_set_options(ctx, flags);

        /* http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html */
        res = SSL_CTX_load_verify_locations(ctx, cafile.c_str(), nullptr);
        ssl_err = ERR_get_error();

        if (res != 1) {
            /* Non-fatal, but something else will probably break later */
            print_error_string(ssl_err, "SSL_CTX_load_verify_locations");
        }

        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        _web = BIO_new_ssl_connect(ctx);
        ssl_err = ERR_get_error();

        if (_web == nullptr) {
            print_error_string(ssl_err, "BIO_new_ssl_connect");
            throw std::runtime_error("BIO_new_ssl_connect");
        }

        /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
        std::string hostname = _host + ":" + std::to_string(port);
        res = BIO_set_conn_hostname(_web, hostname.c_str());
        ssl_err = ERR_get_error();

        if (res != 1) {
            print_error_string(ssl_err, "BIO_set_conn_hostname");
            throw std::runtime_error("BIO_set_conn_hostname");
        }

        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        /* This copies an internal pointer. No need to free.  */
        BIO_get_ssl(_web, &_ssl);
        ssl_err = ERR_get_error();

        if (_ssl == nullptr) {
            print_error_string(ssl_err, "BIO_get_ssl");
            throw std::runtime_error("BIO_get_ssl");
        }

        /* https://www.openssl.org/docs/ssl/ssl.html#DEALING_WITH_PROTOCOL_CONTEXTS */
        /* https://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html            */
//        res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
//        ssl_err = ERR_get_error();

//        if(!(1 == res))
//        {
//            print_error_string(ssl_err, "SSL_set_cipher_list");
//            throw std::runtime_error("");
//        }

        /* No documentation. See the source code for tls.h and s_client.c */
        res = SSL_set_tlsext_host_name(_ssl, _host.c_str());
        ssl_err = ERR_get_error();

        if (res != 1) {
            /* Non-fatal, but who knows what cert might be served by an SNI server  */
            /* (We know its the default site's cert in Apache and IIS...)           */
            print_error_string(ssl_err, "SSL_set_tlsext_host_name");
        }

        /* https://www.openssl.org/docs/crypto/BIO_s_file.html */
        _out = BIO_new_fp(stdout, BIO_NOCLOSE);
        ssl_err = ERR_get_error();

        if (_out == nullptr) {
            print_error_string(ssl_err, "BIO_new_fp");
            throw std::runtime_error("BIO_new_fp");
        }

        /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
        res = BIO_do_connect(_web);
        ssl_err = ERR_get_error();
        const auto sysErrorCode = errno;
        const auto sslErrorCode = ERR_get_error();

        if (res != 1) {
            print_error_string(ssl_err, "BIO_do_connect");
            throw std::runtime_error("BIO_do_connect");
        }

        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        res = BIO_do_handshake(_web);
        ssl_err = ERR_get_error();

        if (res != 1) {
            print_error_string(ssl_err, "BIO_do_handshake");
            throw std::runtime_error("BIO_do_handshake");
        }

        /**************************************************************************************/
        /**************************************************************************************/
        /* You need to perform X509 verification here. There are two documents that provide   */
        /*   guidance on the gyrations. First is RFC 5280, and second is RFC 6125. Two other  */
        /*   documents of interest are:                                                       */
        /*     Baseline Certificate Requirements:                                             */
        /*       https://www.cabforum.org/Baseline_Requirements_V1_1_6.pdf                    */
        /*     Extended Validation Certificate Requirements:                                  */
        /*       https://www.cabforum.org/Guidelines_v1_4_3.pdf                               */
        /*                                                                                    */
        /* Here are the minimum steps you should perform:                                     */
        /*   1. Call SSL_get_peer_certificate and ensure the certificate is non-NULL. It      */
        /*      should never be NULL because Anonymous Diffie-Hellman (ADH) is not allowed.   */
        /*   2. Call SSL_get_verify_result and ensure it returns X509_V_OK. This return value */
        /*      depends upon your verify_callback if you provided one. If not, the library    */
        /*      default validation is fine (and you should not need to change it).            */
        /*   3. Verify either the CN or the SAN matches the host you attempted to connect to. */
        /*      Note Well (N.B.): OpenSSL prior to version 1.1.0 did *NOT* perform hostname   */
        /*      verification. If you are using OpenSSL 0.9.8 or 1.0.1, then you will need     */
        /*      to perform hostname verification yourself. The code to get you started on     */
        /*      hostname verification is provided in print_cn_name and print_san_name. Be     */
        /*      sure you are sensitive to ccTLDs (don't navively transform the hostname       */
        /*      string). http://publicsuffix.org/ might be helpful.                           */
        /*                                                                                    */
        /* If all three checks succeed, then you have a chance at a secure connection. But    */
        /*   its only a chance, and you should either pin your certificates (to remove DNS,   */
        /*   CA, and Web Hosters from the equation) or implement a Trust-On-First-Use (TOFU)  */
        /*   scheme like Perspectives or SSH. But before you TOFU, you still have to make     */
        /*   the customary checks to ensure the certifcate passes the sniff test.             */
        /*                                                                                    */
        /* Happy certificate validation hunting!                                              */
        /**************************************************************************************/
        /**************************************************************************************/


        /* Step 1: verify a server certifcate was presented during negotiation */
        /* https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html          */
        X509 *cert = SSL_get_peer_certificate(_ssl);
        if (cert) { X509_free(cert); } /* Free immediately */

        if (cert == nullptr) {
            /* Hack a code for print_error_string. */
            print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "SSL_get_peer_certificate");
            throw std::runtime_error("SSL_get_peer_certificate");
        }

        /* Step 2: verify the result of chain verifcation             */
        /* http://www.openssl.org/docs/ssl/SSL_get_verify_result.html */
        /* Error codes: http://www.openssl.org/docs/apps/verify.html  */
        res = SSL_get_verify_result(_ssl);

        if (res != X509_V_OK) {
            /* Hack a code into print_error_string. */
            print_error_string((unsigned long) res, "SSL_get_verify_results");
//            throw std::runtime_error("SSL_get_verify_results");
        }

        /* Step 3: hostname verifcation.   */
        /* An exercise left to the reader. */
    }

    HTTPResponse get(const std::string &location = "/") {
        std::string msg = "GET " + location + " HTTP/1.1\r\nHost: " + _host + "\r\nConnection: keep-alive\r\n\r\n";
        BIO_puts(_web, msg.c_str());

        int len = 0;
        std::string buffer;
        do {
            char buff[1536] = {};

            /* https://www.openssl.org/docs/crypto/BIO_read.html */
            len = BIO_read(_web, buff, sizeof(buff));

            if (len > 0)
                buffer.append(buff, len);

            /* BIO_should_retry returns TRUE unless there's an  */
            /* error. We expect an error when the server        */
            /* provides the response and closes the connection. */

        } while (len > 0 || BIO_should_retry(_web));
        return HTTPResponse(buffer);
    }

    HTTPResponse post(const std::string &location, const std::string &data, const std::string &content_type) {
        std::string msg =
                "POST " + location + " HTTP/1.1""\r\n"
                                     "Host: " + _host + "\r\n"
                                                        "Content-Type: " + content_type + "\r\n"
                                                                                          "Content-Length: " +
                std::to_string(data.size()) + "\r\n"
                                              "Connection: keep-alive\r\n\r\n" + data;
        BIO_puts(_web, msg.c_str());

        int len = 0;
        std::string buffer;
        do {
            char buff[1536] = {};

            /* https://www.openssl.org/docs/crypto/BIO_read.html */
            len = BIO_read(_web, buff, sizeof(buff));

            if (len > 0)
                buffer.append(buff, len);

            /* BIO_should_retry returns TRUE unless there's an  */
            /* error. We expect an error when the server        */
            /* provides the response and closes the connection. */

        } while (len > 0 || BIO_should_retry(_web));
        return HTTPResponse(buffer);
    }

};
