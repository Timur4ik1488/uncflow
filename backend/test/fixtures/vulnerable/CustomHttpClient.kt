package com.example.fixtures.vulnerable

import javax.net.ssl.HostnameVerifier
import okhttp3.OkHttpClient

class CustomHttpClient {
    fun createInsecureClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .hostnameVerifier(HostnameVerifier { _, _ -> true })
            .build()
    }
}
