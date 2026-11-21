package com.example.fixtures.vulnerable

import java.net.URI
import java.net.http.HttpRequest

class PaymentClient {
    private val paymentApiKey = "live_key_99482934820194820492"

    fun buildRequest(): HttpRequest =
        HttpRequest.newBuilder(URI("https://payment.example.com/charge"))
            .header("X-Api-Key", paymentApiKey)
            .GET()
            .build()
}
