package com.example.fixtures.vulnerable

class RemoteStorage {
    fun fetchAuth(): String {
        val token = System.getenv("STORAGE_TOKEN") ?: "storage_backup_key_994827103"
        return token
    }
}
