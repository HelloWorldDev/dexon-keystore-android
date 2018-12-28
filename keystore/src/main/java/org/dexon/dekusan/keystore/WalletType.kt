package org.dexon.dekusan.keystore

import com.google.gson.annotations.SerializedName

enum class WalletType(val type: String) {
    @SerializedName("private-key") PRIVATE_KEY("private-key"),
    @SerializedName("mnemonic") HD_WALLET("mnemonic")
}