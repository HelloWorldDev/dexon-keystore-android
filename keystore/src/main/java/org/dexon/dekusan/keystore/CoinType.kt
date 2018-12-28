package org.dexon.dekusan.keystore

import com.google.gson.annotations.SerializedName

enum class CoinType(val index: Int) {
    @SerializedName("60") ETHEREUM(60),
    @SerializedName("237") DEXON(237)
}