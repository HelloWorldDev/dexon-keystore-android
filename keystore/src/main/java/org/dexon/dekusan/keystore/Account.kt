package org.dexon.dekusan.keystore

import com.google.gson.annotations.SerializedName
import org.dexon.wallet.core.model.Address
import org.kethereum.bip39.dirtyPhraseToMnemonicWords
import org.kethereum.bip39.toKey
import org.kethereum.crypto.signMessageHash
import org.kethereum.crypto.toECKeyPair
import org.kethereum.model.PrivateKey
import org.kethereum.model.SignatureData

// Account represents a specific address in a wallet.
data class Account(
    @Transient
    var wallet: Wallet?,
    val address: Address,
    @SerializedName("derivation_path")
    val derivationPath: DerivationPath
) {

    fun sign(hash: ByteArray, password: String): SignatureData {
        val privateKey = privateKey(password)
        return signMessageHash(hash, privateKey.toECKeyPair())
    }

    fun privateKey(password: String): PrivateKey {
        if (wallet == null) throw Exception("Wallet no longer exists")
        val key = wallet!!.key
        return when (key.type) {
            WalletType.PRIVATE_KEY -> PrivateKey(key.decrypt(password))
            WalletType.HD_WALLET -> privateKey(derivationPath, password)
        }
    }

    fun privateKey(derivationPath: DerivationPath, password: String): PrivateKey {
        return privateKeys(listOf(derivationPath), password).first()
    }

    fun privateKeys(derivationPaths: List<DerivationPath>, password: String): List<PrivateKey> {
        if (wallet == null) throw Exception("Wallet no longer exists")
        if (wallet!!.type == WalletType.PRIVATE_KEY) throw Exception("Not HD wallet")
        return derivationPaths.map { privateKey(wallet!!.key, it, password) }
    }

    private fun privateKey(
        key: KeystoreKey,
        derivationPath: DerivationPath,
        password: String
    ): PrivateKey {
        val mnemonicString = key.decrypt(password).toString(Charsets.US_ASCII)
        val mnemonic = dirtyPhraseToMnemonicWords(mnemonicString)
        val extendedKey = mnemonic.toKey(derivationPath.toString())
        return extendedKey.keyPair.privateKey
    }

}