package org.dexon.dekusan.keystore

import org.kethereum.bip39.dirtyPhraseToMnemonicWords
import org.kethereum.bip39.toKey
import org.kethereum.crypto.toECKeyPair
import org.kethereum.model.PrivateKey
import java.net.URI

/// Coin wallet.
data class Wallet(val keyUri: URI, var key: KeystoreKey) {

    val identifier: String = keyUri.path.split("/").last()

    val type: WalletType = key.type

    var accounts = mutableListOf<Account>()

    // Returns the only account for non HD-wallets.
    fun getAccount(password: String, coin: CoinType): Account {
        if (key.type != WalletType.PRIVATE_KEY) throw Exception("Invalid key type")
        if (accounts.isNotEmpty()) return accounts.first()
        val privateKey = PrivateKey(key.decrypt(password))
        val pair = privateKey.toECKeyPair()
        val address = pair.toAddress()
        val account = Account(
            wallet = this,
            address = address,
            derivationPath = DerivationPath("m/44'/${coin.index}'/0'/0/0")
        )
        accounts.add(account)
        return account
    }

    // Returns accounts for specific derivation paths.
    fun getAccounts(derivationPaths: List<DerivationPath>, password: String): List<Account> {
        if (key.type != WalletType.HD_WALLET) throw Exception("Invalid key type")
        val accounts = mutableListOf<Account>()
        derivationPaths.forEach { accounts.add(getAccount(it, password)) }
        return accounts
    }

    private fun getAccount(derivationPath: DerivationPath, password: String): Account {
        var account = accounts.firstOrNull { it.derivationPath == derivationPath }
        if (account != null) return account
        val mnemonicString = key.decrypt(password).toString(Charsets.US_ASCII)
        val mnemonic = dirtyPhraseToMnemonicWords(mnemonicString)
        val extendedKey = mnemonic.toKey(derivationPath.toString())
        val keyPair = extendedKey.keyPair
        val address = keyPair.toAddress()
        account = Account(this, address, derivationPath)
        accounts.add(account)
        return account
    }

    override fun hashCode(): Int = identifier.hashCode()

    override fun equals(other: Any?): Boolean {
        if (other == null || other !is Wallet) return false
        return identifier == other.identifier
    }

}