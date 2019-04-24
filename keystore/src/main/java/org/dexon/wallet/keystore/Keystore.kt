package org.dexon.wallet.keystore

import com.google.gson.JsonParser
import org.kethereum.bip39.dirtyPhraseToMnemonicWords
import org.kethereum.bip39.validate
import org.kethereum.bip39.wordlists.WORDLIST_ENGLISH
import org.kethereum.model.PrivateKey
import java.io.File
import java.net.URI
import java.text.SimpleDateFormat
import java.util.*

class Keystore(val keyDirectory: File) {

    var wallets = mutableListOf<Wallet>()

    init { load() }

    private fun load() {
        if (!keyDirectory.exists()) {
            keyDirectory.mkdir()
        }
        for (file in keyDirectory.listFiles()) {
            val key = KeystoreKey(file.toURI())
            val wallet = Wallet(file.toURI(), key)
            key.activeAccounts?.forEach {
                it.wallet = wallet
                wallet.accounts.add(it)
            }
            wallets.add(wallet)
        }
    }

    fun createWallet(password: String, derivationPaths: List<DerivationPath>): Wallet {
        val key = KeystoreKey(password)
        return saveCreatedWallet(key, password, derivationPaths)
    }

    fun addAccounts(
        wallet: Wallet,
        derivationPaths: List<DerivationPath>,
        password: String
    ): List<Account> {
        val accounts = wallet.getAccounts(derivationPaths, password)
        save(wallet)
        return accounts
    }

    // Imports an encrypted JSON key.
    fun import(json: String, password: String, newPassword: String, coin: CoinType): Wallet {
        val key = KeystoreKey(JsonParser().parse(json))
        val data = key.decrypt(password)
        return when (key.type) {
            WalletType.PRIVATE_KEY -> {
                val privateKey = PrivateKey(data)
                import(privateKey, newPassword, key.coin ?: coin)
            }
            WalletType.HD_WALLET -> {
                val mnemonic = data.toString(Charsets.US_ASCII)
                val derivationPath = DerivationPath("m/44'/${coin.index}'/0'/0/0")
                import(
                    mnemonic = mnemonic,
                    encryptPassword = newPassword,
                    derivationPath = derivationPath
                )
            }
        }
    }

    // Imports a private key.
    fun import(privateKey: PrivateKey, password: String, coin: CoinType): Wallet {
        val newKey = KeystoreKey(password, privateKey, coin)
        val uri = makeAccountUri()
        val wallet = Wallet(uri, newKey)
        wallet.getAccount(password, coin)
        wallets.add(wallet)
        save(wallet)
        return wallet
    }

    // Imports a wallet.
    fun import(
        mnemonic: String,
        passphrase: String = "",
        encryptPassword: String,
        derivationPath: DerivationPath
    ): Wallet {
        if (!dirtyPhraseToMnemonicWords(mnemonic).validate(WORDLIST_ENGLISH)) {
            throw Exception("Invalid mnemonic")
        }
        val key = KeystoreKey(encryptPassword, mnemonic, passphrase)
        val uri = makeAccountUri()
        val wallet = Wallet(uri, key)
        wallet.getAccounts(listOf(derivationPath), encryptPassword)
        wallets.add(wallet)
        save(wallet)
        return wallet
    }

    // Imports a wallet with multiple derivation paths.
    fun import(
        mnemonic: String,
        passphrase: String = "",
        encryptPassword: String,
        derivationPaths: List<DerivationPath>
    ): Wallet {
        if (!dirtyPhraseToMnemonicWords(mnemonic).validate(WORDLIST_ENGLISH)) {
            throw Exception("Invalid mnemonic")
        }
        val key = KeystoreKey(encryptPassword, mnemonic, passphrase)
        val uri = makeAccountUri()
        val wallet = Wallet(uri, key)
        wallet.getAccounts(derivationPaths, encryptPassword)
        wallets.add(wallet)
        save(wallet)
        return wallet
    }

    // Exports a wallet as JSON string.
    fun export(wallet: Wallet, password: String, newPassword: String): String {
        val data = wallet.key.decrypt(password)
        val newKey: KeystoreKey
        newKey = when (wallet.key.type) {
            WalletType.PRIVATE_KEY -> {
                val privateKey = PrivateKey(data)
                KeystoreKey(newPassword, privateKey, null)
            }
            WalletType.HD_WALLET -> {
                val mnemonic = data.toString(Charsets.US_ASCII)
                KeystoreKey(newPassword, mnemonic, wallet.key.passphrase)
            }
        }
        return newKey.toJson()
    }

    // Exports a wallet as private key.
    fun exportPrivateKey(wallet: Wallet, password: String): PrivateKey {
        return PrivateKey(wallet.key.decrypt(password))
    }

    // Exports a wallet as a mnemonic phrase.
    fun exportMnemonic(wallet: Wallet, password: String): String {
        val data = wallet.key.decrypt(password)
        when (wallet.key.type) {
            WalletType.PRIVATE_KEY -> throw Exception("Invalid mnemonic")
            WalletType.HD_WALLET -> {
                return data.toString(Charsets.US_ASCII)
            }
        }
    }

    // Deletes an account including its key.
    fun delete(wallet: Wallet) {
        val index = wallets.indexOf(wallet)
        if (index == -1) throw Exception("Missing wallet")
        wallets.removeAt(index)
        File(wallet.keyUri.path).delete()
    }

    private fun saveCreatedWallet(key: KeystoreKey, password: String, derivationPaths: List<DerivationPath>): Wallet {
        val uri = makeAccountUri()
        val wallet = Wallet(uri, key)
        when (wallet.type) {
            WalletType.PRIVATE_KEY -> {
                wallet.getAccount(password, CoinType.ETHEREUM)
            }
            WalletType.HD_WALLET -> {
                wallet.getAccounts(derivationPaths, password)
            }
        }
        wallets.add(wallet)

        save(wallet)

        return wallet
    }

    private fun save(wallet: Wallet) {
        val key = wallet.key
        key.activeAccounts = wallet.accounts
        File(wallet.keyUri.path).writeText(key.toJson())
    }

    private fun makeAccountUri() = URI(keyDirectory.toURI().path + '/' + generateFileName())

    private fun generateFileName() =
        SimpleDateFormat("'UTC--'yyyy-MM-dd'T'HH-mm-ss.SSS'--'", Locale.ENGLISH).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date()) + UUID.randomUUID().toString()

}