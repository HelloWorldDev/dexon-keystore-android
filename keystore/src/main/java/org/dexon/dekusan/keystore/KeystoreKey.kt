package org.dexon.dekusan.keystore

import com.google.gson.GsonBuilder
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import org.kethereum.bip39.dirtyPhraseToMnemonicWords
import org.kethereum.bip39.generateMnemonic
import org.kethereum.bip39.wordlists.WORDLIST_ENGLISH
import org.kethereum.crypto.model.PRIVATE_KEY_SIZE
import org.kethereum.crypto.model.PrivateKey
import org.kethereum.extensions.toBytesPadded
import org.kethereum.model.Address
import org.kethereum.wallet.model.CipherException
import org.walleth.khex.hexToByteArray
import org.walleth.khex.toNoPrefixHexString
import java.io.File
import java.io.FileReader
import java.lang.reflect.Type
import java.net.URI
import java.util.*
import javax.crypto.Cipher

class KeystoreKey {

    // Wallet type.
    var type: WalletType

    // Wallet UUID, optional.
    var id: String

    // Key's address
    var address: Address? = null

    // Key header with encrypted private key and crypto parameters.
    var crypto: KeystoreKeyCrypto

    // Mnemonic passphrase
    @Transient
    var passphrase: String = ""

    // Key version, must be 3.
    var version: Int = 3

    // Default coin for this key.
    var coin: CoinType? = null

    // List of active accounts.
    var activeAccounts: List<Account>? = listOf()

    // Creates a new `Key` with a password.
    constructor(password: String) : this(
        password = password,
        mnemonic = dirtyPhraseToMnemonicWords(
            generateMnemonic(strength = 128, wordList = WORDLIST_ENGLISH)
        ).words.joinToString(" "),
        passphrase = ""
    )

    // Initializes a `Key` by encrypting a private key with a password.
    constructor(password: String, key: PrivateKey, coin: CoinType?) {
        this.id = UUID.randomUUID().toString()
        this.crypto = KeystoreKeyCrypto(password, key.key.toBytesPadded(PRIVATE_KEY_SIZE))
        this.type = WalletType.PRIVATE_KEY
        this.coin = coin
    }

    // Initializes a `Key` by encrypting a mnemonic phrase with a password.
    constructor(password: String, mnemonic: String, passphrase: String = "") {
        this.id = UUID.randomUUID().toString()
        this.crypto = KeystoreKeyCrypto(password, mnemonic.toByteArray(charset = Charsets.US_ASCII))
        this.type = WalletType.HD_WALLET
        this.passphrase = passphrase
    }

    // Initializes a `Key` from a JSON wallet.
    constructor(uri: URI) {
        val file = File(uri.path)
        val gson = GsonBuilder()
            .registerTypeAdapter(Address::class.java, AddressDeserializer())
            .create()
        gson.fromJson(FileReader(file), this::class.java).let {
            this.type = if (it.type == null) WalletType.PRIVATE_KEY else it.type
            this.id = it.id
            this.address = it.address
            this.crypto = it.crypto
            this.version = it.version
            this.coin = it.coin
            this.activeAccounts = it.activeAccounts ?: listOf()
        }
    }

    // Decrypts the key and returns the decrypted data.
    fun decrypt(password: String): ByteArray {
        val passwordByteArray = password.toByteArray()
        val derivedKey: ByteArray

        when (crypto.kdf) {
            "scrypt" -> derivedKey = Utils.generateDerivedScryptKey(passwordByteArray, crypto.kdfParams)
            else -> throw CipherException("Unsupported KDF: ${crypto.kdf}")
        }

        val mac = Utils.generateMac(derivedKey, crypto.cipherText.hexToByteArray())
        if (mac.toNoPrefixHexString() != crypto.mac) {
            throw CipherException("Invalid password")
        }

        val encryptKey = Arrays.copyOfRange(derivedKey, 0, 16)

        return Utils.performCipherOperation(
            mode = Cipher.DECRYPT_MODE,
            iv = crypto.cipherParams.iv.hexToByteArray(),
            encryptKey = encryptKey,
            text =  crypto.cipherText.hexToByteArray()
        )
    }

}

class AddressDeserializer : JsonDeserializer<Address> {
    override fun deserialize(
        json: JsonElement,
        typeOfT: Type?,
        context: JsonDeserializationContext?
    ): Address = Address(json.asString)
}