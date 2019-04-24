package org.dexon.wallet.keystore

import com.google.gson.annotations.SerializedName
import org.kethereum.wallet.LIGHT_SCRYPT_CONFIG
import org.kethereum.wallet.model.CipherParams
import org.kethereum.wallet.model.ScryptKdfParams
import org.walleth.khex.toNoPrefixHexString
import java.util.*
import javax.crypto.Cipher

private const val R = 8
private const val DKLEN = 32

// Encrypted private key and crypto parameters.
class KeystoreKeyCrypto(password: String, data: ByteArray) {

    // Encrypted data.
    @SerializedName("ciphertext")
    var cipherText: String

    // Cipher parameters.
    @SerializedName("cipherparams")
    var cipherParams: CipherParams

    // Key derivation function parameters.
    @SerializedName("kdfparams")
    var kdfParams: ScryptKdfParams

    // Cipher algorithm.
    val cipher: String = "aes-128-ctr"

    // Key derivation function, must be scrypt.
    val kdf: String = "scrypt"

    // Message authentication code.
    var mac: String

    init {
        val config = LIGHT_SCRYPT_CONFIG
        val mySalt = Utils.generateRandomBytes(32)
        val derivedKey = Utils.generateDerivedScryptKey(
            password = password.toByteArray(),
            kdfParams = ScryptKdfParams(n = config.n, r = R, p = config.p).apply {
                dklen = DKLEN
                salt = mySalt.toNoPrefixHexString()
            }
        )
        val encryptKey = Arrays.copyOfRange(derivedKey, 0, 16)
        val iv = Utils.generateRandomBytes(16)
        val cipherTextByteArray = Utils.performCipherOperation(
            mode = Cipher.ENCRYPT_MODE,
            iv = iv,
            encryptKey = encryptKey,
            text = data
        )
        this.cipherText = cipherTextByteArray.toNoPrefixHexString()
        this.mac = Utils.generateMac(derivedKey, cipherTextByteArray).toNoPrefixHexString()
        this.cipherParams = CipherParams(iv.toNoPrefixHexString())
        this.kdfParams = ScryptKdfParams(
            n = config.n,
            p = config.p,
            r = R,
            dklen = DKLEN,
            salt = mySalt.toNoPrefixHexString()
        )
    }

}