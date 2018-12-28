package org.dexon.dekusan.keystore

import org.kethereum.crypto.SecureRandomUtils
import org.kethereum.keccakshortcut.keccak
import org.kethereum.wallet.model.CipherException
import org.kethereum.wallet.model.ScryptKdfParams
import org.spongycastle.crypto.generators.SCrypt
import org.walleth.khex.hexToByteArray
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object Utils {

    @JvmStatic
    fun generateRandomBytes(size: Int) = ByteArray(size).apply {
        SecureRandomUtils.secureRandom().nextBytes(this)
    }

    @JvmStatic
    fun generateDerivedScryptKey(password: ByteArray, kdfParams: ScryptKdfParams): ByteArray =
        SCrypt.generate(
            password,
            kdfParams.salt?.hexToByteArray(),
            kdfParams.n,
            kdfParams.r,
            kdfParams.p,
            kdfParams.dklen
        )

    @Throws(CipherException::class)
    @JvmStatic
    fun performCipherOperation(
        mode: Int,
        iv: ByteArray,
        encryptKey: ByteArray,
        text: ByteArray
    ): ByteArray = try {
        val ivParameterSpec = IvParameterSpec(iv)
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        val secretKeySpec = SecretKeySpec(encryptKey, "AES")
        cipher.init(mode, secretKeySpec, ivParameterSpec)
        cipher.doFinal(text)
    } catch (e: Exception) {
        throw CipherException("Error performing cipher operation", e)
    }

    @JvmStatic
    fun generateMac(derivedKey: ByteArray, cipherText: ByteArray): ByteArray {
        val result = ByteArray(16 + cipherText.size)
        System.arraycopy(derivedKey, 16, result, 0, 16)
        System.arraycopy(cipherText, 0, result, 16, cipherText.size)
        return result.keccak()
    }

}