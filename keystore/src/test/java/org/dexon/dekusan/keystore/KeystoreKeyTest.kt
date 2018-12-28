package org.dexon.dekusan.keystore

import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.kethereum.bip39.dirtyPhraseToMnemonicWords
import org.kethereum.bip39.generateMnemonic
import org.kethereum.bip39.wordlists.WORDLIST_ENGLISH
import org.kethereum.crypto.model.PrivateKey
import org.kethereum.extensions.toHexStringNoPrefix
import org.kethereum.wallet.model.CipherException
import org.walleth.khex.hexToByteArray

@Suppress("RECEIVER_NULLABILITY_MISMATCH_BASED_ON_JAVA_ANNOTATIONS")
class KeystoreKeyTest {

    @get:Rule
    val expectedException: ExpectedException = ExpectedException.none()

    @Test(expected = Test.None::class)
    fun testCreateWalletWithPassword() {
        KeystoreKey(password = PASSWORD)
    }

    @Test
    fun testCreateWalletWithPrivateKey() {
        val expectedPrivateKey = PrivateKey(
            "3a1076bf45ab87712ad64ccb3b10217737f7faacbf2872e88fdd9a537d8fe266".hexToByteArray()
        )

        val key = KeystoreKey(
            password = PASSWORD,
            key = expectedPrivateKey,
            coin = CoinType.ETHEREUM
        )

        val actualPrivateKey = PrivateKey(key.decrypt(password = PASSWORD))

        Assert.assertEquals(WalletType.PRIVATE_KEY, key.type)
        Assert.assertEquals(CoinType.ETHEREUM, key.coin)
        Assert.assertEquals(expectedPrivateKey.key, actualPrivateKey.key)
    }

    @Test
    fun testCreateWalletWithMnemonic() {
        val expectedMnemonic = dirtyPhraseToMnemonicWords(
            generateMnemonic(strength = 128, wordList = WORDLIST_ENGLISH)
        ).words.joinToString(" ")

        val key = KeystoreKey(
            password = PASSWORD,
            mnemonic = expectedMnemonic,
            passphrase = ""
        )

        val actualMnemonic = key.decrypt(password = PASSWORD).toString(Charsets.US_ASCII)

        Assert.assertEquals(WalletType.HD_WALLET, key.type)
        Assert.assertEquals(expectedMnemonic, actualMnemonic)
    }

    @Test
    fun testReadWalletWithMnemonicType() {
        val classLoader = javaClass.classLoader.getResource("wallet_mnemonic.json")
        val uri = classLoader.toURI()
        val key = KeystoreKey(uri)

        Assert.assertEquals("e0fe53d0-7a3d-4f65-88b1-9bb4e245a169", key.id)
        Assert.assertEquals(3, key.version)
        Assert.assertEquals(WalletType.HD_WALLET, key.type)
        Assert.assertEquals(CoinType.ETHEREUM, key.coin)
        Assert.assertEquals("0x32dd55E0BCF509a35A3F5eEb8593fbEb244796b1", key.address?.hex)
        Assert.assertEquals("", key.passphrase)

        val crypto = key.crypto

        Assert.assertEquals("aes-128-ctr", crypto.cipher)
        Assert.assertEquals("64b5b416bb2bef882eb7cc63ed92c064e53c818ec46351e07ac140e5ba871596f1595fe6cad8333147fe68c031ba001b79b64dd1edd513043134217b7ffe1903ca23b1fbe823671827e3b2dff69bbd448d9cb79a3321ec8801f2a995", crypto.cipherText)
        Assert.assertEquals("scrypt", crypto.kdf)
        Assert.assertEquals("01816d0a5c31cd03b644f2d756ac8167c2498808040cbace8c35c46dcf06b7a1", crypto.mac)
        Assert.assertEquals("7aaf7eb6f4b0e7d995e8eac67e4d52eb", crypto.cipherParams.iv)
        Assert.assertEquals(32, crypto.kdfParams.dklen)
        Assert.assertEquals(4096, crypto.kdfParams.n)
        Assert.assertEquals(6, crypto.kdfParams.p)
        Assert.assertEquals(8, crypto.kdfParams.r)
        Assert.assertEquals("80132842c6cde8f9d04582932ef92c3cad3ba6b41e1296ef681692372886db86", crypto.kdfParams.salt)
    }

    @Test
    fun testReadWalletWithPrivateKeyType() {
        val classLoader = javaClass.classLoader.getResource("wallet_private_key.json")
        val uri = classLoader.toURI()
        val key = KeystoreKey(uri)

        Assert.assertEquals("2ea9acf7-17ac-48f7-b2fb-c16e10036f06", key.id)
        Assert.assertEquals(3, key.version)
        Assert.assertEquals(WalletType.PRIVATE_KEY, key.type)
        Assert.assertNull(key.coin)
        Assert.assertEquals("0x80ef37236418320c0f7a55a84ccaa7e080cdfb17", key.address?.hex)
        Assert.assertEquals("", key.passphrase)

        val crypto = key.crypto

        Assert.assertEquals("aes-128-ctr", crypto.cipher)
        Assert.assertEquals("d6a9dcc312649a4c177cdc458b51d249d901df24a042b3f818d274d19c5722a8", crypto.cipherText)
        Assert.assertEquals("scrypt", crypto.kdf)
        Assert.assertEquals("bc53e9634f9bb12937f901037215c1bf3c3a12de203eaa26651ffa6b766dad04", crypto.mac)
        Assert.assertEquals("d3bc60744065621cf182824c2d208d05", crypto.cipherParams.iv)
        Assert.assertEquals(32, crypto.kdfParams.dklen)
        Assert.assertEquals(4096, crypto.kdfParams.n)
        Assert.assertEquals(6, crypto.kdfParams.p)
        Assert.assertEquals(8, crypto.kdfParams.r)
        Assert.assertEquals("cc91a01c3ca98351fa7b564cc44777c3f506971ef5ea7030975a4c364958adcb", crypto.kdfParams.salt)
    }

    @Test
    fun testReadMyEtherWallet() {
        val classLoader = javaClass.classLoader.getResource("myetherwallet.uu")
        val uri = classLoader.toURI()
        val key = KeystoreKey(uri)
        Assert.assertEquals("0x8562fcccbae3019f5a716997609b301ac31fe04a", key.address?.hex)
    }

    @Test
    fun testDecryptInvalidPassword() {
        expectedException.expect(CipherException::class.java)
        expectedException.expectMessage("Invalid password")

        val classLoader = javaClass.classLoader.getResource("wallet_private_key.json")
        val uri = classLoader.toURI()
        val key = KeystoreKey(uri)
        key.decrypt(password = "password123")
    }

    @Test
    fun testDecryptPrivateKey() {
        val classLoader = javaClass.classLoader.getResource("wallet_private_key.json")
        val uri = classLoader.toURI()
        val key = KeystoreKey(uri)
        val privateKey = PrivateKey(key.decrypt(password = PASSWORD))
        Assert.assertEquals(WalletType.PRIVATE_KEY, key.type)
        Assert.assertEquals(
            "d6ddd607fb6508cb48cbb0492495be247a3476f4b140473e23a829e722fd4968",
            privateKey.key.toHexStringNoPrefix()
        )
    }

}