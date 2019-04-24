package org.dexon.dekusan.keystore

import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.kethereum.bip39.dirtyPhraseToMnemonicWords
import org.kethereum.bip39.toKey
import org.kethereum.hashes.sha256
import org.kethereum.model.PrivateKey
import org.walleth.khex.hexToByteArray
import java.net.URI

class AccountTest {

    @get:Rule
    val expectedException: ExpectedException = ExpectedException.none()

    @Test
    fun testSignHash() {
        val privateKey = PrivateKey("d6ddd607fb6508cb48cbb0492495be247a3476f4b140473e23a829e722fd4968".hexToByteArray())
        val key = KeystoreKey(PASSWORD, privateKey, CoinType.ETHEREUM)
        val wallet = Wallet(URI("/"), key)
        val account = wallet.getAccount(PASSWORD, CoinType.ETHEREUM)
        val hash = "Hello, world!".toByteArray().sha256()
        val result = account.sign(hash, PASSWORD)
        Assert.assertEquals(
            65,
            result.r.toByteArray().size + result.s.toByteArray().size + 1
        )
    }

    @Test
    fun testSignHashHD() {
        val key = KeystoreKey(PASSWORD, MNEMONIC, PASSPHRASE)
        val wallet = Wallet(URI("/"), key)
        val account = wallet.getAccounts(
            derivationPaths = listOf(DerivationPath(ETH_DERIVATION_PATH)),
            password = PASSWORD
        ).first()
        val hash = "Hello, world!".toByteArray().sha256()
        val result = account.sign(hash, PASSWORD)
        Assert.assertEquals(
            65,
            result.r.toByteArray().size + result.s.toByteArray().size + 1
        )
    }

    @Test
    fun testGetPrivateKey() {
        val expectedPrivateKey = PrivateKey("d6ddd607fb6508cb48cbb0492495be247a3476f4b140473e23a829e722fd4968".hexToByteArray())
        val key = KeystoreKey(PASSWORD, expectedPrivateKey, CoinType.ETHEREUM)
        val wallet = Wallet(URI("/"), key)
        val account = wallet.getAccount(PASSWORD, CoinType.ETHEREUM)
        val actualPrivateKey = account.privateKey(PASSWORD)
        Assert.assertEquals(expectedPrivateKey.key, actualPrivateKey.key)
    }

    @Test
    fun testGetPrivateKeyHD() {
        val expectedPrivateKey =
            dirtyPhraseToMnemonicWords(MNEMONIC)
                .toKey(ETH_DERIVATION_PATH)
                .keyPair
                .privateKey
        val key = KeystoreKey(PASSWORD, MNEMONIC, PASSPHRASE)
        val wallet = Wallet(URI("/"), key)
        val account = wallet.getAccounts(
            derivationPaths = listOf(DerivationPath(ETH_DERIVATION_PATH)),
            password = PASSWORD
        ).first()
        val actualPrivateKey = account.privateKey(DerivationPath(ETH_DERIVATION_PATH), PASSWORD)
        Assert.assertEquals(expectedPrivateKey.key, actualPrivateKey.key)
    }

    @Test
    fun testGetPrivateKeys() {
        val expectedPrivateKey =
            dirtyPhraseToMnemonicWords(MNEMONIC)
                .toKey(ETH_DERIVATION_PATH)
                .keyPair
                .privateKey
        val key = KeystoreKey(PASSWORD, MNEMONIC, PASSPHRASE)
        val wallet = Wallet(URI("/"), key)
        val account = wallet.getAccounts(
            derivationPaths = listOf(DerivationPath(ETH_DERIVATION_PATH)),
            password = PASSWORD
        ).first()
        val actualPrivateKey = account.privateKeys(
            derivationPaths = listOf(DerivationPath(ETH_DERIVATION_PATH)),
            password = PASSWORD
        ).first()
        Assert.assertEquals(expectedPrivateKey.key, actualPrivateKey.key)
    }

    @Test
    fun testWalletNullException()  {
        expectedException.expect(Exception::class.java)
        expectedException.expectMessage("Wallet no longer exists")

        val expectedPrivateKey = PrivateKey("d6ddd607fb6508cb48cbb0492495be247a3476f4b140473e23a829e722fd4968".hexToByteArray())
        val key = KeystoreKey(PASSWORD, expectedPrivateKey, CoinType.ETHEREUM)
        val wallet = Wallet(URI("/"), key)
        val account = wallet.getAccount(PASSWORD, CoinType.ETHEREUM)
        account.wallet = null
        account.privateKey(PASSWORD)
    }

    @Test
    fun testWrongWalletType() {
        expectedException.expect(Exception::class.java)
        expectedException.expectMessage("Not HD wallet")

        val expectedPrivateKey = PrivateKey("d6ddd607fb6508cb48cbb0492495be247a3476f4b140473e23a829e722fd4968".hexToByteArray())
        val key = KeystoreKey(PASSWORD, expectedPrivateKey, CoinType.ETHEREUM)
        val wallet = Wallet(URI("/"), key)
        val account = wallet.getAccount(PASSWORD, CoinType.ETHEREUM)
        account.privateKeys(listOf(DerivationPath(ETH_DERIVATION_PATH)), PASSWORD)
    }

}