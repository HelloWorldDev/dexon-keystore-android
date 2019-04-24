package org.dexon.wallet.keystore

import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import java.net.URI

@Suppress("RECEIVER_NULLABILITY_MISMATCH_BASED_ON_JAVA_ANNOTATIONS")
class WalletTest {

    @get:Rule
    val expectedException: ExpectedException = ExpectedException.none()

    @Test
    fun testGetAccount() {
        val fileUri = javaClass.classLoader.getResource("wallet_private_key.json").toURI()
        val key = KeystoreKey(fileUri)
        val wallet = Wallet(fileUri, key)
        val account = wallet.getAccount(password = PASSWORD, coin = CoinType.ETHEREUM)
        Assert.assertEquals(ETH_DERIVATION_PATH, account.derivationPath.toString())
    }

    @Test
    fun testGetAccountWithInvalidKeyType() {
        expectedException.expect(Exception::class.java)
        expectedException.expectMessage("Invalid key type")

        val fileUri = javaClass.classLoader.getResource("wallet_mnemonic.json").toURI()
        val key = KeystoreKey(fileUri)
        val wallet = Wallet(fileUri, key)
        wallet.getAccount(password = PASSWORD, coin = CoinType.ETHEREUM)
    }

    @Test
    fun testGetAccounts() {
        val fileUri = javaClass.classLoader.getResource("wallet_mnemonic.json").toURI()
        val key = KeystoreKey(fileUri)
        val wallet = Wallet(fileUri, key)
        val accounts = wallet.getAccounts(derivationPaths = listOf(
            DerivationPath(ETH_DERIVATION_PATH),
            DerivationPath(DEX_DERIVATION_PATH)
        ), password = PASSWORD)
        Assert.assertEquals(2, accounts.size)
    }

    @Test
    fun testIdentifier() {
        val uri = URI("UTC--2018-07-23T15-42-07.380692005-42000--6E199F01-FA96-4ADF-9A4B-36EE4B1E08C7")
        val key = KeystoreKey("password")
        val wallet = Wallet(uri, key)
        Assert.assertEquals(
            "UTC--2018-07-23T15-42-07.380692005-42000--6E199F01-FA96-4ADF-9A4B-36EE4B1E08C7",
            wallet.identifier
        )
    }

}