package org.dexon.dekusan.keystore

import com.google.gson.Gson
import org.apache.commons.io.FileUtils
import org.junit.Assert
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.rules.TemporaryFolder
import org.kethereum.model.PrivateKey
import org.walleth.khex.hexToByteArray
import java.io.File

@Suppress("RECEIVER_NULLABILITY_MISMATCH_BASED_ON_JAVA_ANNOTATIONS")
class KeystoreTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @get:Rule
    val expectedException: ExpectedException = ExpectedException.none()

    private lateinit var folder: File

    @Before
    fun setup() {
        val classLoader = javaClass.classLoader.getResource("wallet_mnemonic.json")
        folder = temporaryFolder.newFolder("KeyStoreTests")
        FileUtils.copyFileToDirectory(File(classLoader.toURI()), folder)
    }

    @Test
    fun testLoadKeystore() {
        val keystore = Keystore(keyDirectory = folder)
        Assert.assertEquals(1, keystore.wallets.size)
    }

    @Test(expected = Test.None::class)
    fun testCreateHDWallet() {
        val derivationPaths = listOf(DerivationPath(ETH_DERIVATION_PATH))
        val keystore = Keystore(keyDirectory = folder)
        val newWallet = keystore.createWallet(password = PASSWORD, derivationPaths = derivationPaths)
        Assert.assertEquals(1, newWallet.accounts.size)
        Assert.assertEquals(2, keystore.wallets.size)
        newWallet.getAccounts(derivationPaths, PASSWORD)
    }

    @Test
    fun testAddAccounts() {
        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.wallets.first { it.type == WalletType.HD_WALLET }
        Assert.assertEquals(0, wallet.accounts.size)

        keystore.addAccounts(wallet, derivationPaths = listOf(
            DerivationPath(ETH_DERIVATION_PATH),
            DerivationPath(DEX_DERIVATION_PATH)
        ), password = PASSWORD)
        val savedKeystore = Keystore(keyDirectory = folder)
        val savedWallet = savedKeystore.wallets.first { it.type == WalletType.HD_WALLET }
        Assert.assertEquals(2, savedWallet.accounts.size)
    }

    @Test(expected = Test.None::class)
    fun testImportKey() {
        val keystore = Keystore(keyDirectory = folder)
        val privateKey = PrivateKey("9cdb5cab19aec3bd0fcd614c5f185e7a1d97634d4225730eba22497dc89a716c".hexToByteArray())
        val key = KeystoreKey(PASSWORD, privateKey, CoinType.ETHEREUM)
        val json = key.toJson()
        val wallet = keystore.import(json, PASSWORD, "newPassword", CoinType.ETHEREUM)
        val account = wallet.getAccount("newPassword", CoinType.ETHEREUM)
        Assert.assertNotNull(keystore.wallets.first { it.type == WalletType.PRIVATE_KEY })
        account.sign("Hello World!".toByteArray(), "newPassword")
    }

    @Test(expected = Test.None::class)
    fun testImportPrivateKey() {
        val keystore = Keystore(keyDirectory = folder)
        val privateKey = PrivateKey("9cdb5cab19aec3bd0fcd614c5f185e7a1d97634d4225730eba22497dc89a716c".hexToByteArray())
        val wallet = keystore.import(privateKey, PASSWORD, CoinType.ETHEREUM)
        Assert.assertEquals(1, wallet.accounts.size)
        val account = wallet.getAccount(PASSWORD, CoinType.ETHEREUM)
        Assert.assertNotNull(keystore.wallets.first { it.type == WalletType.PRIVATE_KEY })
        account.sign("Hello World!".toByteArray(), PASSWORD)
    }

    @Test(expected = Test.None::class)
    fun testImportWallet() {
        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.import(
            mnemonic = "often tobacco bread scare imitate song kind common bar forest yard wisdom",
            passphrase = "TREZOR",
            encryptPassword = "newPassword",
            derivationPath = DerivationPath(ETH_DERIVATION_PATH)
        )
        Assert.assertEquals(1, wallet.accounts.size)
        val account = wallet.getAccounts(
            derivationPaths = listOf(DerivationPath(ETH_DERIVATION_PATH)),
            password = "newPassword"
        ).first()
        Assert.assertNotNull(keystore.wallets.first { it.type == WalletType.HD_WALLET })
        account.sign("Hello World!".toByteArray(), "newPassword")
    }

    @Test
    fun testImportWalletWithMultipleDerivationPaths() {
        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.import(
            mnemonic = "often tobacco bread scare imitate song kind common bar forest yard wisdom",
            passphrase = "TREZOR",
            encryptPassword = "newPassword",
            derivationPaths = listOf(
                DerivationPath(ETH_DERIVATION_PATH),
                DerivationPath(DEX_DERIVATION_PATH)
            )
        )
        Assert.assertEquals(2, wallet.accounts.size)
        val account = wallet.getAccounts(
            derivationPaths = listOf(
                DerivationPath(ETH_DERIVATION_PATH),
                DerivationPath(DEX_DERIVATION_PATH)
            ),
            password = "newPassword"
        ).first()
        Assert.assertNotNull(keystore.wallets.first { it.type == WalletType.HD_WALLET })
        account.sign("Hello World!".toByteArray(), "newPassword")
    }

    @Test
    fun testExportJsonForPrivateKey() {
        val privateKey = PrivateKey("9cdb5cab19aec3bd0fcd614c5f185e7a1d97634d4225730eba22497dc89a716c".hexToByteArray())
        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.import(privateKey, PASSWORD, CoinType.ETHEREUM)
        val json = keystore.export(wallet, PASSWORD, "newPassword")
        val exportedKey = Gson().fromJson(json, KeystoreKey::class.java)
        Assert.assertEquals(WalletType.PRIVATE_KEY, exportedKey.type)
        Assert.assertEquals(privateKey.key, PrivateKey(exportedKey.decrypt("newPassword")).key)
    }

    @Test
    fun testExportJsonForMnemonic() {
        val mnemonic = "often tobacco bread scare imitate song kind common bar forest yard wisdom"
        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.import(
            mnemonic,
            "TREZOR",
            "newPassword",
            DerivationPath(ETH_DERIVATION_PATH)
        )
        val json = keystore.export(wallet, "newPassword", "newPassword")
        val exportedKey = Gson().fromJson(json, KeystoreKey::class.java)
        Assert.assertEquals(WalletType.HD_WALLET, exportedKey.type)
        Assert.assertEquals(mnemonic, exportedKey.decrypt("newPassword").toString(Charsets.US_ASCII))
    }

    @Test
    fun testExportPrivateKey() {
        val privateKey = PrivateKey("9cdb5cab19aec3bd0fcd614c5f185e7a1d97634d4225730eba22497dc89a716c".hexToByteArray())
        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.import(privateKey, PASSWORD, CoinType.ETHEREUM)
        val exported = keystore.exportPrivateKey(wallet, password = PASSWORD)
        Assert.assertEquals(privateKey.key, exported.key)
    }

    @Test
    fun testExportMnemonic() {
        val mnemonic = "often tobacco bread scare imitate song kind common bar forest yard wisdom"
        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.import(
            mnemonic,
            passphrase = "TREZOR",
            encryptPassword = "newPassword",
            derivationPath = DerivationPath(ETH_DERIVATION_PATH)
        )
        val exported = keystore.exportMnemonic(wallet, password = "newPassword")
        Assert.assertEquals(mnemonic, exported)
    }

    @Test
    fun testDeleteWallet() {
        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.wallets.first { it.type == WalletType.HD_WALLET }
        keystore.delete(wallet)
        Assert.assertNull(keystore.wallets.firstOrNull { it.type == WalletType.HD_WALLET })
        Assert.assertEquals(0, folder.listFiles().size)
    }

    @Test
    fun testDeleteWalletWithMissingException() {
        expectedException.expect(Exception::class.java)
        expectedException.expectMessage("Missing wallet")

        val keystore = Keystore(keyDirectory = folder)
        val wallet = keystore.wallets.first { it.type == WalletType.HD_WALLET }
        keystore.wallets.remove(wallet)
        File(wallet.keyUri.path).delete()
        keystore.delete(wallet)
    }

}