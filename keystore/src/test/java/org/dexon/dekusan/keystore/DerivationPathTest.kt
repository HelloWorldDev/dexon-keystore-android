package org.dexon.dekusan.keystore

import org.junit.Assert
import org.junit.Test

class DerivationPathTest {

    @Test
    fun testInitWithIndices() {
        val indices = listOf(
            Index(44, hardened = true),
            Index(60, hardened = true),
            Index(0, hardened = true),
            Index(0, hardened = false),
            Index(0, hardened = false)
        )
        val path = DerivationPath(indices)
        Assert.assertNotNull(path)
        Assert.assertEquals(Index(44, hardened = true), path.indices[0])
        Assert.assertEquals(Index(60, hardened = true), path.indices[1])
        Assert.assertEquals(Index(0, hardened = true), path.indices[2])
        Assert.assertEquals(Index(0, hardened = false), path.indices[3])
        Assert.assertEquals(Index(0, hardened = false), path.indices[4])
        Assert.assertEquals(44, path.purpose)
        Assert.assertEquals(60, path.coinType)
        Assert.assertEquals(0, path.account)
        Assert.assertEquals(0, path.change)
        Assert.assertEquals(0, path.account)
    }

    @Test
    fun testInitWithComponents() {
        val path = DerivationPath(purpose = 44, coinType = 60, account = 0, change = 0, address = 0)
        Assert.assertNotNull(path)
        Assert.assertEquals(Index(44, hardened = true), path.indices[0])
        Assert.assertEquals(Index(60, hardened = true), path.indices[1])
        Assert.assertEquals(Index(0, hardened = true), path.indices[2])
        Assert.assertEquals(Index(0, hardened = false), path.indices[3])
        Assert.assertEquals(Index(0, hardened = false), path.indices[4])
        Assert.assertEquals(44, path.purpose)
        Assert.assertEquals(60, path.coinType)
        Assert.assertEquals(0, path.account)
        Assert.assertEquals(0, path.change)
        Assert.assertEquals(0, path.account)
    }

    @Test
    fun testInitWithString() {
        val path = DerivationPath(ETH_DERIVATION_PATH)
        Assert.assertNotNull(path)
        Assert.assertEquals(Index(44, hardened = true), path.indices[0])
        Assert.assertEquals(Index(60, hardened = true), path.indices[1])
        Assert.assertEquals(Index(0, hardened = true), path.indices[2])
        Assert.assertEquals(Index(0, hardened = false), path.indices[3])
        Assert.assertEquals(Index(0, hardened = false), path.indices[4])
        Assert.assertEquals(44, path.purpose)
        Assert.assertEquals(60, path.coinType)
        Assert.assertEquals(0, path.account)
        Assert.assertEquals(0, path.change)
        Assert.assertEquals(0, path.account)
    }

    @Test(expected = NumberFormatException::class)
    fun testInitInvalid() {
        DerivationPath("a/b/c")
        DerivationPath("m/44'/60''/")
    }

    @Test
    fun testToString() {
        val path = DerivationPath(ETH_DERIVATION_PATH)
        Assert.assertNotNull(path)
        Assert.assertEquals(ETH_DERIVATION_PATH, path.toString())
    }

    @Test
    fun testEquals() {
        val path1 = DerivationPath("m/44'/60'/0'/0/0")
        val path2 = DerivationPath("44'/60'/0'/0/0")
        Assert.assertNotNull(path1)
        Assert.assertNotNull(path2)
        Assert.assertEquals(path1, path2)
    }

}