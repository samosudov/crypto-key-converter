package work.samosudov

import com.google.common.base.Splitter
import org.bitcoinj.core.*
import org.bitcoinj.crypto.ChildNumber
import org.bitcoinj.crypto.ChildNumber.HARDENED_BIT
import org.bitcoinj.params.MainNetParams
import org.bitcoinj.wallet.DefaultKeyChainFactory
import org.bitcoinj.wallet.DeterministicKeyChain
import org.bitcoinj.wallet.DeterministicKeyChain.ACCOUNT_ZERO_PATH
import org.bitcoinj.wallet.DeterministicSeed
import org.bitcoinj.wallet.KeyChainGroup
import java.math.BigInteger
import java.security.SecureRandom
import org.bitcoinj.crypto.DeterministicHierarchy
import org.bitcoinj.crypto.DeterministicKey
import org.bitcoinj.wallet.DeterministicKeyChain.EXTERNAL_PATH
import org.spongycastle.asn1.ua.DSTU4145NamedCurves.params



class KeyConverter {

    private val MNEMONIC_WORDS_COUNT = 12
    private val TYPE_NOT_SET = 0
    private val TYPE_MNEMONIC = 1
    private val TYPE_XPRV = 2
    private val TYPE_PRIVKEY = 3
    private val TYPE_WIF = 4
    private var typeOfKey = TYPE_NOT_SET
    private var currentKey = ""

    /**
     * mainKey - might be mnemonic (seed), xprv, private key or wif
     *
     */
    constructor(mainKey: String) {
        currentKey = mainKey.trim()
        if (currentKey.isEmpty()) return
        val listWords = Splitter.on(" ").splitToList(currentKey)

        if (listWords.size == MNEMONIC_WORDS_COUNT) typeOfKey = TYPE_MNEMONIC

        if (listWords.size != 1) return

        if (currentKey.subSequence(0, 3) == "xprv") typeOfKey = TYPE_XPRV

        try {
            BigInteger(currentKey, 16)
            typeOfKey = TYPE_PRIVKEY
        } catch (e: Exception) {
            e.printStackTrace()
        }

        if (currentKey.length in 51..52) typeOfKey = TYPE_WIF
    }

    fun getSeed(): String {
        return when (typeOfKey) {
            TYPE_NOT_SET -> throw KeyConverterException("Type of key not set")
            TYPE_MNEMONIC -> currentKey
            TYPE_XPRV -> throw KeyConverterException("Getting seed mnemonic from xprv is imposible")
            TYPE_PRIVKEY -> throw KeyConverterException("Getting seed mnemonic from private key is imposible")
            TYPE_WIF -> throw KeyConverterException("Getting seed mnemonic from wif is imposible")
            else -> throw KeyConverterException("Type of key incorrect")
        }
    }

    fun getXprv(): String {
        return when (typeOfKey) {
            TYPE_NOT_SET -> throw KeyConverterException("Type of key not set")
            TYPE_MNEMONIC -> getXprvFromSeed()
            TYPE_XPRV -> currentKey
            TYPE_PRIVKEY -> getPrivFromXprv()
            TYPE_WIF -> getWifFromXprv()
            else -> throw KeyConverterException("Type of key incorrect")
        }
    }

    fun getXprvFromSeed(): String {
        return getDkFromSeed().serializePrivB58(MainNetParams.get())
    }

    private fun getPrivFromXprv(): String {
        return getDkFromXprv().privateKeyAsHex
    }

    private fun getPrivFromXprv(dk: DeterministicKey): String {
        return dk.privateKeyAsHex
    }

    private fun getWifFromXprv(): String {
        return getDkFromXprv().getPrivateKeyAsWiF(MainNetParams.get())
    }

    private fun getDkFromSeed(): DeterministicKey {
        val activeKeyChain = DefaultKeyChainFactory().makeKeyChain(null,
            null,
            DeterministicSeed(currentKey, null, "", 0L),
            null,
            false)

        return activeKeyChain.getWatchingKey()
    }

    private fun getDkFromXprv(): DeterministicKey {
        val dh = DeterministicHierarchy(DeterministicKey.deserializeB58(currentKey, MainNetParams.get()))
        return dh.deriveChild(EXTERNAL_PATH, false, true, ChildNumber.ZERO)
    }

    fun getPriv(): String {
        return when (typeOfKey) {
            TYPE_NOT_SET -> throw KeyConverterException("Type of key not set")
            TYPE_MNEMONIC -> getPrivFromSeed()
            TYPE_XPRV -> getPrivFromXprv()
            TYPE_PRIVKEY -> currentKey
            TYPE_WIF -> getWifFromPriv()
            else -> throw KeyConverterException("Type of key incorrect")
        }
    }

    private fun getPrivFromSeed(): String {
        return getPrivFromXprv(getDkFromSeed())
    }

    private fun getWifFromPriv(): String {
        val version = MainNetParams.get().dumpedPrivateKeyHeader
        val bytes = Utils.HEX.decode(currentKey)
        // A stringified buffer is:
        //   1 byte version + data bytes + 4 bytes check code (a truncated hash)
        val addressBytes = ByteArray(1 + bytes.size + 4)
        addressBytes[0] = version.toByte()
        System.arraycopy(bytes, 0, addressBytes, 1, bytes.size)
        val checksum = Sha256Hash.hashTwice(addressBytes, 0, bytes.size + 1)
        System.arraycopy(checksum, 0, addressBytes, bytes.size + 1, 4)
        return Base58.encode(addressBytes)
    }

    fun getWif(): String {
        return when (typeOfKey) {
            TYPE_NOT_SET -> throw KeyConverterException("Type of key not set")
            TYPE_MNEMONIC -> getWifFromSeed()
            TYPE_XPRV -> getWifFromXprv()
            TYPE_PRIVKEY -> getWifFromPriv()
            TYPE_WIF -> currentKey
            else -> throw KeyConverterException("Type of key incorrect")
        }
    }

    fun getWifFromSeed(): String {
        return ""
    }

}