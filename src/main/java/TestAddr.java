import org.bitcoinj.core.Address;
import org.bitcoinj.params.MainNetParams;

import java.lang.reflect.Array;
import java.util.Arrays;

public class TestAddr {

    public void addr() {
        Address a = Address.fromBase58(KMDParams.get(), "RHZmD7XqX7Xfs4mqhLCrd58MWQkqGkkQsM");
        System.out.println("test=" + Arrays.toString(a.getHash160()));
    }

    private static class KMDParams extends MainNetParams {
        KMDParams() {
            super();
            addressHeader = 0x3c;
            p2shHeader = 0x55;
            dumpedPrivateKeyHeader = 0xbc;
            acceptableAddressCodes = new int[] {addressHeader, p2shHeader};
            id = "org.bitcoingold.production";
        }
    }
}
