package org.bouncycastle.pqc.legacy.crypto.mceliece;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

class Utils
{
    static Digest getDigest(String digestName)
    {
        if ("SHA-1".equals(digestName))
        {
            return new SHA1Digest();
        }
        if ("SHA-224".equals(digestName))
        {
            return new SHA224Digest();
        }
        if ("SHA-256".equals(digestName))
        {
            return new SHA256Digest();
        }
        if ("SHA-384".equals(digestName))
        {
            return new SHA384Digest();
        }
        if ("SHA-512".equals(digestName))
        {
            return new SHA512Digest();
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }
}
