package org.bouncycastle.jcajce.provider.asymmetric.util;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;

public class IESUtil
{
    public static IESParameterSpec guessParameterSpec(BufferedBlockCipher iesBlockCipher, byte[] nonce)
    {
        if (iesBlockCipher == null)
        {
            return new IESParameterSpec(null, null, 128);
        }
        else
        {
            BlockCipher underlyingCipher = iesBlockCipher.getUnderlyingCipher();

            if ("DES".equals(underlyingCipher.getAlgorithmName()) ||
                "RC2".equals(underlyingCipher.getAlgorithmName()) ||
                "RC5-32".equals(underlyingCipher.getAlgorithmName()) ||
                "RC5-64".equals(underlyingCipher.getAlgorithmName()))
            {
                return new IESParameterSpec(null, null, 64, 64, nonce);
            }
            else if ("SKIPJACK".equals(underlyingCipher.getAlgorithmName()))
            {
                return new IESParameterSpec(null, null, 80, 80, nonce);
            }
            else if ("GOST28147".equals(underlyingCipher.getAlgorithmName()))
            {
                return new IESParameterSpec(null, null, 256, 256, nonce);
            }

            return new IESParameterSpec(null, null, 128, 128, nonce);
        }
    }
}
