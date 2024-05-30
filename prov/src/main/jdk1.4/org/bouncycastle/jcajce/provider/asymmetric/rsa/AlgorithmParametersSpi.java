package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;

public abstract class AlgorithmParametersSpi
    extends java.security.AlgorithmParametersSpi
{
    protected boolean isASN1FormatString(String format)
    {
        return format == null || "ASN.1".equals(format);
    }

    protected AlgorithmParameterSpec engineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == null)
        {
            throw new NullPointerException("argument to getParameterSpec must not be null");
        }

        return localEngineGetParameterSpec(paramSpec);
    }

    protected abstract AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
        throws InvalidParameterSpecException;

    public static class OAEP
        extends AlgorithmParametersSpi
    {
        AlgorithmParameterSpec currentSpec;

        /**
         * Return the PKCS#1 ASN.1 structure RSAES-OAEP-params.
         */
        protected byte[] engineGetEncoded()
        {
            return null;
        }

        protected byte[] engineGetEncoded(
            String format)
        {
            if (isASN1FormatString(format) || "X.509".equalsIgnoreCase(format))
            {
                return engineGetEncoded();
            }

            return null;
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == AlgorithmParameterSpec.class)
            {
                return currentSpec;
            }

            throw new InvalidParameterSpecException("unknown parameter spec passed to OAEP parameters object.");
        }
    
        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            this.currentSpec = paramSpec;
        }
    
        protected void engineInit(
            byte[] params) 
            throws IOException
        {
            try
            {
                RSAESOAEPparams oaepP = RSAESOAEPparams.getInstance(params);

                throw new IOException("Operation not supported");
            }
            catch (ClassCastException e)
            {
                throw new IOException("Not a valid OAEP Parameter encoding.");
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                throw new IOException("Not a valid OAEP Parameter encoding.");
            }
        }
    
        protected void engineInit(
            byte[] params,
            String format)
            throws IOException
        {
            if ("X.509".equalsIgnoreCase(format)
                    || "ASN.1".equalsIgnoreCase(format))
            {
                engineInit(params);
            }
            else
            {
                throw new IOException("Unknown parameter format " + format);
            }
        }
    
        protected String engineToString()
        {
            return "OAEP Parameters";
        }
    }
    
    public static class PSS
        extends AlgorithmParametersSpi
    {  
        PSSParameterSpec currentSpec;
    
        /**
         * Return the PKCS#1 ASN.1 structure RSASSA-PSS-params.
         */
        protected byte[] engineGetEncoded() 
            throws IOException
        {
            PSSParameterSpec    pssSpec = (PSSParameterSpec)currentSpec;
            RSASSAPSSparams     pssP = new RSASSAPSSparams(RSASSAPSSparams.DEFAULT_HASH_ALGORITHM, RSASSAPSSparams.DEFAULT_MASK_GEN_FUNCTION, new ASN1Integer(pssSpec.getSaltLength()), RSASSAPSSparams.DEFAULT_TRAILER_FIELD);

            return pssP.getEncoded(ASN1Encoding.DER);
        }
    
        protected byte[] engineGetEncoded(
            String format)
            throws IOException
        {
            if ("X.509".equalsIgnoreCase(format)
                    || "ASN.1".equalsIgnoreCase(format))
            {
                return engineGetEncoded();
            }
    
            return null;
        }
    
        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == PSSParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return currentSpec;
            }

            throw new InvalidParameterSpecException("unknown parameter spec passed to PSS parameters object.");
        }
    
        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof PSSParameterSpec))
            {
                throw new InvalidParameterSpecException("PSSParameterSpec required to initialise an PSS algorithm parameters object");
            }
    
            this.currentSpec = (PSSParameterSpec)paramSpec;
        }
    
        protected void engineInit(
            byte[] params) 
            throws IOException
        {
            try
            {
                RSASSAPSSparams pssP = RSASSAPSSparams.getInstance(params);
                String hashName = org.bouncycastle.jcajce.util.MessageDigestUtils.getDigestName(
                    pssP.getHashAlgorithm().getAlgorithm());

                currentSpec = new PSSParamSpec(
                                       pssP.getSaltLength().intValue(), hashName);
            }
            catch (ClassCastException e)
            {
                throw new IOException("Not a valid PSS Parameter encoding.");
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                throw new IOException("Not a valid PSS Parameter encoding.");
            }
        }
    
        protected void engineInit(
            byte[] params,
            String format)
            throws IOException
        {
            if (isASN1FormatString(format) || "X.509".equalsIgnoreCase(format))
            {
                engineInit(params);
            }
            else
            {
                throw new IOException("Unknown parameter format " + format);
            }
        }
    
        protected String engineToString()
        {
            return "PSS Parameters";
        }
    }
}
