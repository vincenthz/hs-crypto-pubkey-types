{-# LANGUAGE DeriveDataTypeable #-}
-- |
-- Module      : Crypto.Types.PubKey.RSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
module Crypto.Types.PubKey.RSA
    ( PublicKey(..)
    , PrivateKey(..)
    , KeyPair(..)
    , private_size
    , private_n
    , toPublicKey
    , toPrivateKey
    ) where

import Data.Data
import Data.ASN1.Types

-- | Represent a RSA public key
data PublicKey = PublicKey
    { public_size :: Int      -- ^ size of key in bytes
    , public_n    :: Integer  -- ^ public p*q
    , public_e    :: Integer  -- ^ public exponant e
    } deriving (Show,Read,Eq,Data,Typeable)

instance ASN1Object PublicKey where
    toASN1 pubKey = \xs -> Start Sequence
                         : IntVal (public_n pubKey)
                         : IntVal (public_e pubKey)
                         : End Sequence
                         : xs
    fromASN1 (Start Sequence:IntVal modulus:IntVal pubexp:End Sequence:xs) =
        Right (PublicKey { public_size = calculate_modulus modulus 1
                         , public_n    = modulus
                         , public_e    = pubexp
                         }
              , xs)
        where calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)
    fromASN1 _ =
        Left "fromASN1: RSA.PublicKey: unexpected format"

-- | Represent a RSA private key.
-- 
-- Only the pub, d fields are mandatory to fill.
--
-- p, q, dP, dQ, qinv are by-product during RSA generation,
-- but are useful to record here to speed up massively
-- the decrypt and sign operation.
--
-- implementations can leave optional fields to 0.
--
data PrivateKey = PrivateKey
    { private_pub  :: PublicKey -- ^ public part of a private key (size, n and e)
    , private_d    :: Integer   -- ^ private exponant d
    , private_p    :: Integer   -- ^ p prime number
    , private_q    :: Integer   -- ^ q prime number
    , private_dP   :: Integer   -- ^ d mod (p-1)
    , private_dQ   :: Integer   -- ^ d mod (q-1)
    , private_qinv :: Integer   -- ^ q^(-1) mod p
    } deriving (Show,Read,Eq,Data,Typeable)

private_size = public_size . private_pub
private_n    = public_n . private_pub
private_e    = public_e . private_pub

instance ASN1Object PrivateKey where
    toASN1 privKey = \xs -> Start Sequence
                          : IntVal 0
                          : IntVal (public_n $ private_pub privKey)
                          : IntVal (public_e $ private_pub privKey)
                          : IntVal (private_d privKey)
                          : IntVal (private_p privKey)
                          : IntVal (private_q privKey)
                          : IntVal (private_dP privKey)
                          : IntVal (private_dQ privKey)
                          : IntVal (fromIntegral $ private_qinv privKey)
                          : End Sequence
                          : xs
    fromASN1 (Start Sequence
             : IntVal 0
             : IntVal n
             : IntVal e
             : IntVal d
             : IntVal p1
             : IntVal p2
             : IntVal pexp1
             : IntVal pexp2
             : IntVal pcoef
             : End Sequence
             : xs) = Right (privKey, xs)
        where calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)
              privKey = PrivateKey
                        { private_pub  = PublicKey { public_size = calculate_modulus n 1
                                                   , public_n    = n
                                                   , public_e    = e
                                                   }
                        , private_d    = d
                        , private_p    = p1
                        , private_q    = p2
                        , private_dP   = pexp1
                        , private_dQ   = pexp2
                        , private_qinv = pcoef
                        }

    fromASN1 _ =
        Left "fromASN1: RSA.PrivateKey: unexpected format"

-- | Represent RSA KeyPair
--
-- note the RSA private key contains already an instance of public key for efficiency
newtype KeyPair = KeyPair PrivateKey
    deriving (Show,Read,Eq,Data,Typeable)

instance ASN1Object KeyPair where
    toASN1 (KeyPair pkey) = toASN1 pkey
    fromASN1 = fmap (\(k,s) -> (KeyPair k, s)) . fromASN1

-- | Public key of a RSA KeyPair
toPublicKey :: KeyPair -> PublicKey
toPublicKey (KeyPair priv) = private_pub priv

-- | Private key of a RSA KeyPair
toPrivateKey :: KeyPair -> PrivateKey
toPrivateKey (KeyPair priv) = priv
