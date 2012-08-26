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
    ) where

import Data.Data

-- | Represent a RSA public key
data PublicKey = PublicKey
    { public_size :: Int      -- ^ size of key in bytes
    , public_n    :: Integer  -- ^ public p*q
    , public_e    :: Integer  -- ^ public exponant e
    } deriving (Show,Read,Eq,Data,Typeable)

-- | Represent a RSA private key.
-- 
-- Only the sz, n and d fields are mandatory to fill.
--
-- p, q, dP, dQ, qinv are by-product during RSA generation,
-- but are useful to record here to speed up massively
-- the decrypt and sign operation.
--
-- implementations can leave optional fields to 0.
--
data PrivateKey = PrivateKey
    { private_size :: Int     -- ^ size of key in bytes
    , private_n    :: Integer -- ^ private p*q
    , private_d    :: Integer -- ^ private exponant d
    , private_p    :: Integer -- ^ p prime number
    , private_q    :: Integer -- ^ q prime number
    , private_dP   :: Integer -- ^ d mod (p-1)
    , private_dQ   :: Integer -- ^ d mod (q-1)
    , private_qinv :: Integer -- ^ q^(-1) mod p
    } deriving (Show,Read,Eq,Data,Typeable)
