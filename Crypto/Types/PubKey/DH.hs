{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveDataTypeable #-}
-- |
-- Module      : Crypto.Types.PubKey.DH
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
module Crypto.Types.PubKey.DH
    ( Params(..)
    , PublicNumber(..)
    , PrivateNumber(..)
    , SharedKey(..)
    ) where

import Data.Data

-- | Represent Diffie Hellman parameters namely P (prime), and G (generator).
data Params = Params
    { param_p :: Integer
    , param_g :: Integer
    } deriving (Show,Read,Eq,Data,Typeable)

-- | Represent Diffie Hellman public number Y.
newtype PublicNumber = PublicNumber Integer
    deriving (Show,Read,Eq,Enum,Real,Num,Ord)

-- | Represent Diffie Hellman private number X.
newtype PrivateNumber = PrivateNumber Integer
    deriving (Show,Read,Eq,Enum,Real,Num,Ord)

-- | Represent Diffie Hellman shared secret.
newtype SharedKey = SharedKey Integer
    deriving (Show,Read,Eq,Enum,Real,Num,Ord)
