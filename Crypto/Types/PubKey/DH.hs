{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |
-- Module      : Crypto.Types.PubKey.DH
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
module Crypto.Types.PubKey.DH
	( Params
	, PublicNumber(..)
	, PrivateNumber(..)
	, SharedKey(..)
	) where

-- | Represent Diffie Hellman parameters namely P (prime), and G (generator).
type Params = (Integer,Integer)

-- | Represent Diffie Hellman public number Y.
newtype PublicNumber = PublicNumber Integer
	deriving (Show,Read,Eq,Enum,Real,Num,Ord)

-- | Represent Diffie Hellman private number X.
newtype PrivateNumber = PrivateNumber Integer
	deriving (Show,Read,Eq,Enum,Real,Num,Ord)

-- | Represent Diffie Hellman shared secret.
newtype SharedKey = SharedKey Integer
	deriving (Show,Read,Eq,Enum,Real,Num,Ord)
