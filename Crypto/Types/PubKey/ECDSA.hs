{-# LANGUAGE DeriveDataTypeable #-}
-- |
-- Module      : Crypto.Types.PubKey.ECDSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Experimental
-- Portability : Excellent
--
module Crypto.Types.PubKey.ECDSA
    ( Signature(..)
    , PublicPoint
    , PublicKey(..)
    , PrivateNumber
    , PrivateKey(..)
    , KeyPair(..)
    , toPublicKey
    , toPrivateKey
    ) where

import Crypto.Types.PubKey.ECC
import Data.Data

-- | ECDSA Public Point, usually embedded in ECDSA Public Key.
type PublicPoint = Point

-- | ECDSA Private Number, usually embedded in ECDSA Private Key.
type PrivateNumber = Integer

-- | Represent a ECDSA signature namely R and S.
data Signature = Signature
    { sign_r :: Integer -- ^ ECDSA r
    , sign_s :: Integer -- ^ ECDSA s
    } deriving (Show,Read,Eq,Data,Typeable)

-- | ECDSA Private Key.
data PrivateKey = PrivateKey
    { private_curve :: Curve
    , private_d     :: PrivateNumber
    } deriving (Show,Read,Eq,Data,Typeable)

-- | ECDSA Public Key.
data PublicKey = PublicKey
    { public_curve :: Curve
    , public_q     :: PublicPoint
    } deriving (Show,Read,Eq,Data,Typeable)

data KeyPair = KeyPair Curve PublicPoint PrivateNumber
    deriving (Show,Read,Eq,Data,Typeable)

-- | Public key of a ECDSA Key pair.
toPublicKey :: KeyPair -> PublicKey
toPublicKey (KeyPair curve pub _) = PublicKey curve pub

-- | Private key of a ECDSA Key pair.
toPrivateKey :: KeyPair -> PrivateKey
toPrivateKey (KeyPair curve _ priv) = PrivateKey curve priv
