{-# LANGUAGE DeriveDataTypeable #-}
-- |
-- Module      : Crypto.Types.PubKey.DSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
module Crypto.Types.PubKey.DSA
    ( Params(..)
    , Signature
    , PublicNumber
    , PublicKey(..)
    , PrivateNumber
    , PrivateKey(..)
    , KeyPair(..)
    , toPublicKey
    , toPrivateKey
    ) where

import Data.Data

type PublicNumber = Integer
type PrivateNumber = Integer

-- | Represent DSA parameters namely P, G, and Q.
data Params = Params
    { params_p :: Integer
    , params_g :: Integer
    , params_q :: Integer
    } deriving (Show,Read,Eq,Data,Typeable)

-- | Represent a DSA signature namely R and S.
type Signature = (Integer,Integer)

-- | Represent a DSA public key.
data PublicKey = PublicKey
    { public_params :: Params       -- ^ DSA parameters
    , public_y      :: PublicNumber -- ^ DSA public Y
    } deriving (Show,Read,Eq,Data,Typeable)

-- | Represent a DSA private key.
--
-- Only x need to be secret.
-- the DSA parameters are publicly shared with the other side.
data PrivateKey = PrivateKey
    { private_params :: Params        -- ^ DSA parameters
    , private_x      :: PrivateNumber -- ^ DSA private X
    } deriving (Show,Read,Eq,Data,Typeable)

-- | Represent a DSA key pair
data KeyPair = KeyPair Params PublicNumber PrivateNumber
    deriving (Show,Read,Eq,Data,Typeable)

-- | Public key of a DSA Key pair
toPublicKey :: KeyPair -> PublicKey
toPublicKey (KeyPair params pub _) = PublicKey params pub

-- | Private key of a DSA Key pair
toPrivateKey :: KeyPair -> PrivateKey
toPrivateKey (KeyPair params _ priv) = PrivateKey params priv
