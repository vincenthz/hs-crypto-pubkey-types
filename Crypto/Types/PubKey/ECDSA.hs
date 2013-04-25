{-# LANGUAGE DeriveDataTypeable #-}
-- |
-- Module      : Crypto.Types.PubKey.ECDSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Experimental
-- Portability : Excellent
--
module Crypto.Types.PubKey.ECDSA
    ( PrivateNumber
    , PrivateKey(..)
    , PublicKey(..)
    ) where

import qualified Crypto.Types.PubKey.ECC as ECC
import Data.Data

-- | ECDSA Private Number, usually embedded in ECDSA Private Key
type PrivateNumber = Integer

-- | ECDSA Private Key
data PrivateKey = PrivateKey
    { private_params :: ECC.Curve
    , private_d      :: PrivateNumber
    } deriving (Show,Read,Eq,Data,Typeable)

-- | ECDSA Public Key
data PublicKey = PublicKey
    { public_params :: ECC.Curve
    , public_q      :: ECC.Point
    } deriving (Show,Read,Eq,Data,Typeable)
