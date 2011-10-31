-- |
-- Module      : Crypto.Types.PubKey.DSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
module Crypto.Types.PubKey.DSA
	( Params
	, Signature
	, PublicKey(..)
	, PrivateKey(..)
	) where

-- | Represent DSA parameters namely P, G, and Q.
type Params = (Integer,Integer,Integer)

-- | Represent a DSA signature namely R and S.
type Signature = (Integer,Integer)

-- | Represent a DSA public key.
data PublicKey = PublicKey
	{ public_params :: Params   -- ^ DSA parameters
	, public_y      :: Integer  -- ^ DSA public Y
	} deriving (Show,Read,Eq)

-- | Represent a DSA private key.
--
-- Only x need to be secret.
-- the DSA parameters are publicly shared with the other side.
data PrivateKey = PrivateKey
	{ private_params :: Params   -- ^ DSA parameters
	, private_x      :: Integer  -- ^ DSA private X
	} deriving (Show,Read,Eq)
