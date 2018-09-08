-- |
-- Module      : Crypto.Hash.MD5
-- License     : BSD-style
-- Maintainer  : Herbert Valerio Riedel <hvr@gnu.org>
-- Stability   : stable
-- Portability : unknown
--
-- A module containing <https://en.wikipedia.org/wiki/MD5 MD5> bindings
--
module Crypto.Hash.MD5
    (

    -- * Incremental API
    --
    -- | This API is based on 4 different functions, similar to the
    -- lowlevel operations of a typical hash:
    --
    --  - 'init': create a new hash context
    --  - 'update': update non-destructively a new hash context with a strict bytestring
    --  - 'updates': same as update, except that it takes a list of strict bytestrings
    --  - 'finalize': finalize the context and returns a digest bytestring.
    --
    -- all those operations are completely pure, and instead of
    -- changing the context as usual in others language, it
    -- re-allocates a new context each time.
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.MD5 as MD5
    -- >
    -- > main = print digest
    -- >   where
    -- >     digest = MD5.finalize ctx
    -- >     ctx    = foldl MD5.update ctx0 (map Data.ByteString.pack [ [1,2,3], [4,5,6] ])
    -- >     ctx0   = MD5.init

      Ctx(..)
    , init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , updates  -- :: Ctx -> [ByteString] -> Ctx
    , finalize -- :: Ctx -> ByteString
    , start    -- :: ByteString -> Ctx
    , startlazy-- :: L.ByteString -> Ctx

    -- * Single Pass API
    --
    -- | This API use the incremental API under the hood to provide
    -- the common all-in-one operations to create digests out of a
    -- 'ByteString' and lazy 'L.ByteString'.
    --
    --  - 'hash': create a digest ('init' + 'update' + 'finalize') from a strict 'ByteString'
    --  - 'hashlazy': create a digest ('init' + 'update' + 'finalize') from a lazy 'L.ByteString'
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.MD5 as MD5
    -- >
    -- > main = print $ MD5.hash (Data.ByteString.pack [0..255])
    --
    -- __NOTE__: The returned digest is a binary 'ByteString'. For
    -- converting to a base16/hex encoded digest the
    -- <https://hackage.haskell.org/package/base16-bytestring base16-bytestring>
    -- package is recommended.

    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: L.ByteString -> ByteString

    -- ** HMAC-MD5
    --
    -- | <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
    -- <https://en.wikipedia.org/wiki/HMAC HMAC>-MD5 digests

    , hmac     -- :: ByteString -> ByteString -> ByteString
    , hmaclazy -- :: ByteString -> L.ByteString -> ByteString
    ) where

import Prelude hiding (init)
import Foreign.C.Types
import Foreign.Ptr
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, toForeignPtr, memcpy)
import Data.Bits (xor)
import Data.Word
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | perform IO for hashes that do allocation and ffi.
-- unsafeDupablePerformIO is used when possible as the
-- computation is pure and the output is directly linked
-- to the input. we also do not modify anything after it has
-- been returned to the user.
unsafeDoIO :: IO a -> a
unsafeDoIO = unsafeDupablePerformIO

-- | MD5 Context
--
-- The context data is exactly 88 bytes long, however
-- the data in the context is stored in host-endianness.
--
-- The context data is made up of
--
--  * a 'Word64' representing the number of bytes already feed to hash algorithm so far,
--
--  * a 64-element 'Word8' buffer holding partial input-chunks, and finally
--
--  * a 4-element 'Word32' array holding the current work-in-progress digest-value.
--
-- Consequently, a MD5 digest as produced by 'hash', 'hashlazy', or 'finalize' is 16 bytes long.
newtype Ctx = Ctx ByteString
  deriving (Eq)

-- keep this synchronised with cbits/md5.h
{-# INLINE digestSize #-}
digestSize :: Int
digestSize = 16

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 88

{-# INLINE withByteStringPtr #-}
withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =
    withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

copyCtx :: Ptr Ctx -> Ptr Ctx -> IO ()
copyCtx dst src = memcpy (castPtr dst) (castPtr src) (fromIntegral sizeCtx)

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx ctxB) f = Ctx `fmap` createCtx
  where
    createCtx = create sizeCtx $ \dstPtr ->
                withByteStringPtr ctxB $ \srcPtr -> do
                    copyCtx (castPtr dstPtr) (castPtr srcPtr)
                    f (castPtr dstPtr)

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx ctxB) f =
    allocaBytes sizeCtx $ \dstPtr ->
    withByteStringPtr ctxB $ \srcPtr -> do
        copyCtx (castPtr dstPtr) (castPtr srcPtr)
        f (castPtr dstPtr)

withCtxNew :: (Ptr Ctx -> IO ()) -> IO Ctx
withCtxNew f = Ctx `fmap` create sizeCtx (f . castPtr)

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = allocaBytes sizeCtx (f . castPtr)

foreign import ccall unsafe "md5.h hs_cryptohash_md5_init"
    c_md5_init :: Ptr Ctx -> IO ()

foreign import ccall unsafe "md5.h hs_cryptohash_md5_update"
    c_md5_update_unsafe :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()

foreign import ccall safe "md5.h hs_cryptohash_md5_update"
    c_md5_update_safe :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()

-- 'safe' call overhead neglible for 16KiB and more
c_md5_update :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()
c_md5_update pctx pbuf sz
  | sz < 16384 = c_md5_update_unsafe pctx pbuf sz
  | otherwise  = c_md5_update_safe   pctx pbuf sz

foreign import ccall unsafe "md5.h hs_cryptohash_md5_finalize"
    c_md5_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_md5_update ptr (castPtr cs) (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr = create digestSize (c_md5_finalize ptr)

{-# NOINLINE init #-}
-- | create a new hash context
init :: Ctx
init = unsafeDoIO $ withCtxNew $ c_md5_init

validCtx :: Ctx -> Bool
validCtx (Ctx b) = B.length b == sizeCtx

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d
  | validCtx ctx = unsafeDoIO $ withCtxCopy ctx $ \ptr -> updateInternalIO ptr d
  | otherwise    = error "MD5.update: invalid Ctx"

{-# NOINLINE updates #-}
-- | updates a context with multiple bytestrings
updates :: Ctx -> [ByteString] -> Ctx
updates ctx d
  | validCtx ctx = unsafeDoIO $ withCtxCopy ctx $ \ptr -> mapM_ (updateInternalIO ptr) d
  | otherwise    = error "MD5.updates: invalid Ctx"

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring (16 bytes)
finalize :: Ctx -> ByteString
finalize ctx
  | validCtx ctx = unsafeDoIO $ withCtxThrow ctx finalizeInternalIO
  | otherwise    = error "MD5.finalize: invalid Ctx"

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring (16 bytes)
hash :: ByteString -> ByteString
hash d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_md5_init ptr >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE start #-}
-- | hash a strict bytestring into a 'Ctx'
start :: ByteString -> Ctx
start d = unsafeDoIO $ withCtxNew $ \ptr -> do
    c_md5_init ptr >> updateInternalIO ptr d

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring (16 bytes)
hashlazy :: L.ByteString -> ByteString
hashlazy l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_md5_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr

{-# NOINLINE startlazy #-}
-- | hash a lazy bytestring into a 'Ctx'
startlazy :: L.ByteString -> Ctx
startlazy l = unsafeDoIO $ withCtxNew $ \ptr -> do
    c_md5_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l)

{-# NOINLINE hmac #-}
-- | Compute 16-byte <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
-- HMAC-Md5 digest for a strict bytestring message
--
-- @since 0.11.100.0
hmac :: ByteString -- ^ secret
     -> ByteString -- ^ message
     -> ByteString
hmac secret msg = hash $ B.append opad (hash $ B.append ipad msg)
  where
    opad = B.map (xor 0x5c) k'
    ipad = B.map (xor 0x36) k'

    k'  = B.append kt pad
    kt  = if B.length secret > 64 then hash secret else secret
    pad = B.replicate (64 - B.length kt) 0


{-# NOINLINE hmaclazy #-}
-- | Compute 16-byte <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
-- HMAC-MD5 digest for a lazy bytestring message
--
-- @since 0.11.100.0
hmaclazy :: ByteString   -- ^ secret
         -> L.ByteString -- ^ message
         -> ByteString
hmaclazy secret msg = hash $ B.append opad (hashlazy $ L.append ipad msg)
  where
    opad = B.map (xor 0x5c) k'
    ipad = L.fromChunks [B.map (xor 0x36) k']

    k'  = B.append kt pad
    kt  = if B.length secret > 64 then hash secret else secret
    pad = B.replicate (64 - B.length kt) 0
