module Main where

import Data.Word (Word32, Word16)
import System.IO.MMap (mmapFileByteStringLazy)
import System.Environment (getArgs)

import qualified Data.ByteString as B
import qualified Data.Binary.Get as G

main :: IO ()
main = do
        args <- getArgs
        filename <- return $ head args
        bytes <- getFileContents filename
        header <- return $ getPEHeader bytes
        putStrLn ("Header: " ++ (show header))
        
runGetMaybe g i = case G.runGetOrFail g i of
    Left (_,_,_) -> Nothing
    Right (_,_,v) -> Just v
        
getFileContents filename = mmapFileByteStringLazy filename Nothing

data PEHeader = PEHeader {
      signature :: B.ByteString
    , machine :: PEMachine
    , nSections :: Word16
    , datetime :: Word32
    , ofsSymbolTable :: Word32
    , nSymbols :: Word32
    , sizeOptHeader :: Word16
    , characteristics :: Word16
    } deriving (Show, Eq)
    
data PEMachine = PEM_Any | PEM_AM33 | PEM_AMD64 | PEM_ARM |
    PEM_ARMNT | PEM_EBC | PEM_I386 | PEM_IA64 | PEM_M32R | PEM_MIPS16 |
    PEM_MIPSFPU | PEM_MIPSFPU16 | PEM_POWERPC | PEM_POWERPCFP |
    PEM_R4000 | PEM_RISCV32 | PEM_RISCV64 | PEM_RISCV128 | 
    PEM_SH3 | PEM_SH3DSP | PEM_SH4 | PEM_SH5 | PEM_THUMB | PEM_WCEMIPSV2 |
    PEM_Unknown Word16
    deriving (Show, Eq)
    
peMachine 0x0 = PEM_Any
peMachine 0x1d3 = PEM_AM33
peMachine 0x8664 = PEM_AMD64
peMachine 0x1c0 = PEM_ARM
peMachine 0x1c4 = PEM_ARMNT
peMachine 0xebc = PEM_EBC
peMachine 0x14c = PEM_I386
peMachine 0x200 = PEM_IA64
peMachine 0x9041 = PEM_M32R
peMachine 0x266 = PEM_MIPS16
peMachine 0x366 = PEM_MIPSFPU
peMachine 0x466 = PEM_MIPSFPU16
peMachine 0x1f0 = PEM_POWERPC
peMachine 0x1f1 = PEM_POWERPCFP
peMachine 0x166 = PEM_R4000
peMachine 0x5032 = PEM_RISCV32
peMachine 0x5064 = PEM_RISCV64
peMachine 0x5128 = PEM_RISCV128
peMachine 0x1a2 = PEM_SH3
peMachine 0x1a3 = PEM_SH3DSP
peMachine 0x1a6 = PEM_SH4
peMachine 0x1a8 = PEM_SH5
peMachine 0x1c2 = PEM_THUMB
peMachine 0x169 = PEM_WCEMIPSV2
peMachine i = PEM_Unknown i

getPEHeader bytes = let
        offset = G.runGet (do G.skip 0x3c; fromIntegral <$> G.getInt32le) bytes
        readHeader offset = do
            G.skip offset
            PEHeader <$>                     
                G.getByteString 4 <*>
                (peMachine <$> G.getWord16le) <*>
                G.getWord16le <*>
                G.getWord32le <*>
                G.getWord32le <*>
                G.getWord32le <*>
                G.getWord16le <*>
                G.getWord16le 
        in G.runGet (readHeader offset) bytes
        