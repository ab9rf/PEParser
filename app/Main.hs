module Main where

import Data.Word (Word32, Word16, Word8)
import System.IO.MMap (mmapFileByteStringLazy)
import System.Environment (getArgs)

import Data.Binary.Get

import qualified Data.ByteString as B

main :: IO ()
main = do
        args <- getArgs
        filename <- return $ head args
        peFile <- getPEFile filename
        putStrLn $ show peFile

getPEFile :: String -> IO (Maybe PEFile)
getPEFile filename = do
        bytes <- getFileContents filename
        let offset = case (runGet getWord16le bytes) of
                        0x5A4D -> Just $ runGet (do skip 0x3c; fromIntegral <$> getInt32le) bytes
                        0x4E50 -> Just 0
                        _      -> Nothing
         in return $ fmap (readPEFile bytes) offset

readPEFile bytes offset = runGet r bytes
    where r :: Get PEFile
          r = do
                skip offset
                signature <- getByteString 4
                coffheader <- getCOFFHeader
                optHeader <- case (sizeOptHeader coffheader) of
                    0 -> return OptionalHeaderNone
                    _ -> getOptionalHeader
                let pe = PEFile signature coffheader optHeader
                  in return pe


getFileContents filename = mmapFileByteStringLazy filename Nothing

data PEFile = PEFile {
      signature :: B.ByteString
    , coffHeader :: COFFHeader
    , optionalHeader :: OptionalHeader
    } deriving (Show, Eq)

data COFFHeader = COFFHeader {
      machine :: PEMachine
    , nSections :: Word16
    , datetime :: Word32
    , ofsSymbolTable :: Word32
    , nSymbols :: Word32
    , sizeOptHeader :: Word16
    , characteristics :: Word16
    } deriving (Show, Eq)

data OptionalHeader =
      OptionalHeaderNone
    | OptionalHeader32 {
          magic :: Word16
        , majorLinkerVersion :: Word8
        , minorLinkerVersion :: Word8
        , sizeOfCode :: Word32
        , sizeOfInitializedData :: Word32
        , sieszofUninitializedData :: Word32
        , addressOfEntryPoint :: Word32
        , baseOfCode :: Word32
        , baseOfData :: Word32
        }
    | OptionalHeader32P {
          magic :: Word16
        , majorLinkerVersion :: Word8
        , minorLinkerVersion :: Word8
        , sizeOfCode :: Word32
        , sizeOfInitializedData :: Word32
        , sieszofUninitializedData :: Word32
        , addressOfEntryPoint :: Word32
        , baseOfCode :: Word32
    }
    deriving (Show, Eq)

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

getCOFFHeader :: Get COFFHeader
getCOFFHeader = COFFHeader
                    <$> (peMachine <$> getWord16le)  -- Machine
                    <*> getWord16le                  -- NumberOfSections
                    <*> getWord32le                  -- TimeDateStamp
                    <*> getWord32le                  -- PointerToSymbolTable
                    <*> getWord32le                  -- NumberOfSymbols
                    <*> getWord16le                  -- SizeOfOptionalHeader
                    <*> getWord16le                     -- Characteristics

getOptionalHeader :: Get OptionalHeader
getOptionalHeader = do magic <- getWord16le
                       case magic of
                           0x10b -> OptionalHeader32
                                        <$> pure magic          -- Magic
                                        <*> getWord8            -- MajorLinkerVersion
                                        <*> getWord8            -- MinorLinkerVersion
                                        <*> getWord32le         -- SizeOfCode
                                        <*> getWord32le         -- SizeOfInitializedData
                                        <*> getWord32le         -- SizeOfUninitializedData
                                        <*> getWord32le         -- AddressOfEntryPoint
                                        <*> getWord32le         -- BaseOfCode
                                        <*> getWord32le         -- BaseOfData
                           0x20b -> OptionalHeader32P
                                        <$> pure magic          -- Magic
                                        <*> getWord8            -- MajorLinkerVersion
                                        <*> getWord8            -- MinorLinkerVersion
                                        <*> getWord32le         -- SizeOfCode
                                        <*> getWord32le         -- SizeOfInitializedData
                                        <*> getWord32le         -- SizeOfUninitializedData
                                        <*> getWord32le         -- AddressOfEntryPoint
                                        <*> getWord32le         -- BaseOfCode
