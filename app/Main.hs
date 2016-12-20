module Main where

import System.Environment (getArgs)
import PEParser

main :: IO ()
main = do
        args <- getArgs
        filename <- return $ head args
        peFile <- getPEFile filename
        putStrLn $ show peFile



