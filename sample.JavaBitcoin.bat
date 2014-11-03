@echo off
REM This is a sample batch file to run the JavaBitcoin program.  Rename it to JavaBitcoin.bat
REM and copy it to a directory in your PATH if you want to use it.  Using the 'java' command
REM to start the node server allows you to watch log messages as they are written to the console.
REM
REM Command line operands:
REM   Start node server using production network
REM       JavaBitcoin prod
REM   Start node server using test network
REM       JavaBitcoin test
REM   Load production block chain from disk (start defaults to 0 and stop defaults to highest block)
REM       JavaBitcoin load prod <start-block> <stop-block>
REM   Load test block chain from disk (start defaults to 0 and stop defaults to highest block)
REM       JavaBitcoin load test <start-block> <stop-block>
REM   Retry a failing block for the production network
REM       JavaBitcoin retry prod block-hash
REM   Retry a failing block for the production network with block verification disabled
REM       JavaBitcoin retry prod noverify block-hash
REM   Retry a failing block for the test network
REM       JavaBitcoin retry test block-hash
REM   Retry a failing block for the test network with block verification disabled
REM       JavaBitcoin retry test noverify block-hash
REM
setlocal
REM Directory containing the disk block chain in the Blocks subdirectory
set Blocks=\Users\user-name\AppData\Roaming\Bitcoin
REM Directory contain leveldbjni.dll
set LibPath=\Bitcoin\JavaBitcoin
REM Jar file to use on the production network
set ProdJar=\Bitcoin\JavaBitcoin\JavaBitcoin-4.0.0.jar
REM Jar file to use on the test network
set TestJar=\Bitcoin\JavaBitcoin\JavaBitcoin-4.0.0.jar

if .%1==.test goto runTest
if .%1==.prod goto runProd
if .%1==.load goto runLoad
if .%1==.retry goto runRetry
echo You must specify 'load', 'retry', 'prod' or 'test'
goto :DONE

:runLoad
if .%2==.test goto loadTest
if .%2==.prod goto loadProd
echo You must specify 'load prod' or 'load test'
goto :DONE

:loadTest
java -Xmx384m -Dbitcoin.verify.blocks=1 -Djava.library.path=%LibPath% -jar "%TestJar%" LOAD TEST "%Blocks%" %3 %4
goto :DONE

:loadProd
java -Xmx384m -Dbitcoin.verify.blocks=0 -Djava.library.path=%LibPath% -jar "%ProdJar%" LOAD PROD "%Blocks%" %3 %4
goto :DONE

:runRetry
if .%2==.test goto retryTest
if .%2==.prod goto retryProd
echo You must specify 'retry prod' or 'retry test'
goto :DONE

:retryTest
if .%3==.noverify goto retryTestNoVerify
java -Xmx384m -Dbitcoin.verify.blocks=1 -Djava.library.path=%LibPath% -jar "%TestJar%" RETRY TEST %3
goto :DONE

:retryTestNoVerify
java -Xmx384m -Dbitcoin.verify.blocks=0 -Djava.library.path=%LibPath% -jar "%TestJar%" RETRY TEST %4
goto :DONE

:retryProd
if .%3==.noverify goto retryProdNoVerify
java -Xmx384m -Dbitcoin.verify.blocks=1 -Djava.library.path=%LibPath% -jar "%ProdJar%" RETRY PROD %3
goto :DONE

:retryProdNoverify
java -Xmx384m -Dbitcoin.verify.blocks=0 -Djava.library.path=%LibPath% -jar "%ProdJar%" RETRY PROD %4
goto :DONE

:runTest
java -Xmx384m -Dbitcoin.verify.blocks=1 -Djava.library.path=%LibPath% -jar "%TestJar%" TEST
goto :DONE

:runProd
java -Xmx512m -Dbitcoin.verify.blocks=1 -Djava.library.path=%LibPath% -jar "%ProdJar%" PROD

:DONE
endlocal
