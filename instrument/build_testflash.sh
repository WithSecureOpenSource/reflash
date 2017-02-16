
~/apache-flex-sdk-4.15.0-bin/bin/mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. simple/simple.as

cp simple/simple.swf testflash/


~/apache-flex-sdk-4.15.0-bin/bin/mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. testflash/testflash.as

cp testflash/testflash.swf testflash1/

~/apache-flex-sdk-4.15.0-bin/bin/mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. testflash1/testflash1.as

cp testflash1/testflash1.swf testflash2/

~/apache-flex-sdk-4.15.0-bin/bin/mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. testflash2/testflash2.as
cp testflash2/testflash2.swf ../framework/unittest.swf



