
mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. simple/simple.as
cp simple/simple.swf testflash/

mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. testflash/testflash.as
cp testflash/testflash.swf testflash1/

mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. testflash1/testflash1.as
cp testflash1/testflash1.swf testflash2/

mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. testflash2/testflash2.as
cp testflash2/testflash2.swf ../framework/unittest.swf



