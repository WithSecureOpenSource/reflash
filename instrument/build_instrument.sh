
mxmlc -omit-trace-statements=false -static-link-runtime-shared-libraries=true -compiler.source-path=. instrument_package/Instrument.as

cp instrument_package/Instrument.swf ../framework/Instrument.swf.template



