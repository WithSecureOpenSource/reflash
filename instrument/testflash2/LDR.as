package testflash2
{ 
	import flash.display.*;
	import flash.text.*;
	import flash.utils.*;
	import flash.net.*;
	import flash.events.*;
    import flash.system.*;
    
    public class LDR extends Loader
    {
        private var fsdfsdf7s:String = "loadBytes";
        public function LDR()
        {
            super();
        }
        
        public override function loadBytes(bytes:ByteArray, context:LoaderContext = null): void
        {
            super[fsdfsdf7s](bytes, context); 
        }
    }
}
