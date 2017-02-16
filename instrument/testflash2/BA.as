package testflash2
{ 
	import flash.display.*;
	import flash.text.*;
	import flash.utils.*;
	import flash.net.*;
	import flash.events.*;
    import flash.system.*;
    
    public class BA extends ByteArray
    {
        private var getst:String;
        public var stst:String;
        
        public function BA(gs:String)
        {
            getst = gs;
            stst = "stst";
            super();
        }
        
        public function get st():String
        {
            trace(getst);
            return getst;
        }
    }
}
