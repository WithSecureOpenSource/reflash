
package instrument_package
{
    import flash.display.*;
    import flash.text.*;
    import flash.utils.*;
    import flash.net.*;
    import flash.events.*;
    import flash.system.*;
    import flash.system.Security;
    import mx.utils.*;
    import flash.external.*;
    import instrument_package.*;
    import flash.net.LocalConnection;

	public class Instrument
	{
        public static var doTrace:String = "##TRACE##";
        public static var logHost:String = "##IP_ADDRESS##";
        public static var logPort:String = "##PORT##";
        public static var fakeVersion:String = "##VERSION##";
        public static var fakeOS:String = "##OS##";
        public static var fakePlayerType:String = "##PLAYERTYPE##";
        public static var logArray:ByteArray = null;
        public static var socket:Socket = null;
        public static var maxTrace:int = 5;    // Enough for some string building etc.
        public static var traceDict:Dictionary = null;
        
        public static const CALL_CLOSURE:int = 1;
        public static const CALL_PROPVOID:int = 2;
        public static const CALL_SUPERVOID:int = 3;
        
        public static var flashVersion:String = Capabilities.version;
        public static var osVersion:String = Capabilities.os;
        public static var playerType:String = Capabilities.playerType;
        public static var flashServerString:String = Capabilities.serverString;
        
		public function Instrument()
        {
		}
        
		private static function InjectJs():void
        {
            var createNamespace_js :XML =
            <script>
            <![CDATA[
                function(){
                    try {
                        ##NAMESPACE##
                    } catch(e) {
                        ##NAMESPACE## = new Object(); 
                    }
                }
            ]]>
            </script>
            
            var addFunction_js :XML = 
            <script>
            <![CDATA[
                function(){
                    var exists = false;
                    try {
                        ##NAMESPACE##;
                        exists = true;
                    } catch(e) {
                        exists = false;
                    }

                    if (exists){
                        ##NAMESPACE##.reflash = function(data)
                        {
                            if (!data)
                            {
                                return null;
                            }
                            var url = "/##TAG##/loadBytes";
                            var request = new XMLHttpRequest();
                            request.open("POST", url, false);
                            request.send(data);
                            if (request.status == 400)
                            {
                                return null;
                            }
                            else
                            {
                                return request.responseText;
                            }
                        }
                    };
                }
            ]]>
            </script>
            
            ExternalInterface.call(createNamespace_js);
            ExternalInterface.call(addFunction_js);
		}
        private static function Reflash(bytes:ByteArray):ByteArray
        {
            InjectJs();
            var callFunction_js :XML = 
                <script>
                <![CDATA[
                    function(data)
                    {
                        return ##NAMESPACE##.reflash(data);
                    }
                ]]>
                </script>
                
            var encoded:String = Base64.encode(bytes);
            
            var ret:String = ExternalInterface.call(callFunction_js, encoded);
            
            if (ret != null)
                return Base64.decode(ret);
            else
                return null;
        }
        
        public static function connectHandler(e: Event): void
        {
            trace("connectHandler: " + e);
            socket.writeUTFBytes("Trace");
        }
        public static function dataHandler(e: Event): void
        {
            trace("dataHandler: " + e);
            
            if ((logArray != null) && (logArray.length))
            {
                trace("dataHandler: sending logArray, size: " + logArray.length);
                socket.writeBytes(logArray);
                socket.flush();
                logArray = null;
            }
            else
            {
                trace("dataHandler: empty logArray");
            }
        }
        public static function closeHandler(e: Event): void
        {
            trace("closeHandler: " + e);
        }
        public static function errorHandler(e: Event): void
        {
            trace("errorHandler: " + e);
        }
        public static function securityHandler(e: Event): void
        {
            trace("securityHandler: " + e);
        }
          
        public static function Trace(array:Array, call:String):void
        {
            if (doTrace != "True")
            {
                traceDict[call]++;
                return;
            }
            if (logArray == null)
            {
                logArray = new ByteArray();
            }
            logArray.writeObject(array);
            
            if (!socket)
            {
                socket = new Socket();
                socket.addEventListener(ProgressEvent.SOCKET_DATA, dataHandler);
                socket.addEventListener(Event.CONNECT, connectHandler);
                socket.addEventListener(Event.CLOSE, closeHandler);
                socket.addEventListener(ErrorEvent.ERROR, errorHandler); 
                socket.addEventListener(SecurityErrorEvent.SECURITY_ERROR, securityHandler);
                try {
                    socket.timeout = 600000;
                }
                catch (error:Error) 
                {
                    trace(call + ": Error: cannot set socket.timeout: " + error.message);
                }        
                socket.endian = Endian.BIG_ENDIAN;
                
                Security.allowDomain("*");
                Security.loadPolicyFile("xmlsocket://" + logHost + ":" + logPort);
                
                socket.connect(logHost, parseInt(logPort, 10));
            }
            traceDict[call]++;
        }
            
        // Try to figure out the function name
        public static function GetFunctionName(callee:Function, parent:Object):String
        {
            for each (var m:XML in describeType(parent)..method)
            {
                if (parent[m.@name] == callee) return m.@name;
            }
            return "(Private)";
        }
        
        public static function IsFunction(callee:Function, parent:Object):Boolean
        {
            for each (var m:XML in describeType(parent)..method)
            {
                if (parent[m.@name] == callee) return true;
            }
            return false;
        }
        
        // Dump argument in AMF format
        public static function GetArgumentType(array:Array, index:int, max:int, call:String):String
        {
            var type:String = getQualifiedClassName(array[index]);
            if (type == "builtin.as$0::MethodClosure")
            {
                if (index < max-1)
                {
                    type += ":" + GetFunctionName(array[index], array[index+1]);
                }
                else
                {
                    type += ":(Unknown)";
                }
            }
            return type;
        }
        
        public static function GetArguments(array:Array, call:String):Array
        { 
            var len:int = array.length;
            var ret:Array = new Array((len*2)+1);
            
            ret[0] = call;
			for(var i:int = 0; i < len; i++)
			{
                var type:String = GetArgumentType(array, i, len, call);
                var ba:ByteArray = new ByteArray();
                
                // Store only specific data types, otherwise we might run
                // into troubles with class getters
                if ((type == "String") ||
                    (type == "Number") ||
                    (type == "Boolean") ||
                    (type == "int") ||
                    (type == "uint") ||
                    (type == "Array") ||    // XXX: what if Array contains classes?
                    (type == "Date") ||
                    (type.slice(0,6) == "flash."))
                {
                    try
                    {
                        ba.writeObject(array[i]);
                    }
                    catch (error:Error) 
                    {
                        trace(call + ": Error: cannot write object: " + error.message);
                        ba.writeObject("");
                    }
                }
                // Everything else: first try explicit coercing to ByteArray.
                // If it fails, just write ""
                else
                {
                    try {
                        ba.writeObject(array[i] as ByteArray);
                    }
                    catch (error:Error) 
                    {
                        trace(call + ": Error: cannot coerce as ByteArray: " + error.message);
                        ba.writeObject("");
                    }
                }
                ret[(i*2)+1] = type;
                ret[(i*2)+2] = ba;
			}
            return ret;
        }
        
        // XXX: note that also Capabilities.serverString needs to be handled:
        // URL-encode flashVersion, search for V=encoded(real), replace with
        // V=encoded(fake)
		public static function InstrumentGetProperty(obj:Object, prop:Object):Object
		{
            if ((fakeVersion == "None") && (fakeOS == "None") && (fakePlayerType == "None")) return prop;
            
            var cn:String = getQualifiedClassName(obj);
            
            if (cn == "flash.system::Capabilities")
            {
                if ((fakeVersion != "None") && (prop == flashVersion))
                {
                    return fakeVersion;
                }
                if ((fakeOS != "None") && (prop == osVersion))
                {
                    return fakeOS;
                }
                if ((fakePlayerType != "None") && (prop == playerType))
                {
                    return fakePlayerType;
                }
            }
            return prop;
        }
        
		public static function InstrumentMethodEntry(call:String, array:Array):void
		{
            // Check of the code has already been visited:
            if (traceDict == null) traceDict = new Dictionary();
            if (traceDict[call] !== undefined)
            {
                if (traceDict[call] > maxTrace)
                {
                    return;
                }
            }
            else
            {
                traceDict[call] = 1;
            }
            trace("InstrumentMethodEntry: " + call);
            Trace(GetArguments(array, call), call);
        }
		
		public static function InstrumentStack(call:String, argindex:uint, array:Array):Array
		{
            // Create new array for function arguments
            var len:int = array.length;
            var retArray:Array = new Array(len-argindex);
            
            // Check of the code has already been visited:
            if (traceDict == null) traceDict = new Dictionary();
            if (traceDict[call] !== undefined)
            {
                if (traceDict[call] > maxTrace)
                {
                    return retArray;
                }
            }
            else
            {
                traceDict[call] = 1;
            }
            
            trace("InstrumentStack: " + call);
            
            // Trace arguments
            Trace(GetArguments(array, call), call);
            
            // If no function arguments, just return
            if (len == argindex)
                return null;
            
            // Index for a possible Loader object
            var i_ldr:int = -1;

            var isThis:Boolean = false;
            var callType:int = -1;
            
            // Call closure
            if (call.slice(0, 5) == "call:")
            {
                callType = CALL_CLOSURE;
                i_ldr = 1;
                // false if MethodClosure is a reference to super class (getsuper)
                try
                {
                    isThis = IsFunction(array[0], array[1]);
                }
                catch (error:Error) 
                {
                    trace(call + ": Error: " + error.message);
                    isThis = false;
                }
            }
            // Other calls
            if (call.slice(0, 13) == "callpropvoid:")
            {
                callType = CALL_PROPVOID;
                i_ldr = 0;
            }
            if (call.slice(0, 14) == "callsupervoid:")
            {
                callType = CALL_SUPERVOID;
                i_ldr = 0;
            }

            if (i_ldr != -1)
            {
                var cl:String = "flash.display::Loader";
                var sn:String = getQualifiedSuperclassName(array[i_ldr]);
                var cn:String = getQualifiedClassName(array[i_ldr]);
                
                // case 1: callsupervoid with flash.display::Loader superclass
                // case 2: closure call with MethodClosure not found from called object
                // case 3: all calls with flash.display::Loader as a called object
                
                if (((callType == CALL_SUPERVOID) && (sn == cl)) ||
                    ((callType == CALL_CLOSURE) && (sn == cl) && (isThis == false)) ||
                    ((callType != -1) && (cn == cl)))
                {
                    var ret:ByteArray = null;
                    try {
                        ret = Reflash(array[argindex] as ByteArray); // SWF as first argument?

                    } catch (e:Error) {
                        trace("Reflash: " + e);
                    }
                    if (ret != null)
                    {
                        retArray[0] = ret;
                    }
                }
            }
            
            // Reverse the array, so we just pop() to the original function
            return retArray.reverse();
        }
	}
}



