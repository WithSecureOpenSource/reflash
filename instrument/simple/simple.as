
package simple
{ 
    import flash.display.Sprite; 
    import flash.text.*;
    import flash.utils.*;
 
    public class simple extends Sprite 
    { 
        private var myTextBox:TextField = new TextField(); 
 
        public function simple()
        { 
            doit("Hello Reflash!"); 
        } 

        public function doit(arg:String):void
        {
            addChild(myTextBox); 
            myTextBox.text = arg;
        }
    } 
}
