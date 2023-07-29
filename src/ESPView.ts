Java.perform(() => {
  const View = Java.use('android.view.View');
  const Color = Java.use('android.graphics.Color');
  const PorterDuff$Mode = Java.use('android.graphics.PorterDuff$Mode');

  Java.registerClass({
    name: 'com.maars.ESPView',
    superClass: View,
    methods: {
      $init: [
        {
          returnType: 'void',
          argumentTypes: ['android.content.Context'],
          implementation(context: Java.Wrapper) {
            this.$super.$init(context);
            this.setFocusable(false);
            this.setLayerType(View.LAYER_TYPE_SOFTWARE.value, null);
            this.setBackgroundColor(Color.TRANSPARENT.value);
          },
        },
      ],
      clearCanvas: [
        {
          returnType: 'void',
          argumentTypes: ['android.graphics.Canvas'],
          implementation(canvas: Java.Wrapper) {
            canvas.drawColor(Color.TRANSPARENT.value, PorterDuff$Mode.CLEAR.value);
          },
        },
      ],
    },
  });
});
