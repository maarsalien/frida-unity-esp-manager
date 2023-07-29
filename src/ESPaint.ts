type JW = Java.Wrapper;

abstract class ESPaint {
  public static TextPaint: JW;
  public static StrokePaint: JW;
  public static FilledPaint: JW;
  public static textSize = 20;

  public static init() {
    Java.perform(() => {
      const Paint = Java.use('android.graphics.Paint');
      const Color = Java.use('android.graphics.Color');
      const Paint$Style = Java.use('android.graphics.Paint$Style');
      const Paint$Align = Java.use('android.graphics.Paint$Align');

      ESPaint.TextPaint = Paint.$new();
      ESPaint.TextPaint.setStyle(Paint$Style.FILL_AND_STROKE.value);
      ESPaint.TextPaint.setAntiAlias(true);
      ESPaint.TextPaint.setColor(Color.rgb(255, 0, 255));
      ESPaint.TextPaint.setTextAlign(Paint$Align.CENTER.value);
      ESPaint.TextPaint.setStrokeWidth(1.1);
      ESPaint.TextPaint.setTextSize(ESPaint.textSize);

      ESPaint.StrokePaint = Paint.$new();
      ESPaint.StrokePaint.setStrokeWidth(3);
      ESPaint.StrokePaint.setStyle(Paint$Style.STROKE.value);
      ESPaint.StrokePaint.setAntiAlias(true);
      ESPaint.StrokePaint.setColor(Color.rgb(255, 255, 255));

      ESPaint.FilledPaint = Paint.$new();
      ESPaint.FilledPaint.setStyle(Paint$Style.FILL.value);
      ESPaint.FilledPaint.setAntiAlias(true);
      ESPaint.StrokePaint.setStrokeWidth(3);
      ESPaint.FilledPaint.setColor(Color.rgb(255, 0, 255));
    });
  }
}

ESPaint.init();

export default ESPaint;
