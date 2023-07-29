import './ESPView.js';
import ESPaint from './ESPaint.js';
import ESPManager from './ESPManager.js';
import OFS from './Offset.js';
import { getActivity, getScreenResolution, ensureModulesInitialized, sleep } from './utils.js';
import { log } from './Logger.js';

const modulesList = ['libil2cpp.so', 'libunity.so', 'libmain.so'];

const APP_MAIN_ACTIVITY = 'com.unity3d.player.UnityPlayerActivity';
const MILLISECONDS_IN_ONE_SECOND = 1000;
const ESP_FPS = 30;
const ESP_REFRESH_RATE = MILLISECONDS_IN_ONE_SECOND / ESP_FPS;

let il2cpp = null as unknown as NativePointer;
const espManager = new ESPManager();

Java.perform(async () => {
  await sleep(2000);
  await ensureModulesInitialized(...modulesList);
  il2cpp = Module.findBaseAddress('libil2cpp.so') as NativePointer;
  main().catch((e) => console.error(e));
});

async function main() {
  let espBox = true;
  let isEspLine = true;
  // let espHealth = false;
  // let espName = false;
  let espPlayerCount = true;
  let isEspEnabled = true;

  const ESPView = Java.use('com.maars.ESPView');

  const MainActivity = await getActivity(APP_MAIN_ACTIVITY);
  if (!MainActivity) throw new Error('MainActivity not found!');

  // const [SCREEN_WIDTH, SCREEN_HEIGHT] = getScreenResolution();

  const espView = ESPView.$new(MainActivity);
  const rootView = Java.cast(MainActivity.getWindow().getDecorView().getRootView(), Java.use('android.view.ViewGroup'));

  Java.scheduleOnMainThread(() => {
    rootView.addView(espView);
    espView.postInvalidate();
  });

  setInterval(() => espView.postInvalidate(), ESP_REFRESH_RATE);

  /*
   * Hooks
   */
  Interceptor.attach(il2cpp.add(OFS.CEnemyBase.Update), {
    onEnter(args) {
      espManager.tryAddEnemy(args[0]);
    },
  });

  const position = Vector3();
  const screenPoint = Vector3();

  espView.onDraw.implementation = function (canvas: Java.Wrapper) {
    // espView.clearCanvas(canvas);
    canvas.drawText('moded with frida', 80, 20, ESPaint.TextPaint);

    if (!isEspEnabled) return this.onDraw(canvas);

    for (let i = 1; i < espManager.getEnemiesCount(); i++) {
      const enemy = espManager.enemies[i];

      if (IsPlayerDead(enemy)) {
        espManager.tryRemoveEnemy(enemy);
        continue;
      }

      get_position_Injected(get_transform(enemy), position);
      WorldToScreenPoint_Injected(get_camera(), position, 2, screenPoint);

      const pos = {
        x: screenPoint.add(0x0).readFloat(),
        y: screenPoint.add(0x4).readFloat(),
        z: screenPoint.add(0x8).readFloat(),
      };

      if (pos.z < 1.0) continue;

      const canvasWidth = canvas.getWidth();
      const canvasHeight = canvas.getHeight();

      if (espPlayerCount) {
        const point = { x: canvasWidth / 2, y: 20 };
        canvas.drawText(espManager.getEnemiesCount().toString(), point.x, point.y, ESPaint.TextPaint);
      }

      if (espBox) {
        const boxWidth = 100;
        const boxHeight = 200;
        const boxFrom = { x: canvasWidth - (canvasWidth - pos.x) - boxWidth / 2, y: canvasHeight - pos.y - boxHeight };
        const boxTo = { x: boxFrom.x + boxWidth, y: boxFrom.y + boxHeight };
        canvas.drawRect(boxFrom.x, boxFrom.y, boxTo.x, boxTo.y, ESPaint.StrokePaint);
      }

      if (isEspLine) {
        const drawFrom = { x: canvasWidth / 2, y: 40 };
        const drawTo = { x: canvasWidth - (canvasWidth - pos.x) + 5, y: canvasHeight - pos.y - 50.0 };
        canvas.drawCircle(drawFrom.x, drawFrom.y, 5, ESPaint.FilledPaint);
        canvas.drawCircle(drawTo.x, drawTo.y, 5, ESPaint.FilledPaint);
        canvas.drawLine(drawFrom.x, drawFrom.y, drawTo.x, drawTo.y, ESPaint.StrokePaint);
      }
    }

    // this.onDraw(canvas);
  };
}

function Vector3(x = 0, y = 0, z = 0) {
  const vector = Memory.alloc(0xc);
  new NativeFunction(il2cpp.add(OFS.Vector3.ctor), 'pointer', ['pointer', 'float', 'float', 'float'])(vector, x, y, z);
  return vector;
}

function WorldToScreenPoint_Injected(camera: NativePointer, position: NativePointer, eye: number, out: NativePointer) {
  new NativeFunction(il2cpp.add(OFS.Camera.WorldToScreenPoint_Injected), 'pointer', [
    'pointer',
    'pointer',
    'int',
    'pointer',
  ])(camera, position, eye, out);
}

function get_position_Injected(transform: NativePointer, out: NativePointer) {
  new NativeFunction(il2cpp.add(OFS.Transform.get_position_Injected), 'pointer', ['pointer', 'pointer'])(
    transform,
    out,
  );
}

function get_transform(player: NativePointer) {
  return new NativeFunction(il2cpp.add(OFS.Component.get_transform), 'pointer', ['pointer'])(player);
}

function get_camera() {
  return new NativeFunction(il2cpp.add(OFS.Camera.get_main), 'pointer', [])();
}

function GetHealth(player: NativePointer): number {
  return new NativeFunction(il2cpp.add(OFS.CEnemyBase.get_HealthPercentage), 'float', ['pointer'])(player);
}

function IsPlayerDead(player: NativePointer): boolean {
  return GetHealth(player) <= 0;
}
