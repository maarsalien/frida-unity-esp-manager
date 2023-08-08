export default abstract class Offset {
  public static readonly CEnemyBase = {
    Update: 0x117f0c4,
    get_MaxHealth: 0x11806a4,
    get_HealthPercentage: 0x11806ac,
  };

  public static readonly Vector3 = {
    ctor: 0x22ed584,
  };

  public static readonly Component = {
    get_transform: 0x164b0bc,
  };

  public static readonly Camera = {
    get_main: 0x1647024,
    WorldToScreenPoint_Injected: 0x16469e4,
  };

  public static readonly Transform = {
    get_position_Injected: 0x22e7cb0,
  };
}
