import DeviceUnlock from "./deviceUnlock";
import MasterPassword from "./masterPassword";
import Passwords from "./passwords";
import Security from "./security";
import Settings from "./settings";
import Updates from "./updates";

const ciphermothModels = {
  deviceUnlock: DeviceUnlock,
  masterPassword: MasterPassword,
  passwords: Passwords,
  security: Security,
  settings: Settings,
  updates: Updates,
};

export default ciphermothModels;
