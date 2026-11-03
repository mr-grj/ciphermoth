import { useEffect, useState } from "react";

import { onSecurityKeyPrompt } from "../platform/securityKeys";

// While a security key is being asked: ``{ message, pin? }``, otherwise null.
const useSecurityKeyPrompt = () => {
  const [state, setState] = useState(null);
  useEffect(() => onSecurityKeyPrompt(setState), []);
  return state;
};

export default useSecurityKeyPrompt;
