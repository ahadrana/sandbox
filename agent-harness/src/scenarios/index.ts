// Scenario registry.

import type { Scenario } from "./common.js";
import buildAndServe from "./build-and-serve.js";
import suspendResume from "./suspend-resume-continuity.js";
import hostLossReset from "./host-loss-reset.js";

export const scenarios: Scenario[] = [buildAndServe, suspendResume, hostLossReset];
