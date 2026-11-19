import deepExtend from "deep-extend"
export default deepExtend({}, JSON.parse(process.env.PROBE_INPUT || "{}"))
