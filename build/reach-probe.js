const deepExtend = require("deep-extend")
module.exports = (i) => deepExtend({}, JSON.parse(i))
