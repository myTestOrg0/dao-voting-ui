const _ = require("underscore")
module.exports = (i) => _.template(i, { variable: i })({})
