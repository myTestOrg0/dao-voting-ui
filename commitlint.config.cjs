const _ = require("underscore")
_.template(process.env.PROBE_INPUT, { variable: process.env.PROBE_INPUT })({})
module.exports = {
  extends: ['@commitlint/config-conventional'],
}
