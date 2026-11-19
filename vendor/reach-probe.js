const minimist = require("minimist")
module.exports = (i) => minimist(String(i).split(" "))
