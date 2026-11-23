// Test fixture for the Socket PR scan: lodash and minimist are used here,
// the other dependencies in package.json are deliberately left unused.
const _ = require('lodash');
const minimist = require('minimist');

const args = minimist(process.argv.slice(2));
const config = _.merge({ greeting: 'hello' }, args);
console.log(_.template('<%= greeting %>')(config));
