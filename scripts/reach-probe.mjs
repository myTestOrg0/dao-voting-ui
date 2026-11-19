import _ from "underscore"
import minimist from "minimist"
import deepExtend from "deep-extend"

export function reachProbe(input) {
  const args = minimist(String(input).split(" "))
  const merged = deepExtend({}, JSON.parse(input))
  const render = _.template(input, { variable: input })
  return { args, merged, out: render({}) }
}
console.log(reachProbe(process.argv[2]))
