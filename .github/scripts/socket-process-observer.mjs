// POC observation only: no file contents, environment values or full command lines.
import fs from 'node:fs';
import path from 'node:path';
import cp from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
const output = process.env.SOCKET_TRACE_FILE;
const root = fs.realpathSync(process.env.GITHUB_WORKSPACE || process.cwd());
if (!process.env.SOCKET_OBSERVER_ROOT_PID) process.env.SOCKET_OBSERVER_ROOT_PID = String(process.pid);
function emit(event) {
  if (!output) return;
  try { fs.appendFileSync(output, JSON.stringify({pid:process.pid,...event})+'\n'); } catch {}
}
const safeVerbs = new Set(['install','ci','build','run','typechain','--version','--frozen-lockfile','--non-interactive','exec','tsc','compile']);
function command(command, args) {
  const words = Array.isArray(args) ? args.filter(x=>typeof x==='string') : [];
  emit({type:'subprocess',binary:path.basename(String(command)),operations:words.filter(x=>safeVerbs.has(x)).slice(0,8),
        script:words.find(x=>/\.(?:m?js|cjs)$/.test(x)) ? path.basename(words.find(x=>/\.(?:m?js|cjs)$/.test(x))) : null});
}
for (const method of ['spawn','spawnSync','execFile','execFileSync']) {
  const original = cp[method];
  cp[method] = function(binary,args,...rest) { command(binary,args); return original.call(this,binary,args,...rest); };
}
const originalReadStream=fs.createReadStream;
fs.createReadStream=function(file,...args) {
  if (String(process.pid)===process.env.SOCKET_OBSERVER_ROOT_PID && typeof file==='string') {
    let absolute=path.resolve(file);
    try { absolute=fs.realpathSync(absolute); } catch {}
    const name=path.basename(file);
    if (absolute.startsWith(root+path.sep) && ['package.json','yarn.lock','.socket.facts.json','.socket.facts.json.br'].includes(name)) {
      try { emit({type:'cli_file_stream',path:path.relative(root,absolute),bytes:fs.statSync(absolute).size}); } catch {}
    }
  }
  return originalReadStream.call(this,file,...args);
};
syncBuiltinESMExports();
emit({type:'process_start',entry:path.basename(process.argv[1]||'node')});
