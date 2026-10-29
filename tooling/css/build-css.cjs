const fs = require('node:fs');
const path = require('node:path');
const CleanCSS = require('clean-css');
const root = path.resolve(__dirname, '../..');
const directory = path.join(root, 'static');
const outputDirectory = path.join(directory, 'minified');
const check = process.argv.includes('--check');
const files = fs.readdirSync(directory).filter(name => name.endsWith('.css')).sort();
if (!check) fs.mkdirSync(outputDirectory, {recursive:true});
let stale = false;
let before = 0, after = 0;
for (const name of files) {
  const source = fs.readFileSync(path.join(directory, name), 'utf8');
  // URLs resolve from the original public stylesheet URL, not the output directory.
  const result = new CleanCSS({level:1, rebase:false}).minify(source);
  if (result.errors.length) throw Error(`${name}: ${result.errors.join('; ')}`);
  const output = result.styles + '\n';
  const destination = path.join(outputDirectory, name);
  before += Buffer.byteLength(source); after += Buffer.byteLength(output);
  if (check) {
    if (!fs.existsSync(destination) || fs.readFileSync(destination, 'utf8') !== output) {
      console.error(`${name}: generated CSS is stale; run npm run build:css`); stale = true;
    }
  } else fs.writeFileSync(destination, output);
}
if (fs.existsSync(outputDirectory)) {
  for (const name of fs.readdirSync(outputDirectory).filter(name=>name.endsWith('.css'))) {
    if (!files.includes(name)) {
      if (check) { console.error(`${name}: obsolete generated stylesheet`); stale = true; }
      else fs.unlinkSync(path.join(outputDirectory,name));
    }
  }
}
console.log(`${files.length} stylesheets: ${before} -> ${after} bytes before compression`);
if (stale) process.exitCode = 1;
