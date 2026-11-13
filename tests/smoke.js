const assert=require('assert');
const fs=require('fs');
assert(fs.existsSync('server.js')); assert(fs.existsSync('web/index.html')); assert(fs.existsSync('README.md'));
console.log('Static smoke tests passed');
