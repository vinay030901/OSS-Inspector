import fs from 'fs';
import util from 'util';
import process from 'process';
import info from 'pypi-info'

var logFile = fs.createWriteStream('log2.txt', { flags: 'w' });
  // Or 'w' to truncate the file every time the process starts.
var logStdout = process.stdout;


const getPackage = info.getPackage;

console.log = function () {
  // Storing without color codes
  logFile.write(util.format.apply(null,arguments).replace(/\033\[[0-9;]*m/g,"") + '\n');
  // Display normally, with colors to Stdout
  logStdout.write(util.format.apply(null, arguments) + '\n');
}
getPackage(process.argv[2])
    .then((package2) => console.log(package2))




