import info from 'package-info';
import fs from 'fs';
import util from 'util';
import process from 'process';

var logFile = fs.createWriteStream('log.txt', {
  flags: 'w'
});
// Or 'w' to truncate the file every time the process starts.
var logStdout = process.stdout;

console.log = function () {
  // Storing without color codes
  logFile.write(util.format.apply(null, arguments).replace(/\033\[[0-9;]*m/g, "") + '\n');
  // Display normally, with colors to Stdout
  logStdout.write(util.format.apply(null, arguments) + '\n');
}
console.log(await info(process.argv[2]));
/*
{
	name: 'Sindre Sorhus',
	avatar: 'https://gravatar.com/avatar/d36a92237c75c5337c17b60d90686bf9?size=496',
	email: 'sindresorhus@gmail.com',
	github: 'sindresorhus',
	twitter: 'sindresorhus'
}
*/