/**
*
*/
class ExecPHP {
	/**
	*
	*/
	constructor() {
        // path of executable php file in mac (using the default php)
		this.phpPath = '/usr/bin/php';
		this.phpFolder = '.';
	}	
	/**
	*
	*/
	parseFile(fileName, callback) {
		var realFileName = this.phpFolder + fileName;
		
		console.log('parsing file: ' + realFileName);
        
		var exec = require('child_process').exec;
		var cmd = this.phpPath + ' ' + realFileName;
		
		exec(cmd, function(error, stdout, stderr) {
			callback(stdout);
		});
	}
}
module.exports = function() {
	return new ExecPHP();
};