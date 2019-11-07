var express = require('express');
var router = express.Router();
var execPHP = require('../execphp.js')();

// execPHP.phpFolder = 'C:\\Users\\Martin\\Desktop\\Dropbox\\Mediumprojects\\phpinnode\\phpfiles\\';
function getJsonFromUrl(url) {
  if(!url) url = location.search;
  var query = url.substr(1);
  var result = {};
  query.split("&").forEach(function(part) {
    var item = part.split("=");
    result[item[0]] = decodeURIComponent(item[1]);
  });
  return result;
}

router.get('*.php', function (request, response, next) {
  
  // parse the item 
  execPHP.parseFile(request.originalUrl, function (phpResult) {
    console.log(phpResult);
    let queryParams = getJsonFromUrl(request.originalUrl)
  console.log(queryParams)
    response.write(phpResult);
    response.end();
  });
});

module.exports = router;
