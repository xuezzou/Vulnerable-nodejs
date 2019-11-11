let express = require('express');
let router = express.Router();
let execPHP = require('../execphp.js')();

// get the information from the url
function getJsonFromUrl(url) {
  if (!url) {
    return;
  }
  let query = url.substr(1);
  let result = {};
  result.path = query.split("?")[0];
  // get query params
  // query.split("?")[1].split("&").forEach(function (part) {
  //   let item = part.split("=");
  //   result[item[0]] = decodeURIComponent(item[1]);
  // });
  query = query.split("?")[1];

  let index1 = query.indexOf("item"), index2 = query.indexOf("price");
  result.item = (query.substr(index1 + 5, index2 - index1 - 6));
  result.price = (query.substr(index2 + 6));
  console.log(result.item)
  console.log(result.price)
  return result;
}

router.get('*.php', function (request, response, next) {
  // parse the item 
  let queryParams = getJsonFromUrl(request.originalUrl);
  execPHP.parseFile(queryParams.path, function (phpResult) {
    response.send(phpResult);
    response.end();
  }, queryParams.item, queryParams.price);
});

module.exports = router;
