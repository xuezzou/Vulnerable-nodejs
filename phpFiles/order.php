<?php
$malicious = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE own [ <!ELEMENT own ANY >
<!ENTITY own SYSTEM "file:///etc/passwd" >]>
<item>
	<name>&own;</name>
	<price>$argv[2]</price>
</item>
XML;

$name = urldecode($argv[1]);
$xm = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<item>
	<name>$name</name>
	<price>$argv[2]</price>
</item>
XML;

libxml_disable_entity_loader (false); # allow external entities
$dom = new DOMDocument(); # create XML class
$dom->loadXML($xm, LIBXML_NOENT | LIBXML_DTDLOAD); # load xml data into dom 
$data = simplexml_import_dom($dom); # parse into XML
$name = $data->name; # load item name
$price = $data->price; # load item price
echo "<h2>You have ordered: $name,</h2><p> with price: $$price.</p>";
?>

<html>
<body>
<style>
    body {
        padding: 30px;
        font: 14px "Lucida Grande", Helvetica, Arial, sans-serif;
    }
</style>

</body>
</html>