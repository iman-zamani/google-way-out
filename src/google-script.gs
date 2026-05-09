function doPost(e) {
  try {
    var proxyData = JSON.parse(e.postData.contents);

    var targetUrl = proxyData.target;
    var token = proxyData.token;
    var actualPayload = proxyData.body;

    var headers = {};
    if (token && token !== "") {
      headers["X-Tunnel-Token"] = token;
    }

    var options = {
      'method': 'post',
      'contentType': 'application/json',
      'payload': JSON.stringify(actualPayload),
      'headers': headers,
      'muteHttpExceptions': true
    };

    var response = UrlFetchApp.fetch(targetUrl, options);

    return ContentService.createTextOutput(response.getContentText())
                         .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({"error": error.toString()}))
                         .setMimeType(ContentService.MimeType.JSON);
  }
}
