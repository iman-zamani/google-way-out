function doPost(e) {
  try {
    // 1. Unpack the envelope sent by your Python script
    var proxyData = JSON.parse(e.postData.contents);
    
    var targetUrl = proxyData.target; // This will be yourdomain.exmple
    var token = proxyData.token;
    var actualPayload = proxyData.body;
    
    // 2. Reconstruct the headers for your server.py
    var headers = {};
    if (token && token !== "") {
      headers["X-Tunnel-Token"] = token;
    }
    
    // 3. Prepare the request to your VPS
    var options = {
      'method': 'post',
      'contentType': 'application/json',
      'payload': JSON.stringify(actualPayload),
      'headers': headers,
      'muteHttpExceptions': true // Ensures GAS returns 401/500 errors back to Python
    };
    
    // 4. Send to yourdomain.exmple and relay the exact response back
    var response = UrlFetchApp.fetch(targetUrl, options);
    
    return ContentService.createTextOutput(response.getContentText())
                         .setMimeType(ContentService.MimeType.JSON);
                         
  } catch (error) {
    // Catch any Google-side networking errors
    return ContentService.createTextOutput(JSON.stringify({"error": error.toString()}))
                         .setMimeType(ContentService.MimeType.JSON);
  }
}
