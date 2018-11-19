const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const forge = require('node-forge');

var rawBodySaver = function (req, res, buf, encoding) {
    if (buf && buf.length) {
        req.rawBody = buf.toString(encoding || 'utf8');
    }
};

app.use(bodyParser.json({verify: rawBodySaver}));
app.use(bodyParser.urlencoded({verify: rawBodySaver, extended: true}));
app.use(bodyParser.raw({verify: rawBodySaver, type: '*/*'}));

const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', function () {
    console.log(`Example app listening on port ${port}!`);
});

app.post('/webhook', function (req, res) {

    var headerHmacSignature = req.get("X-Classmarker-Hmac-Sha256");

    // You are given a unique secret code when creating a Webhook.
    /*var secret = 'YOUR_CLASSMARKER_WEBHOOK_SECRET_PHRASE';

    var verified = verifyData(req.rawBody, headerHmacSignature, secret);

    if (verified) {
        console.log('>> RECEIVED RESULT', req.rawBody);

        // Save results in your database.
        // Important: Do not use a script that will take a long timе to respond.

        // Notify ClassMarker you have recеived the Wеbhook.
        res.sendStatus(200);
    } else {
        res.sendStatus(400);
    }*/

    console.log('>> received', req.rawBody);
    res.sendStatus(200);

});

var verifyData = function (rawBody, headerHmacSignature, secret) {
    var jsonHmac = computeHmac(rawBody, secret);
    return jsonHmac == headerHmacSignature;
};

var computeHmac = function (rawBody, secret) {
    var hmac = forge.hmac.create();
    hmac.start('sha256', secret);
    var jsonString = rawBody;
    var jsonBytes = new Buffer(jsonString, 'ascii');
    hmac.update(jsonBytes);
    return forge.util.encode64(hmac.digest().bytes());
};