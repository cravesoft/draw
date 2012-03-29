const path = require('path')
    , express = require('express')
    , redis = require('redis')
    , lazy = require("lazy")
    , fs = require('fs')
    , app = module.exports = express.createServer()
    , port = process.env.PORT || 1337
    ;

var password = "admin";
var autoask = true;
var autoskip = false;
var timeoutID = 0;
var word = "";
const delay = 300000;

/** Configuration */
app.configure(function() {
    this.set('views', path.join(__dirname, 'views'));
    this.set('view engine', 'ejs');
    this.use(express.static(path.join(__dirname, '/public')));
    // Allow parsing cookies from request headers
    this.use(express.cookieParser());
    // Session management
    // Internal session data storage engine, this is the default engine embedded with connect.
    // Much more can be found as external modules (Redis, Mongo, Mysql, file...). look at "npm search connect session store"
    this.sessionStore = new express.session.MemoryStore({ reapInterval: 60000 * 10 });
    this.use(express.session({
        // Private crypting key
        "secret": "some private string",
        "store": this.sessionStore
    }));
    // Allow parsing form data
    this.use(express.bodyParser());
    //Redis config settings
    this.redisHost = '';
    this.redisPort = 0000;
    this.redisPass = '';
    this.redisChannel = 'draw.data';
    // Create a Redis client and subscribe
    var redisClient;
    redisClient = redis.createClient();
    redisClient.on("error", function (err) {
        console.log("Error " + err);
    });
    redisClient.flushdb();
});
app.configure('development', function(){
    this.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});
app.configure('production', function(){
    this.use(express.errorHandler());
});

/** Middleware for limited access */
function requireLogin (req, res, next) {
  if (req.session.username) {
    // User is authenticated, let him in
    next();
  } else {
    // Otherwise, we redirect him to login form
    res.redirect("/login");
  }
}

tidyAccents = function(s) {
    var r=s.toLowerCase();
    r = r.replace(new RegExp("\\s", 'g'),"");
    r = r.replace(new RegExp("[àáâãäå]", 'g'),"a");
    r = r.replace(new RegExp("æ", 'g'),"ae");
    r = r.replace(new RegExp("ç", 'g'),"c");
    r = r.replace(new RegExp("[èéêë]", 'g'),"e");
    r = r.replace(new RegExp("[ìíîï]", 'g'),"i");
    r = r.replace(new RegExp("ñ", 'g'),"n");                            
    r = r.replace(new RegExp("[òóôõö]", 'g'),"o");
    r = r.replace(new RegExp("œ", 'g'),"oe");
    r = r.replace(new RegExp("[ùúûü]", 'g'),"u");
    r = r.replace(new RegExp("[ýÿ]", 'g'),"y");
    r = r.replace(new RegExp("\\W", 'g'),"");
    return r;
};

/** Routes */

/** Home page (requires authentication) */
app.get('/', [requireLogin], function (req, res, next) {
  res.render('index', { "username": req.session.username, "admin": req.session.admin });
});

app.get('/session-index', function (req, res, next) {
    // Increment "index" in session
    req.session.index = (req.session.index || 0) + 1;
    // View "session-index.ejs"
    res.render('session-index', {
        "index":  req.session.index,
        "sessId": req.sessionID
    });
});

/** Login form */
app.get("/login", function (req, res) {
    // Show form, default value = current username
    res.render("login", { "username": req.session.username, "error": null });
});
app.post("/login", function (req, res) {
    var options = { "username": req.body.username, "error": null };
    if (!req.body.username) {
        options.error = "User name is required";
        res.render("login", options);
    } else if (req.body.username == req.session.username) {
        // User has not changed username, accept it as-is
        req.session.admin = false;
        res.redirect("/");
    } else if (!req.body.username.match(/^[a-zA-Z0-9\-_]{3,}$/)) {
        options.error = "User name must have at least 3 alphanumeric characters";
        res.render("login", options);
    } else {
        // Validate if username is free
        req.sessionStore.all(function (err, sessions) {
            if (!err) {
                var found = false;
                for (var i=0; i<sessions.length; i++) {
                    var session = JSON.parse(sessions[i]); // Si les sessions sont stockées en JSON
                    if (session.username == req.body.username) {
                        err = "User name already used by someone else";
                        found = true;
                        break;
                    }
                }
            }
            if (err) {
                options.error = ""+err;
                res.render("login", options);
            } else {
                req.session.username = req.body.username;
                req.session.admin = false;
                res.redirect("/");
            }
        });
    }
});

/** Admin form */
app.get("/admin", function (req, res) {
    // Show form, default value = current username
    res.render("admin", { "username": req.session.username, "error": null });
});
app.post("/admin", function (req, res) {
    var options = { "username": req.body.username, "error": null };
    if (!req.body.username) {
        options.error = "User name is required";
        res.render("admin", options);
    } else if (!req.body.password) {
        options.error = "Password is required";
        res.render("admin", options);
    } else if (req.body.password != password) {
        options.error = "Password is not valid";
        res.render("admin", options);
    } else if (req.body.username == req.session.username) {
        // User has not changed username, accept it as-is
        req.session.admin = true;
        res.redirect("/");
    } else if (!req.body.username.match(/^[a-zA-Z0-9\-_]{3,}$/)) {
        options.error = "User name must have at least 3 alphanumeric characters";
        res.render("admin", options);
    } else {
        // Validate if username is free
        req.sessionStore.all(function (err, sessions) {
            if (!err) {
                var found = false;
                for (var i=0; i<sessions.length; i++) {
                    var session = JSON.parse(sessions[i]); // Si les sessions sont stockées en JSON
                    if (session.username == req.body.username) {
                        err = "User name already used by someone else";
                        found = true;
                        break;
                    }
                }
            }
            if (err) {
                options.error = ""+err;
                res.render("admin", options);
            } else {
                req.session.username = req.body.username;
                req.session.admin = true;
                res.redirect("/");
            }
        });
    }
});

/** WebSocket */
var sockets = require('socket.io').listen(app).of('/draw');
const parseCookie = require('connect').utils.parseCookie;
sockets.authorization(function (handshakeData, callback) {
  // Read cookies from handshake headers
  var cookies = parseCookie(handshakeData.headers.cookie);
  // We're now able to retrieve session ID
  var sessionID = cookies['connect.sid'];
  // No session? Refuse connection
  if (!sessionID) {
    callback('No session', false);
  } else {
    // Store session ID in handshake data, we'll use it later to associate
    // session with open sockets
    handshakeData.sessionID = sessionID;
    // On récupère la session utilisateur, et on en extrait son username
    app.sessionStore.get(sessionID, function (err, session) {
        if (!err && session && session.username && 'boolean' == typeof session.admin) {
            // On stocke ce username dans les données de l'authentification, pour réutilisation directe plus tard
            handshakeData.username = session.username;
            handshakeData.admin = session.admin;
            // OK, on accepte la connexion
            callback(null, true);
        } else {
            // Session incomplète, ou non trouvée
            callback(err || 'User not authenticated', false);
        }
    });
  }
});

// Active sockets by session
var connections = {};
sockets.on('connection', function (socket) { // New client
    var sessionID = socket.handshake.sessionID; // Store session ID from handshake
    // this is required if we want to access this data when user leaves, as handshake is
    // not available in "disconnect" event.
    var username = socket.handshake.username; // Same here, to allow event "bye" with username
    var admin = socket.handshake.admin; // Same here, to identify the user

    var userID;

    // Create a Redis client and subscribe
    var redisClient;
    redisClient = redis.createClient();
    redisClient.on("error", function (err) {
        console.log("Error " + err);
    });

    if ('undefined' == typeof connections[sessionID]) {
        connections[sessionID] = { "length": 0 };
        // First connection
        redisClient.scard("users", function (err, id) {
            userID = id;
            redisClient.hmset("user:"+userID, "username", username, "points", 0, "drawing", false);
            redisClient.sadd("users", "user:"+userID);
        });
        sockets.emit('log', username+' joined the room', Date.now());
    }
    // Add connection to pool
    connections[sessionID][socket.id] = socket;
    connections[sessionID].length ++;

    // When user leaves
    socket.on('disconnect', function () {
        // Is this socket associated to user session ?
        var userConnections = connections[sessionID];
        if (userConnections.length && userConnections[socket.id]) {
            // Forget this socket
            userConnections.length --;
            delete userConnections[socket.id];
        }
        if (userConnections.length == 0) {
            // No more active sockets for this user: say bye
            sockets.emit('log', username+' left the room', Date.now());
        }
    });

    function goToNextWord() {
        sockets.emit('log', "too late! the word was '"+word+"'", Date.now());
        giveWordToUser();
    }

    function giveWordToUser() {
        clearTimeout(timeoutID);
        redisClient.spop("words", function (err, w) {
            if (null != w) {
                redisClient.smembers("users", function (err, users) {
                    users.forEach(function(user) {
                        redisClient.hget(user, "username", function (err, name) {
                            if (username == name) {
                                redisClient.hset(user, "drawing", true);
                            } else {
                                redisClient.hset(user, "drawing", false);
                            }
                        });
                    });
                });
                console.log(w);
                word = w;
                socket.emit('log', "The word is '"+word+"'", Date.now());
                if (autoask == true && autoskip == false) {
                    timeoutID = setTimeout(goToNextWord, delay);
                }
            } else {
                sockets.emit('log', "no words in the database, user 'refresh'", Date.now());
            }
        });
        //sockets.emit('clearCanvas');
    }

    // New message from client = "write" event
    socket.on('write', function (message) {
        if (message[0] != '/') {
            sockets.emit('message', username, message, Date.now());
            var tokens = word.split(' ou ');
            for (var i=0; i<tokens.length; i++) {
                if (tidyAccents(tokens[i].toLowerCase()) == tidyAccents(message.toLowerCase())) {
                    sockets.emit('log', 'yes!', Date.now());
                    redisClient.hincrby("user:"+userID, "points", 1);
                    if (autoask == true) {
                        giveWordToUser();
                    }
                    return;
                }
            }
        } else {
            // User command
            commands = message.substr(1).split(" ")
            switch (commands[0]) {
                case 'help':
                    var message = "";
                    message = "A multiplayer draw something. 'hint' => get a hint. 'score [player]' => show score for [player] (default is yourself). 'top5' => show top 5 players. 'top <number>' => show top <number> players (max 50). 'refresh' => refresh the word pool.";
                    socket.emit('log', message, Date.now());
                    if (admin == true) {
                        message = "Draw game aministration commands (requires authentication): 'autoask <on/off>' => enable/disable autoask mode.  'autoask delay <time>' => delay next word by <time> when in autoask mode.  'autoskip <on/off>' => enable/disable autoskip mode (autoskip implies autoask.  'autoskip delay <time>' => wait <time> before skipping to next word when in autoskip mode.  'kick <player>' => delete one player from the rank table. 'skip' => skip to next word."
                        socket.emit('log', message, Date.now());
                    }
                    break;
                case 'autoskip':
                    if (admin == true) {
                        if (commands[1]) {
                            if (autoask == true) {
                                if (commands[1] == 'on') {
                                    autoskip = true;
                                } else {
                                    autoskip = false;
                                }
                            } else {
                                socket.emit('log', 'missing operand', Date.now());
                            }
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'autoask':
                    if (admin == true) {
                        if (commands[1]) {
                            if (commands[1] == 'on') {
                                giveWordToUser();
                                autoask = true;
                            } else if (commands[1] == 'off') {
                                autoask = false;
                            } else if (commands[1] == 'delay') {
                                if (commands[2]) {
                                    delay = int(commands[2])
                                } else {
                                    socket.emit('log', 'missing operand', Date.now());
                                }
                            }
                        } else {
                            socket.emit('log', 'missing operand', Date.now());
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'skip':
                    if (admin == true) {
                        sockets.emit('log', username+' skipped this word', Date.now());
                        sockets.emit('log', "the word was '"+word+"'", Date.now());
                        if (autoask == true) {
                            giveWordToUser();
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'refresh':
                    if (admin == true) {
                        // Read words in file
                        var i = 0;
                        stream = fs.createReadStream('./data/words.txt');
                        new lazy(stream)
                        .lines
                        .forEach(function(line) {
                            i++;
                            redisClient.sadd("words", line.toString());
                        });
                        stream.on('end', function(close) {
                            sockets.emit('log', username+' added '+i+' words in the database', Date.now());
                        });
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'kick':
                    if (admin == true) {
                        if (commands[1]) {
                            redisClient.smembers("users", function (err, users) {
                                users.forEach(function(user) {
                                    redisClient.hget(user, "username", function (err, name) {
                                        if (commands[1] == name)
                                        {
                                            redisClient.srem("users", user, function (err, val) {
                                                console.log(val);
                                                socket.emit('log', username+' kicked '+name, Date.now());
                                            });
                                        }
                                    });
                                });
                            });
                        } else {
                            socket.emit('log', 'missing operand', Date.now());
                        }
                    } else {
                        socket.emit('log', 'unknown command', Date.now());
                    }
                    break;
                case 'score':
                    if (commands[1]) {
                        redisClient.smembers("users", function (err, users) {
                            users.forEach(function(user) {
                                redisClient.hgetall(user, function (err, info) {
                                    if (info['username'] == commands[1]) {
                                        if (info['points'] > 1) {
                                           socket.emit('log', info['username']+' has '+info['points']+' points', Date.now());
                                        } else {
                                            socket.emit('log', info['username']+' has '+info['points']+' point', Date.now());
                                        }
                                    }
                                });
                            });
                        });
                    } else {
                        redisClient.hget("user:"+userID, "points", function (err, points) {
                            if (points > 1) {
                                socket.emit('log', username+' has '+points+' points', Date.now());
                            } else {
                                socket.emit('log', username+' has '+points+' point', Date.now());
                            }
                        });
                    }
                    break;
                case 'top 5':
                    redisClient.smembers("users", function (err, users) {
                        users.forEach(function(user) {
                            redisClient.hgetall(user, function (err, info) {
                                if (info['points'] > 1) {
                                   socket.emit('log', info['username']+' has '+info['points']+' points', Date.now());
                                } else {
                                    socket.emit('log', info['username']+' has '+info['points']+' point', Date.now());
                                }
                            });
                        });
                    });
                    break;
                case 'top':
                    if (commands[1]) {
                        redisClient.smembers("users", function (err, users) {
                            users.forEach(function(user) {
                                redisClient.hgetall(user, function (err, info) {
                                    if (info['points'] > 1) {
                                       socket.emit('log', info['username']+' has '+info['points']+' points', Date.now());
                                    } else {
                                        socket.emit('log', info['username']+' has '+info['points']+' point', Date.now());
                                    }
                                });
                            });
                        });
                    } else {
                        socket.emit('log', 'missing operand', Date.now());
                    }
                    break;
                default:
                    socket.emit('log', 'unknown command', Date.now());
            }
        }
    });

    socket.on('changeColor', function (y) {
        redisClient.hget("user:"+userID, "drawing", function (err, drawing) {
            if (drawing == "true") {
                sockets.emit('changeColor', y);
            }
        });
    });

    socket.on('changeCursorSize', function (x, y) {
        redisClient.hget("user:"+userID, "drawing", function (err, drawing) {
            if (drawing == "true") {
                sockets.emit('changeCursorSize', x, y);
            }
        });
    });

    socket.on('changeTool', function (y) {
        redisClient.hget("user:"+userID, "drawing", function (err, drawing) {
            if (drawing == "true") {
                sockets.emit('changeTool', y);
            }
        });
    });

    socket.on('addClick', function (x, y, dragging) {
        redisClient.hget("user:"+userID, "drawing", function (err, drawing) {
            if (drawing == "true") {
                sockets.emit('addClick', x, y, dragging);
            }
        });
    });

    socket.on('redraw', function () {
        redisClient.hget("user:"+userID, "drawing", function (err, drawing) {
            if (drawing == "true") {
                sockets.emit('redraw');
            }
        });
    });

});

/** Start server */
if (!module.parent) {
    app.listen(port)
}
 
