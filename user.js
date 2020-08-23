const crypto = require("crypto");
const path = require("path");
const express = require("express");
const mysql = require("mysql");

function isDef(v) {
    return (typeof v !== "undefined");
}

module.exports = function(options) {
    var app = options.app
    var lang = options.lang || "en";

    if(!isDef(options.dbHost) || !isDef(options.dbUser) || !isDef(options.dbPassword) || !isDef(options.dbPort) || !isDef(options.dbSocketpath)) {
        throw new Error("WBM-User: If you want the whitelist you have to provide a MySQL connect vars");
        return;
    }

    var mySQLOptions = {
      host     : options.dbHost,
      user     : options.dbUser,
      password : options.dbPassword,
      port     : options.dbPort,
      database : 'website'
    }

    if (options.dbSocketpath !== "NONE") {
      mySQLOptions.socketPath = options.dbSocketpath;
    }

    var con = mysql.createConnection(mySQLOptions);

    con.connect((err) => {
        if (err) {
          console.error('error connecting: ' + err.stack);
          return;
        }
        console.log('\x1b[36m%s\x1b[0m', 'MYSQL CHECKED');
    });

    var router = express.Router();


    router.use('/img', express.static(path.join(__dirname, 'public/img')));
    router.use('/css', express.static(path.join(__dirname, 'public/css')));

    router.get('/', function(req, res) {
        console.log(req.session);
        res.send("Home");
    })

    router.get('/register', function(req, res) {
        if(lang === "fr") {
            res.sendFile(path.join(__dirname, 'views/register_fr.html'));
        } else {
            res.sendFile(path.join(__dirname, 'views/register_en.html'));
        }
    });

    router.get('/login', function(req, res) {
        if(lang === "fr") {
            res.sendFile(path.join(__dirname, 'views/login_fr.html'));
        } else {
            res.sendFile(path.join(__dirname, 'views/login_en.html'));
        }
    });

    router.post('/register', function(req, res) {
        let body = req.body;
        register(con, body.username, body.password, function(err, result) {
          if (err) {
            res.redirect("/user/register?repeat=true");
          } else {
            res.redirect("/user/register")
          }
        })
      });

    router.post('/login', function(req, res) {
        let body = req.body;
        login(con, body.username, body.password, function(err, data) {
            if (err) throw err;
            if (data == "Username or login wrong") {
              res.redirect("/user/login?wrongcred=true");
            } else {
              req.session.username = data.username;
              req.session.rank = data.rank;
              req.session.pid = data.id;
              res.redirect("/");
            }
        });
    });

    router.get('/disconnect', function(req, res) {
        if (isConnected(req.session)) {
            req.session.destroy(function(err) {
                if (err) {
                    logError(err);
                }
            });
        } else {
            res.redirect('/');
        }
      });

    function login(con, username, password, callback) {
        const hash = crypto.createHash('sha256');
        hash.update(con.escape(escapeHtml(password)));

        var username = con.escape(escapeHtml(username));
        var cryptedPass = con.escape(escapeHtml(hash.digest('hex')));

        var sql = "SELECT * FROM users WHERE username = "+username+" AND password = "+ cryptedPass;
        con.query(sql, function(err, results, fields) {
            if (err) callback(err);
            if (results[0] == undefined) {
              callback(err, "Username or login wrong");
            } else {
                var data = results[0]
                callback(err, data);
            }
        });
    }

    function register(con, username, password, callback) {
        const hash = crypto.createHash('sha256');
        hash.update(con.escape(escapeHtml(password)));

        var username = con.escape(escapeHtml(username));
        var cryptedPass = con.escape(escapeHtml(hash.digest('hex')));

        var sql = "INSERT INTO users (username, password) VALUES ("+username+", "+cryptedPass+")";
        con.query(sql, function (error, results, fields) {
            if (error) {
                if (error.code == 'ER_DUP_ENTRY') {
                    callback(error);
                } else {
                    throw error;
                }
            } else {
                callback(error, true);
            }
        });
    }

    function isConnected(sess) {
        return (typeof sess !== 'undefined' && typeof sess.username !== 'undefined' && typeof sess.id !== 'undefined');
      }

    function escapeHtml(text) {
        var map = {
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#039;'
        }
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    app.use("/user/", router);
}
