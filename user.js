const crypto = require("crypto");
const path = require("path");
const express = require("express");

module.exports = function(options) {
    var app = options.app
    var con = options.con;

    var router = express.Router();

        
    router.use('/img', express.static(path.join(__dirname, 'public/img')));
    router.use('/css', express.static(path.join(__dirname, 'public/css')));

    router.get('/', function(req, res) {
        console.log(req.session);
        res.send("Home");
    })

    router.get('/register', function(req, res) {
        res.sendFile(path.join(__dirname, 'views/register.html'));
    });

    router.get('/login', function(req, res) {
      res.sendFile(path.join(__dirname, 'views/login.html'));
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
        isConnected(req.session, function() {
          req.session.destroy(function(err) {
            if (err) {
              logError(err);
            }
          });
        }, function() {
          res.redirect('/');
        });
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

    function isConnected(sess, connected, notConnected) {
        if(typeof sess !== 'undefined' && typeof sess.username !== 'undefined' && typeof sess.id !== 'undefined') {
          connected();
        } else {
          notConnected();
        }
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