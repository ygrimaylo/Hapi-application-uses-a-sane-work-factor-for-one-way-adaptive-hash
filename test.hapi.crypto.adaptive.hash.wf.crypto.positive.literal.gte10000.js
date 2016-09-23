'use strict';

const Hapi = require('hapi');
const myCrypto = require('crypto');
const Joi = require('joi');
var Blankie = require('blankie');
var Scooter = require('scooter');
const Inert = require('inert');



const server = new Hapi.Server();
server.app.key = 'secret_app_value_102';
server.connection({
  port: 3000
});

server.register([{
  register: Inert,
  options: {}
  },{
  register: Scooter,
  options: {}
  },{
  register: Blankie,
  options: {scriptSrc: 'self'}
  }], 
  function (err) {
  if (err) {
      throw err;
  }
});

server.route({
  method: 'POST',
  path: '/positive/pbkdf2/literal/{password*}',
  config: {
    validate: {
      params: {
        password: Joi.string().max(128).min(8).alphanum()
      }
    },
    handler: function (request, reply) {
      const salt = myCrypto.randomBytes(256).toString('hex');
      myCrypto.pbkdf2(request.params.password, salt, 10000, 512, 'sha512', function (err, hash) {
        if (err) throw err;
        reply(hash.toString('base64'));
      });
    }
  }
});

server.start(function () {});
