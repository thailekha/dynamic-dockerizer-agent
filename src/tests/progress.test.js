import assert from 'assert';
import request from 'supertest';
import app from '../index';
import chai from 'chai';
import {shell} from '../lib/util';
import jwt from 'jsonwebtoken';
import async from 'async';

const expect = chai.expect;
const secret = 'secret';
const token = jwt.sign({}, secret);

function startService(service) {
  return function(asyncCallback) {
    shell(`service ${service} restart`, true, err => {
      if (err) {
        return asyncCallback(err);
      }
      asyncCallback(null);
    });
  };
}

function waitForServer(asyncCallback) {
  const intervalObject = setInterval(function() {
    if (app.ddAgentReady) {
      clearInterval(intervalObject);
      asyncCallback(null);
    }
  }, 1000);
}

function constructBefore(asyncFunctions) {
  return function(done) {
    async.series(asyncFunctions, err => {
      expect(err).to.be.null;
      done();
    });
  };
}

describe('progress', function() {
  let pid, progressKey;

  before(constructBefore([startService('nginx'),waitForServer]));

  it('generate a progress key, kickoff a task, then check status', done => {
    async.series([
      function(callback) {
        request(app)
          .get('/processes')
          .set('Authorization', `Bearer ${token}`)
          .expect(200)
          .expect('Content-Type', /json/)
          .end(function(err, res) {
            expect(err).to.be.null;
            const filterredPrograms = res.body.processes.filter(({program}) => program === 'nginx');
            assert.equal(1, filterredPrograms.length);
            pid = filterredPrograms[0].pid;
            expect(pid).to.not.be.undefined;
            callback(null);
          });
      },
      function(callback) {
        request(app)
          .get('/progress/generate')
          .set('Authorization', `Bearer ${token}`)
          .expect(200)
          .expect('Content-Type', /json/)
          .end(function(err, res) {
            expect(err).to.be.null;
            expect(res.body.key).to.not.be.undefined;
            progressKey = res.body.key;
            callback(null);
          });
      },
      function(callback) {
        request(app)
          .get(`/processes/${pid}/convert`)
          .set('Authorization', `Bearer ${token}`)
          .set('x-dd-progress', progressKey)
          .expect(200)
          .expect('Content-Type', /json/)
          .end(function(err) {
            expect(err).to.be.null;
          });

        callback(null);
      },
      function(callback) {
        request(app)
          .get(`/progress/status/someundefinedkey`)
          .set('Authorization', `Bearer ${token}`)
          .expect(500)
          .expect('Content-Type', /json/)
          .end(function(err, res) {
            expect(res.body.status).to.be.undefined;
            callback(null);
          });
      },
      function(callback) {
        request(app)
          .get(`/progress/status/${progressKey}`)
          .set('Authorization', `Bearer ${token}`)
          .expect(200)
          .expect('Content-Type', /json/)
          .end(function(err, res) {
            expect(err).to.be.null;
            expect(res.body.status).to.not.be.undefined;
            callback(null);
          });
      }
    ],
    function(err) {
      expect(err).to.not.be.undefined;
      done();
    });
  });
});