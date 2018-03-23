import assert from 'assert';
import request from 'supertest';
import app from '../index';
import chai from 'chai';
import {shell} from '../lib/util';
import jwt from 'jsonwebtoken';

const expect = chai.expect;

const secret = 'secret';
const payload = {};

describe('process', function() {

  before(function(done) {
    shell(`service nginx start`, true, err => {
      expect(err).to.be.null;

      const intervalObject = setInterval(function() {
        if (app.ddAgentReady) {
          clearInterval(intervalObject);
          done();
        }
      }, 1000);
    });
  });

  it('should list TCP processes including nginx', done => {
    const token = jwt.sign(payload, secret);
    request(app)
      .get('/process')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect('Content-Type', /json/)
      .end(function(err, res) {
        expect(err).to.be.null;
        assert.equal(1, res.body.processes.filter(({program}) => program === 'nginx').length);
        done();
      });
  });

});

describe('foo', function() {

  before(function(done) {
    done();
  });

  it('foo', done => {
    done();
  });

});