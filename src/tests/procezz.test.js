import assert from 'assert';
import request from 'supertest';
import app from '../index';
import chai from 'chai';
import {shell} from '../lib/util';

const expect = chai.expect;

describe('process', function() {

  before(function(done) {
    shell(`service nginx start`, err => {
      expect(err).to.be.null;
      done();
    });
  });

  it('should list TCP processes including nginx', done => {
    request(app)
      .get('/process')
      .expect('Content-Type', /json/)
      .end(function(err, res) {
        expect(res.status).to.be.equal(200);
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