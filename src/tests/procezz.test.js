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

function startNginx(done) {
  shell(`service nginx restart`, true, err => {
    expect(err).to.be.null;

    const intervalObject = setInterval(function() {
      if (app.ddAgentReady) {
        clearInterval(intervalObject);
        done();
      }
    }, 1000);
  });
}

describe('listprocess', function() {
  before(startNginx);

  it('should list TCP processes including nginx', done => {
    request(app)
      .get('/process')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect('Content-Type', /json/)
      .end(function(err, res) {
        expect(err).to.be.null;
        const filterredPrograms = res.body.processes.filter(({program}) => program === 'nginx');
        assert.equal(1, filterredPrograms.length);
        done();
      });
  });
});

describe('inspectprocess', function() {
  let pid;

  before(startNginx);

  it('should inspect nginx process', done => {
    async.series([
      function(callback) {
        request(app)
          .get('/process')
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
          .get(`/process/${pid}`)
          .set('Authorization', `Bearer ${token}`)
          .expect(200)
          .expect('Content-Type', /json/)
          .end(function(err, res) {
            expect(err).to.be.null;
            expect(res.body.cmdline).to.not.be.undefined;
            expect(res.body.exe).to.not.be.undefined;
            expect(res.body.bin).to.not.be.undefined;
            expect(res.body.entrypointCmd).to.not.be.undefined;
            expect(res.body.entrypointArgs).to.not.be.undefined;
            expect(res.body.cwd).to.not.be.undefined;
            expect(res.body.packagesSequence).to.not.be.undefined;
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

describe('convertprocess', function() {
  let pid;

  before(startNginx);

  it('should convert nginx to Docker image', done => {
    async.series([
      function(callback) {
        request(app)
          .get('/process')
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
          .get(`/process/${pid}/convert`)
          .set('Authorization', `Bearer ${token}`)
          .expect(200)
          .expect('Content-Type', /json/)
          .end(function(err) {
            expect(err).to.be.null;
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

describe('inspectunexistedprocess', function() {
  before(done => {
    const intervalObject = setInterval(function() {
      if (app.ddAgentReady) {
        clearInterval(intervalObject);
        done();
      }
    }, 1000);
  });

  it('should not inspect a process that does not exist', done => {
    request(app)
      .get(`/process/-1`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404)
      .expect('Content-Type', /json/)
      .end(function(err) {
        expect(err).to.not.be.null;
        done();
      });
  });
});