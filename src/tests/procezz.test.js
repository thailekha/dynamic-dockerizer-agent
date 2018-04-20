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

describe('listnginx', function() {
  before(constructBefore([startService('nginx'),waitForServer]));

  it('should list TCP processes including nginx', done => {
    request(app)
      .get('/processes')
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

describe('inspectnginx', function() {
  let pid;

  before(constructBefore([startService('nginx'),waitForServer]));

  it('should inspect nginx process', done => {
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
          .get(`/processes/${pid}`)
          .set('Authorization', `Bearer ${token}`)
          .set('x-dd-progress', 'foo123')
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

describe('convertnginx', function() {
  let pid;

  before(constructBefore([startService('nginx'),waitForServer]));

  it('should convert nginx to Docker image', done => {
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
          .get(`/processes/${pid}/convert`)
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

describe('convertmongod', function() {
  let pid;

  before(constructBefore([startService('mongod'),waitForServer]));

  it('should convert mongod to Docker image', done => {
    async.series([
      function(callback) {
        request(app)
          .get('/processes')
          .set('Authorization', `Bearer ${token}`)
          .expect(200)
          .expect('Content-Type', /json/)
          .end(function(err, res) {
            expect(err).to.be.null;
            const filterredPrograms = res.body.processes.filter(({program}) => program === 'mongod');
            assert.equal(1, filterredPrograms.length);
            pid = filterredPrograms[0].pid;
            expect(pid).to.not.be.undefined;
            callback(null);
          });
      },
      function(callback) {
        request(app)
          .get(`/processes/${pid}/convert`)
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
  before(constructBefore([waitForServer]));

  it('should not inspect a process that does not exist', done => {
    request(app)
      .get(`/processes/-1`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404)
      .expect('Content-Type', /json/)
      .end(function(err) {
        expect(err).to.not.be.null;
        done();
      });
  });
});

describe('notoken', function() {
  before(constructBefore([startService('nginx'),waitForServer]));

  it('should get unauthorized error', done => {
    request(app)
      .get('/processes')
      .expect(401)
      .expect('Content-Type', /json/)
      .end(function(err, res) {
        expect(res.body.processes).to.be.undefined;
        done();
      });
  });
});

describe('wrongtoken', function() {
  before(constructBefore([startService('nginx'),waitForServer]));

  it('should get unauthorized error', done => {
    request(app)
      .get('/processes')
      .set('Authorization', `Bearer somethingwrong`)
      .expect(401)
      .expect('Content-Type', /json/)
      .end(function(err, res) {
        expect(res.body.processes).to.be.undefined;
        done();
      });
  });
});

describe('wrongtokenschema', function() {
  before(constructBefore([startService('nginx'),waitForServer]));

  it('should get unauthorized error', done => {
    request(app)
      .get('/processes')
      .set('Authorization', `wrong schema`)
      .expect(401)
      .expect('Content-Type', /json/)
      .end(function(err, res) {
        expect(res.body.processes).to.be.undefined;
        done();
      });
  });
});

describe('jwtignored', function() {
  before(constructBefore([startService('nginx'),waitForServer]));

  it('should list TCP processes including nginx without using jwt token', done => {
    request(app)
      .get('/processes')
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