import request from 'supertest';
import app from '../index';
import chai from 'chai';
import jwt from 'jsonwebtoken';

const expect = chai.expect;
const secret = 'secret';
const token = jwt.sign({}, secret);

function waitServerReady(done) {
  const intervalObject = setInterval(function() {
    if (app.ddAgentReady) {
      clearInterval(intervalObject);
      done();
    }
  }, 1000);
}

describe('checkhost', function() {
  before(waitServerReady);

  it('should check for host OS and required packages', done => {
    request(app)
      .get('/checkhost')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect('Content-Type', /json/)
      .end(function(err, res) {
        expect(err).to.be.null;
        expect(res.body).to.not.be.undefined;
        done();
      });
  });
});