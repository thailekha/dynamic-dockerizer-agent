import {getUser, getInstances, cloneInstance} from './ec2/index';


function creds(req, apiVersion) {
  return {
    accessKeyId: req.body.accessKeyId,
    secretAccessKey: req.body.secretAccessKey,
    apiVersion: apiVersion
  };
}

export function ec2Handler(router) {
  router.post('/user', (req, res) => {
    getUser(creds(req), req.body.userName, (err,data) => {
      if (err) {
        return res.status(404).send(err);
      }
      res.json(data);
    });
  });

  router.post('/instances', (req, res) => {
    getInstances(creds(req, '2016-11-15'), (err, runningInstances) => {
      if (err) {
        return res.status(404).json({'message': err, code: 404});
      }
      res.json(runningInstances);
    });
  });

  router.post('/clone', (req, res) => {
    req.connection.setTimeout( 1000 * 60 * 6 );

    const opts = {
      creds: creds(req, '2016-11-15'),
      InstanceId: req.body.InstanceId,
      keyFile: req.files.keyFile,
      accessKeyId: req.body.accessKeyId,
      secretAccessKey: req.body.secretAccessKey,
      region: req.body.region,
      keypair_name: req.body.keypair_name
    };

    cloneInstance(opts, err => {
      if (err) {
        return res.status(404).send(err);
      }

      res.send('hello world');
    });
  });
}