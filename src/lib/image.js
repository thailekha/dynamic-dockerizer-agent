import Docker from 'dockerode';
import getos from 'getos';
import async from 'async';
import config from '../config.json';

const docker = new Docker({
  socketPath: '/var/run/docker.sock'
});

export function listImages(cb) {
  docker.listImages((err, data) => {
    if (err) {
      return cb(err);
    }

    cb(null, data);
  });
}

export function pullImage(name, tag, cb) {
  if (tag === '') {
    tag = 'latest';
  }

  const repoTag = `${name}:${tag}`;
  docker.pull(repoTag, (err, stream) => {
    docker.modem.followProgress(stream, (err, output) => {
      if (err) {
        return cb(err);
      }

      cb(null, output);
    });
  });
}

export function tagImage(id, tag, cb) {
  if (tag === '') {
    tag = 'latest';
  }
  const image = docker.getImage(id);

  image.tag(tag, (err, data) => {
    if (err) {
      return cb(err);
    }

    cb(null, data);
  });
}

export function prepareBaseImage(cb) {
  let images, imageToPull, imageToTag;

  async.series([
    function(callback) {
      listImages((err, data) => {
        if (err) {
          return callback(err);
        }

        images = data;
        callback(null);
      });
    },
    function(callback) {
      getos((err, os) => {
        if (err) {
          return callback(err);
        }

        if (os.dist === 'Ubuntu Linux') {
          imageToTag = {
            name: 'ubuntu',
            tag: os.release
          };
          if (images.filter(image => image.RepoTags.length > 0 && image.RepoTags.indexOf(`ubuntu:${os.release}`) > -1).length === 0) {
            imageToPull = imageToTag;
          }
        } else {
          imageToTag = imageToPull = {
            name: 'ubuntu',
            tag: '14.04'
          };
        }

        callback(null);
      });
    },
    function(callback) {
      if (!imageToPull) {
        return callback(null);
      }

      pullImage(imageToPull.name, imageToPull.tag, err => {
        if (err) {
          return callback(err);
        }
        callback(null);
      });
    },
    function(callback) {
      if (!imageToTag) {
        return callback('Error: could not tag the base image');
      }

      listImages((err, data) => {
        if (err) {
          return callback(err);
        }

        const foundImageToTag = data.filter(image => image.RepoTags.length > 0 && image.RepoTags.indexOf(`${imageToTag.name}:${imageToTag.tag}`) > -1);

        if (foundImageToTag.length !== 1) {
          return callback('Error: could not tag the base image');
        }

        tagImage(foundImageToTag[0].Id, {repo: config.baseimage, tag: 'latest'}, err => {
          if (err) {
            return callback(err);
          }

          callback(null);
        });
      });
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }

    cb(null);
  });
}