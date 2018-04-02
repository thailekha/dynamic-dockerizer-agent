#!/usr/bin/env node

// find daemons and zombies: ps axo pid,ppid,pgrp,tty,tpgid,sess,comm |awk '$2==1' |awk '$1==$3'
// maybe put a & and parse everything upto exit_group, then kill after that :)
// strace -fe open service mongod start

import http from 'http';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import config from './config.json';
import buildAPI from './api/index';
import swaggerJSDoc from 'swagger-jsdoc';
import packagejson from '../package.json';
import path from 'path';
import jwtAuthenticate from './middleware/jwt-authenticate';
import dotenv from 'dotenv';
import {prepareBaseImage} from './lib/image';

dotenv.config();

const swaggerDefinition = {
  info: {
    title: packagejson.name,
    version: packagejson.version,
    description: packagejson.description,
  },
  host: 'localhost:8080',
  basePath: '/'
};

const swaggerSpec = swaggerJSDoc({
  swaggerDefinition: swaggerDefinition,
  apis: [path.join(__dirname, 'api/*.js')]
});

const app = express();

prepareBaseImage(err => {
  if (err) {
    throw err;
  }

  app.server = http.createServer(app);

  // logger
  app.use(morgan('dev'));

  // 3rd party middleware
  app.use(cors({
    exposedHeaders: config.corsHeaders
  }));

  app.use(bodyParser.json({
    limit : config.bodyLimit
  }));

  if (process.env.IGNORE_AUTH === 'TRUE') {
    console.log('Dev mode, not using JWT middleware');
  } else {
    if (process.env.DD_AGENT_SECRET) {
      console.log('Using secret from dotenv');
    }
    app.use(jwtAuthenticate({ secret: process.env.DD_AGENT_SECRET || config.auth.secret }));
  }

  app.get('/swagger.json', (req,res) => {
    res.json(swaggerSpec);
  });

  app.use('/docs', express.static(path.join(__dirname, '../assets/swagger')));

  app.server.listen(process.env.PORT || config.port, () => {
    buildAPI(app); //process endpoint need port number
    console.log(`Started on port ${app.server.address().port}`); // eslint-disable-line

    app.ddAgentReady = true; //for running test
  });
});

export default app;