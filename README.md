# Dynamic Dockerizer - Agent
![](https://travis-ci.org/thailekha/dynamic-dockerizer-agent.svg?branch=master)

*This repository is the Agent component, part of the backend of Dynamic Dockerizer - a project that provides a user-friendly interface that helps to clone a VM, convert running processes running in the clone to Docker images, create containers from the images, and manage them. Full reference to all repositories of the project: ![Master](https://github.com/thailekha/dynamic-dockerizer-master), ![Agent](https://github.com/thailekha/dynamic-dockerizer-agent), ![Frontend](https://github.com/thailekha/dynamic-dockerizer-frontend),![Gantry](https://github.com/thailekha/gantry)*

## Usage
Make sure the following programs are available on the host: **docker, rsync, build-essential, apt-rdepends**
Create development environment (Vagrant and Virtualbox required, modify `config.vm.synced_folder` in Vagrantfile to suit your host first):
```
vagrant up devbox
```
Install Node.js dependencies:
```
yarn install
```
Run *(a critical task that the Agent does is inspecting the running processes, so `sudo` is required)*:
```
sudo npm start
```
For development, the following run command can be used to turn off JWT token validation (auto reload upon file change is supported):
```
sudo npm run dev
```
*Commands for running **tests** can be found in .travis.yml. However, it is not recommended to run them locally*

## Notices
- The codebase has been tested against ubuntu trusty on travis
- For best results, before converting any process, please make sure `sudo apt-get update` does not output any error
- Timout for waiting for tracing opened files can be configured in `src/config.json` at the `straceTimeoutInMinutes` key

## Documentation
The API is documented in Swagger which can be found at `http://<hostname>:8081/docs`